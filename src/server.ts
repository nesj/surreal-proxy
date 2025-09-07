import express from 'express';
import cors from 'cors';
import axios, { AxiosRequestConfig } from 'axios';
import rateLimit from 'express-rate-limit';
import * as dotenv from 'dotenv';
import net from 'net';
import dns from 'dns';

dotenv.config();

const {
  SURREAL_URL = '',
  SURREAL_NS = '',
  SURREAL_DB = '',
  SURREAL_AUTH_TYPE = 'none',
  SURREAL_USERNAME,
  SURREAL_PASSWORD,
  SURREAL_TOKEN,
  ALLOWED_ORIGINS = ''
} = process.env;

if (!SURREAL_URL) {
  console.warn('Warning: SURREAL_URL is not set');
}

const allowedOrigins = ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);

const corsOptions = {
  origin: (origin: any, cb: any) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error('CORS not allowed'), false);
  },
  credentials: true,
};

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
});

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ type: 'text/*', limit: '2mb' }));
app.use(limiter);
app.use((req, res, next) => {
    if (req.method === 'OPTIONS') {
      const origin = req.headers.origin as string | undefined;
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin || '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, NS, DB');
        if (origin) res.setHeader('Access-Control-Allow-Credentials', 'true');
        if (origin) res.setHeader('Vary', 'Origin');
        return res.sendStatus(204);
      } else {
        return res.status(403).send('CORS not allowed');
      }
    }
    next();
});
app.use(cors(corsOptions));

app.get('/health', (_req, res) => res.json({ ok: true }));

function buildSurrealHeaders() {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'text/plain',
  };
  if (SURREAL_NS) headers['NS'] = SURREAL_NS;
  if (SURREAL_DB) headers['DB'] = SURREAL_DB;

  if (SURREAL_AUTH_TYPE === 'basic' && SURREAL_USERNAME && SURREAL_PASSWORD) {
    const b = Buffer.from(`${SURREAL_USERNAME}:${SURREAL_PASSWORD}`).toString('base64');
    headers['Authorization'] = `Basic ${b}`;
  } else if (SURREAL_AUTH_TYPE === 'bearer' && SURREAL_TOKEN) {
    headers['Authorization'] = `Bearer ${SURREAL_TOKEN}`;
  }
  return headers;
}

const dnsPromises = (dns as any).promises || dns.promises;

function tcpConnectToIp(ip: string, port: number, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;

    const clean = () => {
      socket.removeAllListeners('error');
      socket.removeAllListeners('connect');
      socket.removeAllListeners('timeout');
      try { socket.destroy(); } catch (_) {}
    };

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      clean();
      reject(err);
    };

    socket.once('error', onError);

    // setTimeout on socket: emits 'timeout' event (doesn't destroy automatically)
    socket.setTimeout(timeoutMs, () => {
      if (settled) return;
      settled = true;
      clean();
      reject(new Error(`TCP connect timeout (${timeoutMs} ms) to ${ip}:${port}`));
    });

    socket.once('connect', () => {
      if (settled) return;
      settled = true;
      clean();
      try { socket.end(); } catch (_) {}
      resolve();
    });

    socket.connect(port, ip);
  });
}

async function tcpConnect(host: string, port: number, timeoutMs = 60000): Promise<void> {
  const start = Date.now();
  let lastErr: any = null;

  let addrs: Array<{ address: string; family?: number }>;
  try {
    addrs = await dnsPromises.lookup(host, { all: true });
    if (!addrs || addrs.length === 0) addrs = [{ address: host }];
  } catch (e) {
    addrs = [{ address: host }];
  }

  for (const addr of addrs) {
    const elapsed = Date.now() - start;
    const remaining = timeoutMs - elapsed;
    if (remaining <= 0) break;

    try {
      await tcpConnectToIp(addr.address, port, remaining);
      return;
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error(`Failed to connect to ${host}:${port} within ${timeoutMs} ms`);
}

async function tcpConnectWithRetries(host: string, port: number, timeoutMs = 60000, tries = 2, backoffMs = 500) {
  let lastErr: any;
  for (let i = 0; i < tries; i++) {
    try {
      await tcpConnect(host, port, timeoutMs);
      return;
    } catch (e) {
      lastErr = e;
      if (i === tries - 1) break;
      const delay = backoffMs * Math.pow(2, i);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastErr;
}

async function axiosWithRetry(cfg: AxiosRequestConfig, tries = 2, backoffMs = 500) {
  let lastErr: any;
  for (let i = 0; i < tries; i++) {
    try {
      return await axios.request(cfg);
    } catch (e) {
      lastErr = e;
      await new Promise(r => setTimeout(r, backoffMs * Math.pow(2, i)));
    }
  }
  throw lastErr;
}

app.post('/api/sql', async (req, res) => {
  try {
    const sql = typeof req.body === 'string' && req.headers['content-type'] && req.headers['content-type'].startsWith('text')
      ? (req.body as string)
      : (req.body && (req.body.sql || req.body.query) ? (req.body.sql || req.body.query) : undefined);

    if (!sql || typeof sql !== 'string') {
      return res.status(400).json({ error: 'Missing SQL in request body (send raw text or JSON { sql } )' });
    }

    const useNs = SURREAL_NS || 'myapp';
    const useDb = SURREAL_DB || 'prod';
    const useStmt = `USE NS ${useNs} DB ${useDb};`;

    let forwardedSql = sql;
    if (req.body && typeof req.body === 'object' && typeof (req.body as any).data !== 'undefined') {
      try {
        const dataJson = JSON.stringify((req.body as any).data);
        forwardedSql = String(forwardedSql).replace(/\$data\b/g, () => dataJson);
      } catch (e) {
        console.warn('Failed to stringify req.body.data for $data substitution', e);
      }
    }

    forwardedSql = `${useStmt}\n${forwardedSql}`;

    const urlObj = new URL('/sql', SURREAL_URL);
    const url = urlObj.toString();
    const host = urlObj.hostname;
    const port = Number(urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80));

    console.log('Proxying SQL to:', url, 'host:', host, 'port:', port, 'forwardedSql:', JSON.stringify(forwardedSql));

    try {
      await tcpConnectWithRetries(host, port, 60000, 2, 500);
    } catch (e) {
      console.error('TCP preflight failed:', e && (e as Error).message ? (e as Error).message : e);
      return res.status(504).json({ error: `Failed to connect to ${host}:${port} — ${(e && (e as Error).message) || e}` });
    }

    const headers = buildSurrealHeaders();

    const axiosCfg: AxiosRequestConfig = {
      method: 'POST',
      url,
      headers,
      data: forwardedSql,
      timeout: 30000,
      responseType: 'text',
      validateStatus: () => true,
    };

    const sres = await axiosWithRetry(axiosCfg, 2, 500);

    const raw = sres.data;
    let parsed: any = raw;
    try { parsed = JSON.parse(raw); } catch (_) { /* keep raw */ }

    console.log('parsed: ', parsed);

    res.set('Access-Control-Allow-Origin', req.headers.origin || '*');
    if (req.headers.origin) res.set('Vary', 'Origin');

    res.status(sres.status).send(parsed);
  } catch (err: any) {
    console.error('Proxy /api/sql error:', err && err.message ? err.message : err);
    res.status(500).json({ error: String(err && err.message ? err.message : err) });
  }
});

app.post('/api/signin', async (req, res) => {
  try {
    const { access, variables } = req.body || {};
    const url = new URL('/signin', SURREAL_URL).toString();

    const headers = buildSurrealHeaders();
    const payload = {
      namespace: SURREAL_NS,
      database: SURREAL_DB,
      access,
      variables,
    };

    const sres = await axios.post(url, payload, { headers: { ...(headers as any), 'Content-Type': 'application/json' }, timeout: 15000, validateStatus: () => true });

    let parsed = sres.data;
    try { parsed = typeof parsed === 'string' ? JSON.parse(parsed) : parsed; } catch (_) {}
    res.set('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.status(sres.status).send(parsed);
  } catch (err: any) {
    console.error('Proxy /api/signin error:', err && err.message ? err.message : err);
    res.status(500).json({ error: String(err && err.message ? err.message : err) });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Surreal proxy listening on ${port}, proxying to ${SURREAL_URL}`);
});
