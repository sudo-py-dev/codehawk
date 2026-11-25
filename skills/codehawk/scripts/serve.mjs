#!/usr/bin/env node
// Optional local server for the report, for apps whose preview pane can't run file:// pages
// (e.g. the Claude desktop app). report.html is still written as a plain file on every build;
// this only adds instant push updates and an http:// URL.
//
//   node serve.mjs <root> [--port <n>] [--idle <minutes>] [--json]   start (or reuse) and print the URL
//   node serve.mjs <root> --stop [--json]                             stop it
//
// Safe by default:
//   - listens on 127.0.0.1 only, on a random port unless --port is given;
//   - every URL carries a random secret (http://127.0.0.1:<port>/<secret>/report.html), so other
//     local processes and web pages can't guess it;
//   - only accepts Host 127.0.0.1/localhost on its own port (blocks DNS rebinding) and rejects
//     cross-site requests;
//   - read-only: GET/HEAD for report.html, live.js and an event stream; nothing else is served
//     (not findings.json, not your source), and nothing can be written through it;
//   - stops by itself after --idle minutes (default 20) with no report open.
// It detaches and returns at once; .codehawk/serve.json records it so a second call reuses it.
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseArgs, OUT_DIR, readJson, fail } from './lib/common.mjs';

const args = parseArgs(process.argv.slice(2));
for (const k of ['stop', 'json', 'foreground']) if (typeof args[k] === 'string') { args._.push(args[k]); args[k] = true; }
const root = path.resolve(args._[0] || '.');
const JSON_OUT = !!args.json;
const dir = path.join(root, OUT_DIR);
const stateFile = path.join(dir, 'serve.json');
const report = path.join(dir, 'report.html');
const say = (obj, text) => { if (JSON_OUT) process.stdout.write(JSON.stringify(obj) + '\n'); else console.log(text); };

const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
function healthy(st) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: st.port, path: `/${st.token}/health`, timeout: 800 }, (res) => { res.resume(); resolve(res.statusCode === 200); });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

// ── stop ──
if (args.stop) {
  const st = readJson(stateFile, null);
  if (st?.pid && alive(st.pid)) { try { process.kill(st.pid, 'SIGTERM'); } catch {} }
  fs.rmSync(stateFile, { force: true });
  say({ ok: true, stopped: !!st }, st ? 'STOPPED  report server' : 'No report server was running.');
  process.exit(0);
}

if (!fs.existsSync(report)) fail('No report yet. Run build.mjs first.', JSON_OUT);

// ── start: reuse a running one, otherwise launch a detached child and wait until it listens ──
if (!args.foreground) {
  const st = readJson(stateFile, null);
  if (st?.pid && alive(st.pid) && await healthy(st)) {
    say({ ok: true, url: st.url, pid: st.pid, reused: true }, `URL      ${st.url}\n         (already running; stop with --stop)`);
    process.exit(0);
  }
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), root, '--foreground', ...(args.port ? ['--port', String(args.port)] : []), ...(args.idle ? ['--idle', String(args.idle)] : [])], { detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const timer = setTimeout(() => { try { child.kill(); } catch {} fail('The report server did not start within 5 seconds.', JSON_OUT); }, 5000);
  child.on('message', (m) => {
    clearTimeout(timer);
    if (!m.ok) fail(`Could not start the report server: ${m.error}`, JSON_OUT);
    child.disconnect(); child.unref();
    say({ ok: true, url: m.url, pid: child.pid, idleMinutes: m.idle }, `URL      ${m.url}\n         local only · read-only · stops after ${m.idle} min with no report open · stop with --stop`);
    process.exit(0);
  });
  child.on('exit', (code) => { clearTimeout(timer); fail(`The report server exited (code ${code}).`, JSON_OUT); });
} else {
  serve();
}

function serve() {
  const token = crypto.randomBytes(16).toString('hex');
  const idleMin = Math.max(1, Math.min(24 * 60, +args.idle || 20));
  const clients = new Set();
  let lastActive = Date.now();
  let port = 0;
  const report_ = (m) => { if (process.send) process.send(m); else console.log(m.ok ? `URL      ${m.url}` : `ERROR    ${m.error}`); };

  const liveMsg = () => {
    try {
      const t = fs.readFileSync(path.join(dir, 'live.js'), 'utf8');
      const i = t.lastIndexOf('__codehawkLive(') + '__codehawkLive('.length, j = t.lastIndexOf(')');
      return i > 15 && j > i ? t.slice(i, j) : null;
    } catch { return null; }
  };
  const push = (res, data) => res.write(`event: live\ndata: ${data}\n\n`);

  const HEAD = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'same-origin' };
  const deny = (res, code, msg) => { res.writeHead(code, { ...HEAD, 'Content-Type': 'text/plain; charset=utf-8' }); res.end(msg + '\n'); };

  const server = http.createServer((req, res) => {
    lastActive = Date.now();
    const host = String(req.headers.host || '').toLowerCase();
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return deny(res, 403, 'Forbidden host');
    if (req.headers['sec-fetch-site'] === 'cross-site') return deny(res, 403, 'Cross-site request refused');
    if (req.headers.origin && req.headers.origin !== `http://${host}`) return deny(res, 403, 'Cross-origin request refused');
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.setHeader('Allow', 'GET, HEAD'); return deny(res, 405, 'Read-only'); }
    const url = new URL(req.url, `http://${host}`);
    const parts = url.pathname.split('/');
    const given = Buffer.from(parts[1] || '');
    if (parts.length !== 3 || given.length !== token.length || !crypto.timingSafeEqual(given, Buffer.from(token))) return deny(res, 404, 'Not found');
    const name = parts[2];
    if (name === 'health') { res.writeHead(200, { ...HEAD, 'Content-Type': 'text/plain' }); return res.end('ok\n'); }
    if (name === 'report.html' || name === '') {
      if (name === '') { res.writeHead(302, { ...HEAD, Location: `/${token}/report.html` }); return res.end(); }
      let html;
      try { html = fs.readFileSync(report, 'utf8'); } catch { return deny(res, 404, 'No report yet'); }
      // Tell the page it can use the event stream instead of polling.
      html = html.replace('<script id="codehawk-data"', '<script>window.__codehawkPush = true;</script>\n<script id="codehawk-data"');
      res.writeHead(200, { ...HEAD, 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(req.method === 'HEAD' ? undefined : html);
    }
    if (name === 'live.js') {
      const m = liveMsg();
      res.writeHead(200, { ...HEAD, 'Content-Type': 'text/javascript; charset=utf-8' });
      return res.end(req.method === 'HEAD' ? undefined : m ? `window.__codehawkLive && window.__codehawkLive(${m});\n` : '');
    }
    if (name === 'events') {
      res.writeHead(200, { ...HEAD, 'Content-Type': 'text/event-stream', Connection: 'keep-alive' });
      res.write('retry: 2000\n\n');
      const m = liveMsg();
      if (m) push(res, m); // anything that changed between page load and connect
      clients.add(res);
      req.on('close', () => { clients.delete(res); lastActive = Date.now(); });
      return;
    }
    deny(res, 404, 'Not found');
  });

  // Push every change to live.js (written by build.mjs and fix.mjs) to open reports at once.
  let debounce, lastSent = null;
  const onChange = () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const m = liveMsg();
      if (!m || m === lastSent) return;
      lastSent = m;
      for (const c of clients) push(c, m);
    }, 40);
  };
  let watcher;
  try { watcher = fs.watch(dir, (ev, file) => { if (!file || file === 'live.js') onChange(); }); } catch { /* no fs.watch: pages still poll live.js */ }

  const heartbeat = setInterval(() => { for (const c of clients) c.write(': ping\n\n'); }, 25000);
  const idleCheck = setInterval(() => { if (!clients.size && Date.now() - lastActive > idleMin * 60000) shutdown(); }, 15000);
  function shutdown() {
    clearInterval(heartbeat); clearInterval(idleCheck); watcher?.close();
    const st = readJson(stateFile, null);
    if (st?.pid === process.pid) fs.rmSync(stateFile, { force: true });
    for (const c of clients) c.end();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1000).unref();
  }
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  server.on('error', (e) => { report_({ ok: false, error: e.message }); process.exit(1); });
  server.listen(+args.port || 0, '127.0.0.1', () => {
    port = server.address().port;
    const url = `http://127.0.0.1:${port}/${token}/report.html`;
    fs.writeFileSync(stateFile, JSON.stringify({ pid: process.pid, port, token, url, startedAt: new Date().toISOString() }, null, 2) + '\n', { mode: 0o600 });
    lastSent = liveMsg();
    report_({ ok: true, url, idle: idleMin });
    if (process.send) process.disconnect?.();
  });
}
