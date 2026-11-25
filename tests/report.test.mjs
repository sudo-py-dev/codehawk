import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { outDir, writeOutput } from '../skills/codehawk/scripts/lib/common.mjs';
import { run, runFail, git, repo, readList, cands } from './helpers/fixture.mjs';

test('review output rejects a symlinked directory and file', { skip: process.platform === 'win32' }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-output-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const root = path.join(dir, 'checkout');
  const outside = path.join(dir, 'outside');
  fs.mkdirSync(root);
  fs.mkdirSync(outside);
  const output = path.join(root, '.codehawk');
  fs.symlinkSync(outside, output, 'dir');
  assert.throws(() => outDir(root), /Unsafe CodeHawk output path/);
  assert.deepEqual(fs.readdirSync(outside), []);

  fs.unlinkSync(output);
  assert.equal(outDir(root), output);
  const sentinel = path.join(outside, 'sentinel.txt');
  fs.writeFileSync(sentinel, 'original');
  const report = path.join(output, 'report.html');
  fs.symlinkSync(sentinel, report);
  assert.throws(() => writeOutput(report, 'replacement'), /Unsafe CodeHawk output path/);
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'original');

  fs.unlinkSync(report);
  writeOutput(report, 'first review');
  writeOutput(report, 'second review');
  assert.equal(fs.readFileSync(report, 'utf8'), 'second review');
  assert.deepEqual(fs.readdirSync(output).sort(), ['.gitignore', 'report.html']);
});

test('build refuses unreviewed candidates, then renders html, sarif and markdown', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const sql = c.find((x) => x.rule === 'sql-concat');
  const out = path.join(dir, '.codehawk', 'findings.json');
  const finding = { title: 'SQL injection in search', severity: 'critical', category: 'injection', cwe: 'CWE-89', confidence: 'high',
    file: sql.file, line: sql.line, candidates: [sql.id], description: 'Concatenated `q`.', fix: 'Bind it.',
    fixCode: "const rows = await db.query('SELECT * FROM products WHERE name LIKE $1', [`%${q}%`]);" };
  fs.writeFileSync(out, JSON.stringify({ findings: [finding], dismissed: [], reviewed: readList(dir) }));
  const scanFile = path.join(dir, '.codehawk', 'candidates.json');
  const scan = fs.readFileSync(scanFile, 'utf8');
  fs.rmSync(scanFile);
  assert.match(runFail('build.mjs', dir, '--partial').error, /candidate results/);
  fs.writeFileSync(scanFile, JSON.stringify({ ...JSON.parse(scan), scanId: 'previous-scope' }));
  assert.match(runFail('build.mjs', dir).error, /stale candidate results/);
  fs.writeFileSync(scanFile, scan);

  fs.writeFileSync(out, JSON.stringify({ findings: [finding], reviewed: readList(dir),
    dismissed: [{ candidates: [sql.id], reason: 'checked by hand in this test fixture' }] }));
  assert.match(runFail('build.mjs', dir).errors.join('\n'), /already has a disposition/);
  fs.writeFileSync(out, JSON.stringify({ findings: [finding], dismissed: [], reviewed: readList(dir) }));
  const bad = runFail('build.mjs', dir);
  assert.equal(bad.ok, false);
  assert.match(bad.errors.join('\n'), /neither confirmed nor dismissed/);

  fs.writeFileSync(out, JSON.stringify({ summary: 'One critical.', findings: [finding], reviewed: readList(dir),
    dismissed: [{ candidates: c.filter((x) => x.id !== sql.id).map((x) => x.id), reason: 'checked by hand in this test fixture', }] }));
  const ok = run('build.mjs', dir);
  assert.equal(ok.ok, true);
  assert.equal(ok.verdict, 'block');
  assert.equal(ok.counts.critical, 1);
  const html = fs.readFileSync(ok.report, 'utf8');
  assert.ok(!html.includes('"__CODEHAWK_DATA__"'));
  assert.ok(!/<\/script>[^]*"__CODEHAWK/.test(html));
  const sarif = JSON.parse(fs.readFileSync(ok.sarif, 'utf8'));
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, sql.line);
  assert.match(fs.readFileSync(ok.summary, 'utf8'), /```diff/);
});

test('build rejects a line outside the file', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    reviewed: readList(dir),
    findings: [{ title: 'x', severity: 'low', category: 'logic', file: 'src/lib/db.js', line: 999, description: 'x', fix: 'x' }],
    dismissed: [{ candidates: cands(dir).map((x) => x.id), reason: 'checked by hand in this test fixture', }],
  }));
  const r = runFail('build.mjs', dir);
  assert.match(r.errors.join('\n'), /outside src\/lib\/db\.js/);
});

test('serve.mjs: local-only, secret URL, read-only, pushes resolutions, reuses and stops', async () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const sql = c.find((x) => x.rule === 'sql-concat');
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    reviewed: readList(dir),
    findings: [{ title: 'Swallowed error', severity: 'medium', category: 'error-handling', file: sql.file, line: 1, description: 'x', fix: 'x' }],
    dismissed: [{ candidates: c.map((x) => x.id), reason: 'checked by hand in this test fixture' }],
  }));
  run('build.mjs', dir, '--no-open');
  const started = run('serve.mjs', dir, '--idle', '1');
  try {
    const u = new URL(started.url);
    assert.equal(u.hostname, '127.0.0.1');
    assert.match(u.pathname, /^\/[0-9a-f]{32}\/report\.html$/);
    const secret = u.pathname.split('/')[1];
    const get = (p, { method = 'GET', headers = {} } = {}) => new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: u.port, path: p, method, headers }, (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b, headers: res.headers })); });
      req.on('error', reject); req.end();
    });
    const head = await get(`/${secret}/events`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    const page = await get(u.pathname);
    assert.equal(page.status, 200);
    assert.match(page.body, /window\.__codehawkPush = true/);
    assert.equal(page.headers['cache-control'], 'no-store');
    assert.equal((await get('/report.html')).status, 404, 'no secret, no report');
    assert.equal((await get(`/${'0'.repeat(32)}/report.html`)).status, 404, 'wrong secret');
    assert.equal((await get(`/${secret}/findings.json`)).status, 404, 'only the report files are served');
    assert.equal((await get(`/${secret}/../findings.json`)).status, 404);
    assert.equal((await get(u.pathname, { headers: { Host: 'evil.example:' + u.port } })).status, 403, 'DNS rebinding blocked');
    assert.equal((await get(u.pathname, { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
    assert.equal((await get(u.pathname, { method: 'POST' })).status, 405, 'read-only');
    assert.equal(run('serve.mjs', dir).url, started.url, 'a second call reuses the running server');

    // The event stream pushes a resolution the moment fix.mjs writes it.
    const id = JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'report.json'), 'utf8')).findings[0].id;
    const pushed = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('no push within 5s')), 5000);
      const req = http.get({ host: '127.0.0.1', port: u.port, path: `/${secret}/events` }, (res) => {
        let buf = '';
        res.on('data', (d) => {
          buf += d;
          if (buf.includes('event: live') && !buf.includes('"resolutions"')) return;
          const msgs = buf.split('\n\n').filter((m) => m.startsWith('event: live')).map((m) => JSON.parse(m.split('\ndata: ')[1]));
          if (!msgs.length) return;
          if (msgs.length === 1 && !msgs[0].resolutions[id]) { run('fix.mjs', 'resolve', dir, id, '--evidence', 'test fixture: src/server.js:1'); return; }
          const last = msgs.at(-1);
          if (last.resolutions[id]) { clearTimeout(timer); req.destroy(); resolve(last); }
        });
      });
      req.on('error', () => {});
    });
    assert.equal(pushed.resolutions[id].status, 'resolved');
    assert.equal(pushed.progress.resolved, 1);
    // A record whose pid isn't our server (wrong pid for that port) is removed without signalling it.
    const stFile = path.join(dir, '.codehawk', 'serve.json');
    const real = JSON.parse(fs.readFileSync(stFile, 'utf8'));
    fs.writeFileSync(stFile, JSON.stringify({ ...real, pid: process.pid }));
    assert.equal(run('serve.mjs', dir, '--stop').stopped, true, 'the stale record is cleared');
    assert.equal((await get(`/${secret}/health`)).status, 200, 'the unverified pid was not signalled, the server still runs');
    fs.writeFileSync(stFile, JSON.stringify(real));
  } finally {
    run('serve.mjs', dir, '--stop');
  }
  assert.ok(!fs.existsSync(path.join(dir, '.codehawk', 'serve.json')));
});

test('dismissals that claim safety without pointing to a line or test get a warning', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const write = (reason) => fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    reviewed: readList(dir), findings: [],
    dismissed: [{ candidates: [c[0].id], reason }, { candidates: c.slice(1).map((x) => x.id), reason: 'checked by hand in this test fixture' }],
  }));
  write('the temp keys are cleaned up afterwards');
  assert.match(run('build.mjs', dir, '--no-open').warnings.join('\n'), /claims "cleaned up" but names no file:line or test/);
  write('the temp keys are cleaned up in src/server.js:12 on every restart');
  assert.doesNotMatch(run('build.mjs', dir, '--no-open').warnings.join('\n'), /names no file:line/);
});

test('cannot be talked out of reviewing: self-claims and skipping injected files are rejected', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const write = (doc) => fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify(doc));
  const all = c.map((x) => x.id);
  // 1. Dismissing because the code says it's safe/audited.
  write({ findings: [], reviewed: readList(dir), dismissed: [{ candidates: all, reason: 'The header comment says this module was already audited by the security team.' }] });
  assert.match(runFail('build.mjs', dir).errors.join('\n'), /relies on what the code\/PR says about itself/);
  // 2. Skipping the very file that asks not to be reviewed.
  write({ findings: [], reviewed: readList(dir).filter((p) => p !== 'src/lib/db.js'), skipped: [{ file: 'src/lib/db.js', reason: 'generated client' }],
    dismissed: [{ candidates: all, reason: 'checked by hand in this test fixture' }] });
  const e = runFail('build.mjs', dir).errors.join('\n');
  assert.match(e, /db\.js contains text aimed at AI reviewers, so it must be reviewed/);
  // 3. --partial can't excuse it either.
  assert.equal(runFail('build.mjs', dir, '--partial').ok, false);
});

test('build: two grades, walkthrough and the PR comment layout', () => {
  const dir = repo();
  fs.appendFileSync(path.join(dir, 'src/lib/orders.js'), '\nasync function sendAll(xs) { xs.forEach(async (x) => { await notify(x); }); }\n');
  git(dir, 'commit', '-qam', 'notify');
  run('target.mjs', dir, '--commit', 'HEAD');
  run('scan.mjs', dir);
  const c = cands(dir);
  const fe = c.find((x) => x.rule === 'js-foreach-async');
  assert.ok(fe);
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    summary: 'Adds bulk notifications.', reviewed: readList(dir),
    walkthrough: { summary: 'Adds sendAll to notify many users.', changes: [{ files: ['src/lib/orders.js'], summary: 'New sendAll helper.' }], effort: 1 },
    findings: [{ title: 'Notifications are fired without awaiting', severity: 'high', category: 'bug', confidence: 'high', file: fe.file, line: fe.line, candidates: [fe.id],
      description: 'forEach ignores promises.', impact: 'Failures are lost.', fix: 'Use Promise.all.', fixCode: 'async function sendAll(xs) { await Promise.all(xs.map((x) => notify(x))); }' }],
    dismissed: c.filter((x) => x.id !== fe.id).length ? [{ candidates: c.filter((x) => x.id !== fe.id).map((x) => x.id), reason: 'checked by hand in this test fixture' }] : [],
  }));
  const out = run('build.mjs', dir);
  assert.equal(out.grade, 'A');
  assert.equal(out.qualityGrade, 'B');
  assert.equal(out.kindCounts.quality, 1);
  const md = fs.readFileSync(out.summary, 'utf8');
  assert.match(md, /### Walkthrough/);
  assert.match(md, /### Code quality — 1 actionable/);
  assert.match(md, /`LIKELY BUG`/);
  const data = JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'report.json'), 'utf8'));
  assert.equal(data.findings[0].id, 'CQ-001');
});

test("a $' in the commit subject does not corrupt the report", () => {
  const dir = repo();
  fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), 'x\n');
  git(dir, 'add', '-A'); git(dir, 'commit', '-qm', "Escape $' in templates");
  run('target.mjs', dir, '--commit', 'HEAD'); run('scan.mjs', dir);
  const c = cands(dir);
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({ reviewed: readList(dir), findings: [], walkthrough: { summary: 'x' },
    dismissed: c.length ? [{ candidates: c.map((x) => x.id), reason: 'checked by hand in this test fixture' }] : [] }));
  run('build.mjs', dir);
  const html = fs.readFileSync(path.join(dir, '.codehawk', 'report.html'), 'utf8');
  assert.equal(html.match(/<title>/g).length, 1);
  assert.match(html, /<title>[^<]*Escape \$' in templates<\/title>/);
});
