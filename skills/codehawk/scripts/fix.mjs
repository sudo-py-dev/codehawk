#!/usr/bin/env node
// Apply CodeHawk fix suggestions — only with the user's approval.
//
//   node fix.mjs plan  <root> <SEC-001 SEC-004 … | --all> [--json]
//       Shows exactly what would change and prints an approval token. Changes nothing.
//   node fix.mjs apply <root> --token <token> [--json]
//       Applies the planned edits to the working tree. Refuses if the plan wasn't made,
//       if anything changed since, or if the token doesn't match. Never commits, pushes or merges.
//
// The token ties an apply to one specific plan the user has seen, so a fix can't be applied
// "blind" — and the skill only allow-lists `plan`, so `apply` also triggers Claude Code's
// own permission prompt.
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { parseArgs, OUT_DIR, readJson, writeJson, tryGit, fail } from './lib/common.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);
const root = path.resolve(args._[0] || '.');
const JSON_OUT = !!args.json;
const dir = path.join(root, OUT_DIR);
const data = readJson(path.join(dir, 'report.json'), null);
if (!data) fail('No report yet. Run a scan and build.mjs first.', JSON_OUT);
const planFile = path.join(dir, 'fix-plan.json');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function fileLines(rel) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) return null; // never touch anything outside the repo
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}

function assess(f) {
  if (!f.fix) return { id: f.id, status: 'manual', reason: 'No ready-made patch: Claude must write this fix and show it to you first.' };
  const text = fileLines(f.file);
  if (text == null) return { id: f.id, status: 'missing', reason: `${f.file} isn't in the working tree.` };
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  const want = f.fix.before;
  const at = f.fix.start - 1;
  const same = (i) => want.every((l, k) => lines[i + k] === l);
  let idx = same(at) ? at : -1;
  if (idx < 0) { // the code moved: look for a unique exact match of the original lines
    const hits = [];
    for (let i = 0; i + want.length <= lines.length; i++) if (same(i)) hits.push(i);
    if (hits.length === 1) idx = hits[0];
    else return { id: f.id, status: 'drifted', reason: hits.length ? 'The original code appears more than once now.' : 'The code changed since the scan.' };
  }
  return { id: f.id, status: 'ready', file: f.file, start: idx + 1, before: want, after: f.fix.after, fileHash: sha(text), eol };
}

if (cmd === 'plan') {
  const all = args.all || args._.slice(1).includes('--all');
  const ids = all ? data.findings.map((f) => f.id) : args._.slice(1).map((s) => s.toUpperCase());
  if (!ids.length) fail('Name the findings to fix (e.g. SEC-001 SEC-004) or pass --all.', JSON_OUT);
  const unknown = ids.filter((id) => !data.findings.some((f) => f.id === id));
  if (unknown.length) fail(`Unknown finding id(s): ${unknown.join(', ')}`, JSON_OUT);
  const items = ids.map((id) => ({ ...assess(data.findings.find((f) => f.id === id)), title: data.findings.find((f) => f.id === id).title, severity: data.findings.find((f) => f.id === id).severity }));
  // Two patches touching overlapping lines of one file can't both apply cleanly.
  const ready = items.filter((i) => i.status === 'ready');
  for (const a of ready) for (const b of ready) if (a !== b && a.file === b.file && a.status === 'ready' && b.status === 'ready' && a.start <= b.start + b.before.length - 1 && b.start <= a.start + a.before.length - 1 && a.id < b.id) {
    b.status = 'conflict'; b.reason = `Overlaps ${a.id}; apply that first, then re-plan.`;
  }
  const head = (tryGit(root, 'rev-parse', 'HEAD') || '').trim();
  const dirty = (tryGit(root, 'status', '--porcelain') || '').trim().length > 0;
  const warnings = [];
  if (data.meta.ref && head && head !== data.meta.ref) warnings.push(`You're on ${head.slice(0, 7)}, but the scan read ${data.meta.ref.slice(0, 7)}${data.meta.pr ? ` (PR #${data.meta.pr.number})` : ''}. Patches go into your current working tree, only where the original code still matches.`);
  if (dirty) warnings.push('You have uncommitted changes. Consider committing or stashing them first so the fixes are easy to review and undo.');
  if (data.meta.trust?.level === 'untrusted') warnings.push('This code is from an untrusted source. Fixing it locally is fine, but do not run or test it, and push to someone else\'s branch only with their consent.');
  const token = sha(JSON.stringify(ready.filter((r) => r.status === 'ready').map((r) => [r.id, r.file, r.start, r.fileHash, r.after]))).slice(0, 10);
  writeJson(planFile, { token, createdAt: new Date().toISOString(), items });
  if (JSON_OUT) { process.stdout.write(JSON.stringify({ ok: true, token, warnings, items }) + '\n'); process.exit(0); }
  console.log(`FIX PLAN — nothing has been changed yet.\n`);
  for (const w of warnings) console.log(`! ${w}`);
  if (warnings.length) console.log('');
  for (const i of items) {
    console.log(`${i.id}  ${i.severity.toUpperCase()}  ${i.title}`);
    if (i.status !== 'ready') { console.log(`    ${i.status.toUpperCase()}: ${i.reason}\n`); continue; }
    console.log(`    ${i.file}:${i.start}`);
    for (const l of i.before) console.log(`    - ${l}`);
    for (const l of i.after) console.log(`    + ${l}`);
    console.log('');
  }
  const n = items.filter((i) => i.status === 'ready').length;
  console.log(n ? `${n} patch(es) ready. After the user approves them, apply with:\n  node <skill>/scripts/fix.mjs apply ${JSON.stringify(root)} --token ${token}` : 'No ready patches. Write the fixes by hand and show each one to the user before editing.');
} else if (cmd === 'apply') {
  const plan = readJson(planFile, null);
  if (!plan) fail('No fix plan. Run `fix.mjs plan` and get the user\'s approval first.', JSON_OUT);
  if (!args.token || args.token !== plan.token) fail('Token missing or does not match the latest plan. Re-run `fix.mjs plan`, show it to the user, and use the token it prints.', JSON_OUT);
  const ready = plan.items.filter((i) => i.status === 'ready');
  // Re-check every file before touching any of them: all or nothing.
  for (const i of ready) {
    const now = fileLines(i.file);
    if (now == null || sha(now) !== i.fileHash) fail(`${i.file} changed after the plan was made. Re-run \`fix.mjs plan\`.`, JSON_OUT);
  }
  const byFile = {};
  for (const i of ready) (byFile[i.file] ||= []).push(i);
  const applied = [];
  const writes = [];
  for (const [file, list] of Object.entries(byFile)) {
    const p = path.resolve(root, file);
    const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
    for (const i of list.sort((a, b) => b.start - a.start)) { // bottom-up keeps line numbers valid
      lines.splice(i.start - 1, i.before.length, ...i.after);
      applied.push({ id: i.id, file, line: i.start });
    }
    writes.push([p, lines.join(list[0].eol)]);
  }
  try { for (const [p, body] of writes) { const t = p + '.codehawk-tmp'; fs.writeFileSync(t, body); fs.chmodSync(t, fs.statSync(p).mode & 0o7777); } }
  catch (e) { for (const [p] of writes) fs.rmSync(p + '.codehawk-tmp', { force: true }); fail(`Could not write patched files (nothing was changed): ${e.message}`, JSON_OUT); }
  for (const [p] of writes) fs.renameSync(p + '.codehawk-tmp', p);
  fs.rmSync(planFile, { force: true }); // a token works once
  const skipped = plan.items.filter((i) => i.status !== 'ready').map((i) => ({ id: i.id, status: i.status, reason: i.reason }));
  if (JSON_OUT) process.stdout.write(JSON.stringify({ ok: true, applied, skipped }) + '\n');
  else {
    for (const a of applied) console.log(`✔ ${a.id}  ${a.file}:${a.line}`);
    for (const s of skipped) console.log(`· ${s.id}  skipped (${s.status}): ${s.reason}`);
    console.log('\nApplied to the working tree only. Nothing was committed, pushed or merged. Review with `git diff`.');
  }
} else {
  fail('Usage: fix.mjs plan <root> <ids…|--all>   |   fix.mjs apply <root> --token <token>', JSON_OUT);
}
