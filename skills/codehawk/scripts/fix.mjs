#!/usr/bin/env node
// Apply CodeHawk fix suggestions — only with the user's approval.
//
//   node fix.mjs plan  <root> <SEC-001 SEC-004 … | --all | --severity critical,high> [--json]
//       Shows exactly what would change and prints an approval token. Changes nothing.
//   node fix.mjs apply <root> --token <token> [--json]
//       Applies the planned edits to the working tree. Refuses if the plan wasn't made,
//       if anything changed since, or if the token doesn't match. Never commits, pushes or merges.
//       Every patch it applies is marked resolved and re-checked like `resolve` does.
//   node fix.mjs resolve <root> <SEC-001 …> [--note "…"] [--evidence "…"] [--siblings "…"] [--regression "…"] [--json]
//       Marks findings resolved and runs the fix checklist. A fix is verified only when all four pass:
//         1. Code changed      automatic: the flagged lines differ from the scanned version
//                              (fix in another file: --changed path:line, checked against git)
//         2. Problem gone      automatic rule re-check; with no rule, --evidence citing the line or test
//         3. Fixed everywhere  --siblings: every other place with the same bug and where it was fixed
//         4. No regression     --regression: what the old code handled and where the new code still does
//       Evidence text must cite a file:line or a test. Steps can be added in later calls. Touches
//       no code; the open report updates by itself.
//   node fix.mjs check <root> [--json]
//       The closing sweep, all by script: re-runs the automatic steps on every resolved finding
//       (catches reverted or half-done fixes) and lists issues the changes introduced.
//   node fix.mjs reopen <root> <SEC-001 …> [--json]
//       Clears a resolution (the fix was reverted or turned out wrong).
//   node fix.mjs status <root> [--json]
//       Lists every finding with its resolution status.
//
// The token ties an apply to one specific plan the user has seen, so a fix can't be applied
// "blind" — and the skill only allow-lists `plan`, so `apply` also triggers Claude Code's
// own permission prompt.
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { parseArgs, OUT_DIR, readJson, writeJson, tryGit, fail, EVIDENCE } from './lib/common.mjs';
import { fingerprint, loadResolutions, saveResolutions, applyResolutions, renderOutputs, RESOLUTION_METHODS, FIX_STEPS, stepsPassed } from './lib/render.mjs';
import { recheck, codeChanged, fileChangedSince, findSiblings, newIssues } from './lib/recheck.mjs';

const [cmd, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);
// Boolean flags never take a value: `--verified SEC-001` means the flag plus the id.
for (const k of ['all', 'manual', 'json']) if (typeof args[k] === 'string') { args._.push(args[k]); args[k] = true; }
const root = path.resolve(args._[0] || '.');
const JSON_OUT = !!args.json;
const dir = path.join(root, OUT_DIR);
const data = readJson(path.join(dir, 'report.json'), null);
if (!data) fail('No report yet. Run a scan and build.mjs first.', JSON_OUT);
const planFile = path.join(dir, 'fix-plan.json');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const findingIds = () => args._.slice(1).filter((s) => !s.startsWith('--')).map((s) => s.toUpperCase());

// Record resolutions for this report's scan and re-render every output; the open report picks
// the change up by itself. `entries` maps id → { method, note, steps } or null (reopen).
function record(entries) {
  const res = loadResolutions(dir, data.meta.scanId);
  res.scanId = data.meta.scanId || null;
  const now = new Date().toISOString();
  for (const [id, e] of Object.entries(entries)) {
    const f = data.findings.find((x) => x.id === id);
    if (e === null) { delete res.items[id]; continue; }
    const prev = res.items[id]?.fingerprint === fingerprint(f) ? res.items[id] : null;
    const done = stepsPassed(e.steps) === FIX_STEPS.length;
    res.items[id] = {
      fingerprint: fingerprint(f), method: e.method || prev?.method || 'manual', steps: e.steps,
      note: e.note || prev?.note || '', at: prev?.at || now,
      ...(done ? { verifiedAt: prev?.verifiedAt && stepsPassed(prev.steps) === FIX_STEPS.length ? prev.verifiedAt : now } : {}),
    };
  }
  res.newIssues = newIssues(root, data); // what the fixes themselves may have introduced
  saveResolutions(dir, res);
  applyResolutions(data, res);
  renderOutputs(dir, data);
  return res;
}

// Evidence passed on the command line must be something a reader can check.
function evidenceArg(name) {
  const v = args[name];
  if (v === undefined) return null;
  const t = typeof v === 'string' ? v.trim().slice(0, 600) : '';
  if (!t || !EVIDENCE.test(t)) fail(`--${name} must cite a file:line (e.g. src/auth.js:42) or a test, so it can be checked. Got: ${JSON.stringify(t || v)}`, JSON_OUT);
  const why = uncheckable(t);
  if (why) fail(`--${name}: ${why}`, JSON_OUT);
  return t;
}

// The wording test above is cheap; this makes the citation real. Every file:line must exist in the
// working tree with that many lines, and a bare "test"/"spec" claim must name a test file that exists.
function uncheckable(t) {
  let cited = false;
  for (const m of t.matchAll(/([\w./@+-]+\.\w+):(\d+)/g)) {
    const text = fileLines(m[1]);
    if (text == null) return `${m[1]} isn't a file in the repo, so ${m[0]} can't be checked.`;
    if (Number(m[2]) < 1 || Number(m[2]) > text.split(/\r?\n/).length) return `${m[1]} has no line ${m[2]}.`;
    cited = true;
  }
  if (cited || /\bline \d+/i.test(t)) return null;
  // Only the word "test"/"spec" so far: it must point at a test file that's really there.
  for (const m of t.matchAll(/[\w./@+-]+\.\w+/g)) if (fileLines(m[0]) != null) return null;
  return 'name the test file (e.g. tests/auth.test.js) or a file:line; "test" on its own can\'t be checked.';
}

function changedArg() {
  if (args.changed === undefined) return null;
  const t = typeof args.changed === 'string' ? args.changed.trim() : '';
  if (!/^[\w./@+-]+(?::\d+(?:-\d+)?)?$/.test(t)) fail('--changed takes the file where the fix landed, e.g. src/middleware/auth.js:12', JSON_OUT);
  return t;
}

// Run the checklist for each finding and decide what to record. Automatic steps are re-run every
// time; evidence steps keep what an earlier call recorded unless new evidence is given.
function resolveIds(ids, { method, note, evidence = null, siblings = null, regression = null, changedAt = null, always = false }) {
  const current = loadResolutions(dir, data.meta.scanId);
  const entries = {}, refused = [], results = [];
  for (const id of ids) {
    const f = data.findings.find((x) => x.id === id);
    const prevRec = current.items[id]?.fingerprint === fingerprint(f) ? current.items[id] : null;
    const prev = prevRec?.steps || {};
    let changed = codeChanged(root, f);
    if (!changed.ok && changedAt) { // the fix lives elsewhere: verify the cited file really changed
      const other = fileChangedSince(root, data.meta.ref || data.meta.head, changedAt.replace(/:\d+(?:-\d+)?$/, ''));
      changed = other.ok ? { ok: true, detail: `fixed in ${changedAt}: ${other.detail}` } : { ok: false, detail: `${changed.detail}; and ${other.detail}` };
    }
    if (!changed.ok && !changedAt && prev.changed?.ok && /^fixed in /.test(prev.changed.detail)) changed = prev.changed;
    const check = recheck(root, f);
    const hitTxt = check.hits.map((h) => `line ${h.line}`).join(', ');
    // Earlier evidence holds only for the code it was given about: if the rule now fires somewhere
    // it didn't then (a revert, or a regression after a later change), the evidence is dropped.
    const keepEvidence = prev.gone?.ok && prev.gone.by === 'evidence' && (check.state !== 'flagged' || (prev.gone.hits ?? prev.gone.detail?.match(/\(rule still matches (.*); reviewed/)?.[1] ?? '') === hitTxt);
    let gone;
    if (check.state === 'clear') gone = { ok: true, by: 'rules', detail: 'the rule that flagged it no longer matches' };
    else if (evidence) gone = { ok: true, by: 'evidence', hits: check.state === 'flagged' ? hitTxt : '', detail: evidence + (check.state === 'flagged' ? ` (rule still matches ${hitTxt}; reviewed as the safe new code)` : '') };
    else if (keepEvidence) gone = prev.gone;
    else gone = { ok: false, detail: check.state === 'flagged' ? `the rule still matches ${hitTxt}` : 'not checked yet: needs the line or test that proves it' };
    const steps = {
      changed,
      gone,
      everywhere: siblings ? { ok: true, by: 'evidence', detail: siblings } : prev.everywhere?.ok && prev.everywhere.by !== 'rules' ? prev.everywhere : autoSiblings(f),
      regression: regression ? { ok: true, detail: regression } : prev.regression?.ok ? prev.regression : { ok: false, detail: 'not checked yet: what the old code handled still works' },
    };
    results.push({ id, steps, hits: check.hits });
    // Never mark a fix that didn't happen: the rule still fires with no evidence, or nothing changed and nothing proves it.
    if (!always && check.state === 'flagged' && !evidence && !keepEvidence) refused.push({ id, reason: `the rule still matches ${check.hits.map((h) => `line ${h.line}: ${h.code}`).join('; ')}`, steps });
    else if (!always && !changed.ok && !gone.ok) refused.push({ id, reason: `${changed.detail}, and no evidence shows the problem is gone`, steps });
    else entries[id] = { method, note, steps };
  }
  const res = Object.keys(entries).length ? record(entries) : current;
  return { res, refused, results, marked: Object.keys(entries) };
}

// Step 3 by script where a rule backs the finding: every other match of the rule in the working
// tree must be another finding that's resolved, or a hit the review dismissed. What's left is
// listed so Claude looks at exactly those lines instead of searching.
function autoSiblings(f) {
  const sib = findSiblings(root, f, data);
  if (!sib) return { ok: false, detail: 'not checked yet: other places with the same bug' };
  const open = sib.hits.filter((h) => !h.dismissed && !h.findingResolved);
  const where = (hs) => hs.slice(0, 6).map((h) => `\`${h.file}:${h.line}\`${h.finding ? ` (${h.finding})` : ''}`).join(', ') + (hs.length > 6 ? ` +${hs.length - 6} more` : '');
  if (!open.length) return { ok: true, by: 'rules', detail: sib.hits.length ? `no other unhandled matches of the rule in ${sib.files} files (${where(sib.hits)} already handled)` : `no other matches of the rule in ${sib.files} files` };
  return { ok: false, detail: `same pattern still at ${where(open)}`, hits: open.slice(0, 20) };
}

function printChecklist(id, steps, head) {
  const n = stepsPassed(steps);
  console.log(`${head} ${id}  ${n === FIX_STEPS.length ? 'resolved · verified (4/4)' : `resolved · ${n}/${FIX_STEPS.length} checked`}`);
  const HOW = { changed: 'fix it, or --changed path:line if it landed in another file', gone: '--evidence "file:line or test"', everywhere: 'fix those too (each is re-checked), or --siblings "why they are safe, file:line"', regression: '--regression "…"' };
  for (const [k, label] of FIX_STEPS) console.log(`   ${steps[k]?.ok ? '☑' : '☐'} ${label.padEnd(17)} ${steps[k]?.detail || ''}${steps[k]?.ok ? '' : `  → ${HOW[k]}`}`);
}
function printProgress() {
  const p = data.progress;
  console.log(`\nPROGRESS ${p.verified}/${p.total} verified · ${p.attention} need attention · ${p.open} open${p.newIssues ? ` · ${p.newIssues} NEW in your changes (run check)` : ''} · report updated live`);
}

function unknownIds(ids) {
  const unknown = ids.filter((id) => !data.findings.some((f) => f.id === id));
  if (unknown.length) fail(`Unknown finding id(s): ${unknown.join(', ')}`, JSON_OUT);
}

// The real path of a repo file, or null when it's missing, not a regular file, or (through a
// symlink anywhere on the way) actually outside the repo. Never read or write anything else.
const realRoot = (() => { try { return fs.realpathSync(root); } catch { return root; } })();
function safePath(rel) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) return null;
  try {
    if (!fs.lstatSync(p).isFile()) return null; // symlinks, dirs, devices: no
    const real = fs.realpathSync(p);
    return real.startsWith(realRoot + path.sep) ? p : null;
  } catch { return null; }
}
function fileLines(rel) {
  const p = safePath(rel);
  if (!p) return null;
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}
// Lines with their own endings, so a patch only touches the lines it replaces.
function splitKeep(text) {
  const parts = text.split(/(\r?\n)/);
  const lines = [], eols = [];
  for (let i = 0; i < parts.length; i += 2) { lines.push(parts[i]); eols.push(parts[i + 1] || ''); }
  return { lines, eols };
}
const planToken = (items) => sha(JSON.stringify(items.filter((r) => r.status === 'ready').map((r) => [r.id, r.file, r.start, r.fileHash, r.before, r.after]))).slice(0, 20);

function assess(f) {
  if (f.resolution) return { id: f.id, status: 'resolved', reason: `Already resolved (${f.resolution.passed}/4 checked). Use \`fix.mjs reopen\` first if it needs another fix.` };
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
  const sevs = typeof args.severity === 'string' ? args.severity.toLowerCase().split(',') : null; // e.g. --severity critical,high
  const ids = all || sevs ? data.findings.filter((f) => !f.resolution && (!sevs || sevs.includes(f.severity))).map((f) => f.id) : findingIds();
  if (!ids.length) fail(all ? 'Every finding is already resolved.' : 'Name the findings to fix (e.g. SEC-001 SEC-004) or pass --all.', JSON_OUT);
  unknownIds(ids);
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
  const token = planToken(ready);
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
  // The token covers the patches themselves: an edited fix-plan.json can't ride on an approval.
  if (planToken(plan.items) !== plan.token) fail('The fix plan was changed after it was shown. Re-run `fix.mjs plan` and get approval again.', JSON_OUT);
  const ready = plan.items.filter((i) => i.status === 'ready');
  // Re-check every file before touching any of them: all or nothing.
  for (const i of ready) {
    const now = fileLines(i.file);
    if (now == null || sha(now) !== i.fileHash) fail(`${i.file} changed after the plan was made (or isn't a regular file inside the repo). Re-run \`fix.mjs plan\`.`, JSON_OUT);
  }
  const byFile = {};
  for (const i of ready) (byFile[i.file] ||= []).push(i);
  const applied = [];
  const writes = [];
  for (const [file, list] of Object.entries(byFile)) {
    const p = safePath(file);
    const original = fs.readFileSync(p, 'utf8');
    const { lines, eols } = splitKeep(original);
    for (const i of list.sort((a, b) => b.start - a.start)) { // bottom-up keeps line numbers valid
      const s0 = i.start - 1, n = i.before.length;
      const old = eols.slice(s0, s0 + n);
      const fallback = old[0] || list[0].eol;
      // Each new line keeps the ending of the line it replaces; the last keeps the block's last ending.
      const fresh = i.after.map((_, k) => (k < i.after.length - 1 ? old[k] || fallback : old.length ? old[old.length - 1] : fallback));
      lines.splice(s0, n, ...i.after);
      eols.splice(s0, n, ...fresh);
      applied.push({ id: i.id, file, line: i.start });
    }
    writes.push({ p, original, body: lines.map((l, k) => l + eols[k]).join(''), mode: fs.statSync(p).mode & 0o7777 });
  }
  // Fresh random temp names opened with O_EXCL, so a planted file or symlink can't redirect the write.
  const tmpFor = (p) => path.join(path.dirname(p), `.${path.basename(p)}.codehawk-${crypto.randomBytes(6).toString('hex')}.tmp`);
  const stage = (p, body, mode) => { const t = tmpFor(p); fs.writeFileSync(t, body, { flag: 'wx', mode }); fs.chmodSync(t, mode); return t; };
  try { for (const w of writes) w.tmp = stage(w.p, w.body, w.mode); }
  catch (e) { for (const w of writes) if (w.tmp) fs.rmSync(w.tmp, { force: true }); fail(`Could not write patched files (nothing was changed): ${e.message}`, JSON_OUT); }
  const done = [];
  try { for (const w of writes) { fs.renameSync(w.tmp, w.p); done.push(w); } }
  catch (e) {
    // Put back what was already replaced so the tree is as it was before the apply.
    for (const w of writes) if (!done.includes(w)) fs.rmSync(w.tmp, { force: true });
    for (const w of done) { try { fs.renameSync(stage(w.p, w.original, w.mode), w.p); } catch {} }
    fail(`Could not apply the patches, so none were kept: ${e.message}`, JSON_OUT);
  }
  fs.rmSync(planFile, { force: true }); // a token works once
  const skipped = plan.items.filter((i) => i.status !== 'ready').map((i) => ({ id: i.id, status: i.status, reason: i.reason }));
  // Each applied patch is resolved right away and re-checked against its rules.
  const r = applied.length ? resolveIds(applied.map((a) => a.id), { method: 'patch', always: true }) : null;
  if (JSON_OUT) process.stdout.write(JSON.stringify({ ok: true, applied, skipped, resolved: r?.marked || [], checklists: r?.results || [], progress: data.progress }) + '\n');
  else {
    for (const a of applied) console.log(`✔ ${a.id}  ${a.file}:${a.line}`);
    for (const s of skipped) console.log(`· ${s.id}  skipped (${s.status}): ${s.reason}`);
    console.log('\nApplied to the working tree only. Nothing was committed, pushed or merged. Review with `git diff`.');
    if (r) { console.log(''); for (const x of r.results) printChecklist(x.id, x.steps, '✔'); printProgress(); }
  }
} else if (cmd === 'resolve' || cmd === 'reopen') {
  const ids = findingIds();
  if (!ids.length) fail(`Name the findings to ${cmd} (e.g. SEC-001 CQ-002).`, JSON_OUT);
  unknownIds(ids);
  if (cmd === 'reopen') {
    record(Object.fromEntries(ids.map((id) => [id, null])));
    if (JSON_OUT) process.stdout.write(JSON.stringify({ ok: true, reopened: ids, progress: data.progress }) + '\n');
    else { for (const id of ids) console.log(`↺ ${id}  reopened`); printProgress(); }
    process.exit(0);
  }
  const note = typeof args.note === 'string' ? args.note.trim().slice(0, 500) : '';
  if (args.verified) fail('--verified is gone: each step needs its own evidence. Use --evidence "file:line or test" (problem gone), --siblings "…" (fixed everywhere) and --regression "…" (no regression).', JSON_OUT);
  const { refused, results, marked } = resolveIds(ids, { method: args.manual ? 'manual' : undefined, note, evidence: evidenceArg('evidence'), siblings: evidenceArg('siblings'), regression: evidenceArg('regression'), changedAt: changedArg() });
  if (JSON_OUT) process.stdout.write(JSON.stringify({ ok: true, resolved: marked, refused, checklists: results, progress: data.progress }) + '\n');
  else {
    for (const x of results) if (marked.includes(x.id)) printChecklist(x.id, x.steps, '✔');
    for (const r of refused) console.log(`✗ ${r.id}  not marked: ${r.reason}\n   Fix it first. If that code is already the safe version, cite why with --evidence "file:line or test".`);
    printProgress();
  }
} else if (cmd === 'check') {
  // The closing sweep, all by script: re-run every automatic step on every resolved finding
  // (catches reverted or half-done fixes), refresh new issues in changed lines, update the report.
  const ids = data.findings.filter((f) => f.resolution).map((f) => f.id);
  const { results } = ids.length ? resolveIds(ids, { always: true }) : { results: [] };
  if (!ids.length) record({});
  const p = data.progress;
  const attention = data.findings.filter((f) => f.resolution && !f.resolution.verified);
  const open = data.findings.filter((f) => !f.resolution);
  if (JSON_OUT) { process.stdout.write(JSON.stringify({ ok: true, progress: p, attention: attention.map((f) => ({ id: f.id, missing: FIX_STEPS.filter(([k]) => !f.resolution.steps[k]?.ok).map(([k]) => k) })), open: open.map((f) => f.id), newIssues: data.newIssues, checklists: results }) + '\n'); process.exit(0); }
  console.log(`CHECK    ${p.total} findings · ${p.verified} verified · ${p.attention} need attention · ${p.open} open${data.newIssues.length ? ` · ${data.newIssues.length} new issue(s) in your changes` : ''}`);
  for (const f of attention) for (const [k, label] of FIX_STEPS) if (!f.resolution.steps[k]?.ok) console.log(`!  ${f.id.padEnd(8)} ${label}: ${f.resolution.steps[k]?.detail || 'not checked yet'}`);
  for (const n of data.newIssues) console.log(`+  NEW      ${n.file}:${n.line}  ${n.severity.toUpperCase()}  ${n.title}  \`${n.code}\``);
  if (open.length) console.log(`○  open     ${open.map((f) => f.id).join(' ')}`);
  if (!attention.length && !open.length && !data.newIssues.length) console.log('✔  Everything found in this scan is fixed and verified, and the changes introduced nothing new.');
  console.log(`REPORT   updated live`);
} else if (cmd === 'status') {
  const p = data.progress || applyResolutions(data, loadResolutions(dir, data.meta.scanId)).progress;
  if (JSON_OUT) { process.stdout.write(JSON.stringify({ ok: true, progress: p, findings: data.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, resolution: f.resolution || null })) }) + '\n'); process.exit(0); }
  for (const f of data.findings) {
    const r = f.resolution;
    console.log(`${r ? (r.verified ? '✔' : '◐') : '○'} ${f.id.padEnd(8)} ${f.severity.toUpperCase().padEnd(8)} ${f.title}${r ? `  — ${RESOLUTION_METHODS[r.method]} · ${r.passed}/${FIX_STEPS.length} checked${r.verified ? '' : ` (missing: ${FIX_STEPS.filter(([k]) => !r.steps[k]?.ok).map(([, l]) => l).join(', ')})`}` : ''}`);
  }
  console.log(`\n${p.resolved} of ${p.total} resolved · ${p.verified} fully verified · ${p.total - p.resolved} open`);
} else {
  fail('Usage: fix.mjs plan <root> <ids…|--all>  |  apply <root> --token <t>  |  check <root>  |  resolve <root> <ids…> [--note "…"] [--evidence "…"] [--siblings "…"] [--regression "…"] [--changed file:line]  |  reopen <root> <ids…>  |  status <root>', JSON_OUT);
}
