// Fast re-check of one finding against the working tree: re-runs the exact rules that flagged it
// on the current version of its file. Used by `fix.mjs resolve` / `apply` so a fix can be marked
// verified in one step, without a full rescan.
//
//   clear     the rule no longer matches the fixed code
//   flagged   it still matches the original line, or a line where the fix went
//   unchecked no rule backs this finding (found in review, structural, dependency): the reviewer's own
//             re-read is the check
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { RULES, QUALITY_RULES, COMMENT, entropy } from './rules.mjs';
import { tryGit, shouldSkip, isBinaryPath, langOf, MAX_BYTES, OUT_DIR } from './common.mjs';

const BY_ID = new Map([...RULES, ...QUALITY_RULES].map((r) => [r.id, r]));

function matches(r, line) {
  if (COMMENT.test(line) && !r.comments) return null;
  const m = r.re.exec(line.length > 20000 ? line.slice(0, 20000) : line);
  if (!m || (r.unless && r.unless.test(line))) return null;
  if (r.entropy && entropy(m[m.length - 1] || m[0]) < r.entropy) return null;
  return m;
}

export function recheck(root, f) {
  const rules = [...new Set((f.checks || []).map((c) => c.rule))].map((id) => BY_ID.get(id)).filter(Boolean)
    .filter((r) => r.langs.includes('*') || r.langs.includes(f.lang)).filter((r) => !r.file || r.file.test(f.file));
  if (!rules.length || /^\(.*\)$/.test(f.file)) return { state: 'unchecked', hits: [] };
  const p = path.resolve(root, f.file);
  if (!p.startsWith(root + path.sep)) return { state: 'unchecked', hits: [] };
  let text;
  try { text = readSource(root, p); } catch (e) {
    // Only a confirmed missing file counts as removed; any other read failure proves nothing.
    return e.code === 'ENOENT' && !fs.existsSync(p)
      ? { state: 'clear', hits: [], reason: 'file removed' }
      : { state: 'unchecked', hits: [], reason: `could not read ${f.file}: ${e.message}` };
  }
  const lines = text.split(/\r?\n/);
  const original = new Set((f.checks || []).map((c) => (c.code || '').trim()).filter(Boolean));
  // Where the fix landed: the original lines, widened by how much the file grew or shrank.
  const drift = Math.abs(lines.length - (f.fileLines || lines.length));
  const lo = f.line - 3 - drift, hi = (f.fix ? f.fix.start + f.fix.after.length : f.endLine) + 3 + drift;
  const hits = [];
  lines.forEach((line, i) => {
    const n = i + 1;
    const same = original.has(line.trim().slice(0, 220));
    if (!same && (n < lo || n > hi)) return;
    for (const r of rules) if (matches(r, line)) { hits.push({ rule: r.id, line: n, code: line.trim().slice(0, 160) }); break; }
  });
  return { state: hits.length ? 'flagged' : 'clear', hits };
}

// Step 1 of the fix checklist: are the lines the scan flagged still there, unchanged, near where
// they were? (Exact match of the scanned lines, ignoring trailing whitespace.)
export function codeChanged(root, f) {
  if (/^\(.*\)$/.test(f.file)) return { ok: true, detail: 'not source code (PR text or commit message)' };
  const s = f.snippet;
  const orig = s ? s.lines.slice(f.line - s.start, f.endLine - s.start + 1).map((l) => l.trimEnd()) : [];
  if (!orig.length || orig.every((l) => !l.trim())) return { ok: false, detail: 'no scanned lines to compare against' };
  const p = path.resolve(root, f.file);
  if (!p.startsWith(root + path.sep)) return { ok: false, detail: 'file is outside the repository' };
  let text;
  try { text = readSource(root, p); } catch (e) {
    return e.code === 'ENOENT' && !fs.existsSync(p)
      ? { ok: true, detail: `${f.file} was removed` }
      : { ok: false, detail: `could not safely read ${f.file}: ${e.message}` };
  }
  const lines = text.split(/\r?\n/).map((l) => l.trimEnd());
  const drift = Math.abs(lines.length - (f.fileLines || lines.length));
  const lo = Math.max(0, f.line - 21 - drift), hi = Math.min(lines.length - orig.length, f.endLine + 20 + drift);
  for (let i = lo; i <= hi; i++) if (orig.every((l, k) => lines[i + k] === l)) {
    return { ok: false, detail: `the flagged code is still there, unchanged (line ${i + 1}${orig.length > 1 ? `–${i + orig.length}` : ''})` };
  }
  return { ok: true, detail: f.endLine > f.line ? `lines ${f.line}–${f.endLine} differ from the scanned version` : `line ${f.line} differs from the scanned version` };
}

// Hash raw bytes without reading beyond the source inspection limit.
function snapshotBytes(root, file) {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.size > MAX_BYTES ||
        !fs.realpathSync(file).startsWith(root + path.sep)) return null;
    const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
      const opened = fs.fstatSync(fd);
      if (!opened.isFile() || opened.size > MAX_BYTES) return null;
      const bytes = Buffer.allocUnsafe(opened.size + 1);
      let size = 0;
      while (size < bytes.length) {
        const count = fs.readSync(fd, bytes, size, bytes.length - size, null);
        if (count === 0) break;
        size += count;
      }
      if (size !== opened.size) return null;
      return bytes.subarray(0, size);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    return err.code === 'ENOENT' ? undefined : null;
  }
}

const digest = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

// Enumerate tracked and non-ignored untracked paths without staging repository files.
// A null entry identifies a path whose contents could not be compared safely.
export function snapshotWorkingTree(root) {
  const paths = tryGit(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z');
  if (paths == null) return null;
  const realRoot = fs.realpathSync(root);
  const files = Object.create(null);
  const hits = Object.create(null);
  for (const rel of new Set(paths.split('\0').filter(Boolean))) {
    if (rel === OUT_DIR || rel.startsWith(OUT_DIR + '/')) continue;
    const bytes = snapshotBytes(realRoot, path.join(realRoot, rel));
    if (bytes === undefined) continue;
    files[rel] = bytes === null ? null : digest(bytes);
    if (bytes === null || bytes.includes(0) || shouldSkip(rel) || isBinaryPath(rel)) continue;
    const counts = Object.create(null);
    for (const { key } of closingHits(rel, bytes.toString('utf8'))) counts[key] = (counts[key] || 0) + 1;
    if (Object.keys(counts).length) hits[rel] = counts;
  }
  return { version: 2, files, hits };
}

// Compare working-tree citations with the raw bytes captured at scan time.
// Older reports containing a Git tree ID need a fresh scan for cross-file verification.
export function fileChangedSince(root, ref, rel, { snapshot = null } = {}) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) return { ok: false, detail: `${rel} is outside the repository` };
  if (!ref && [1, 2].includes(snapshot?.version) && snapshot.files) {
    const key = path.relative(root, p).split(path.sep).join('/');
    const before = Object.hasOwn(snapshot.files, key) ? snapshot.files[key] : undefined;
    const realRoot = fs.realpathSync(root);
    const bytes = snapshotBytes(realRoot, path.join(realRoot, key));
    const now = bytes == null ? bytes : digest(bytes);
    if (before === null || now === null) return { ok: false, detail: `could not safely compare ${rel} with the scan` };
    if (before === now) return { ok: false, detail: now === undefined ? `${rel} doesn't exist` : `${rel} is unchanged since the scan` };
    return { ok: true, detail: before === undefined ? `${rel} is new since the scan` : now === undefined ? `${rel} was removed` : `${rel} changed since the scan` };
  }
  if (!ref) return { ok: false, detail: `no scan-time snapshot to compare ${rel} against (rescan to verify a fix in another file)` };
  const exists = fs.existsSync(p);
  const base = ref;
  const tracked = tryGit(root, 'cat-file', '-e', `${base}:${rel}`) !== null;
  if (!tracked) return exists ? { ok: true, detail: `${rel} is new since the scan` } : { ok: false, detail: `${rel} doesn't exist` };
  if (!exists) return { ok: true, detail: `${rel} was removed` };
  const diff = (tryGit(root, 'diff', '--no-ext-diff', '--no-textconv', '--numstat', base, '--', rel) || '').trim();
  return diff ? { ok: true, detail: `${rel} changed since the scan (+${diff.split(/\s+/)[0]} −${diff.split(/\s+/)[1]})` } : { ok: false, detail: `${rel} is unchanged since the scan` };
}

// ── helpers for the two whole-repo checks below ──
const rulesOf = (ids) => [...new Set(ids)].map((id) => BY_ID.get(id)).filter(Boolean);
const appliesTo = (r, rel, lang) => (r.langs.includes('*') || r.langs.includes(lang)) && (!r.file || r.file.test(rel));
function readSource(root, file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.size > MAX_BYTES ||
      !fs.realpathSync(file).startsWith(fs.realpathSync(root) + path.sep)) {
    throw new Error('File is not a supported source file inside the repository');
  }
  return fs.readFileSync(file, 'utf8');
}

function readSafe(root, rel) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) return null;
  try { return readSource(root, p); } catch { return null; }
}
const MAX_FILES = 20000;
function repoFiles(root) {
  const out = tryGit(root, 'ls-files', '-co', '--exclude-standard', '-z');
  const all = (out || '').split('\0').filter((rel) => rel && !shouldSkip(rel) && !isBinaryPath(rel));
  return { list: all.slice(0, MAX_FILES), capped: all.length > MAX_FILES };
}
// A sibling finding's resolution covers a live match only when its own verified evidence was
// given about that exact match (same rule, same code). A recorded resolution alone is not proof.
function reviewedMatch(other, rule, code) {
  const gone = other?.resolution?.steps?.gone;
  if (!gone?.ok || gone.by !== 'evidence' || !Array.isArray(gone.reviewed)) return false;
  const c = code.slice(0, 160);
  return gone.reviewed.some((h) => h.rule === rule && h.code === c);
}
const countLines = (text, code) => { let n = 0; for (const l of text.split(/\r?\n/)) if (l.trim().slice(0, 220) === code) n++; return n; };
const codeKey = (file, code) => `${file}\u0000${String(code || '').trim().slice(0, 220)}`;

// "Fixed everywhere", step 3, done by script for rule-backed findings: search the whole working
// tree for the same rule and say what each other match is: another finding, a hit the review
// dismissed, or something nobody has looked at. The reviewer only has to judge what's left.
export function findSiblings(root, f, data) {
  const rules = rulesOf((f.checks || []).map((c) => c.rule));
  if (!rules.length || /^\(.*\)$/.test(f.file)) return null;
  const dismissed = new Map();
  for (const d of data.dismissed || []) for (const i of d.items) dismissed.set(codeKey(i.file, i.code), d.reason);
  const files = repoFiles(root);
  const own = { lo: f.line - 3, hi: (f.fix ? f.fix.start + f.fix.after.length : f.endLine) + 3 + Math.abs(((readSafe(root, f.file) || '').split('\n').length) - (f.fileLines || 0)) };
  const hits = [];
  let total = 0;
  const unread = [];
  for (const rel of files.list) {
    const lang = langOf(rel);
    const rs = rules.filter((r) => appliesTo(r, rel, lang));
    if (!rs.length) continue;
    const text = readSafe(root, rel);
    if (text == null) { unread.push(rel); continue; }
    text.split(/\r?\n/).forEach((line, i) => {
      const n = i + 1;
      if (rel === f.file && n >= own.lo && n <= own.hi) return;
      const r = rs.find((x) => matches(x, line));
      if (!r) return;
      total++;
      if (hits.length >= 50) return;
      const code = line.trim().slice(0, 220);
      // Only an exact match of the same rule on the same code ties a hit to another finding;
      // being near one proves nothing.
      const other = data.findings.find((o) => o.id !== f.id && o.file === rel && (o.checks || []).some((c) => c.rule === r.id && (c.code || '').trim() === code));
      hits.push({ file: rel, line: n, rule: r.id, code: code.slice(0, 120), finding: other?.id || null, findingResolved: reviewedMatch(other, r.id, code), dismissed: dismissed.get(codeKey(rel, code)) || null });
    });
  }
  // Incomplete coverage: some matches not listed, files past the cap, or files that couldn't be read.
  const truncated = total > hits.length || files.capped || unread.length > 0;
  return { files: files.list.length, hits, total, truncated, capped: files.capped, unread: unread.length };
}

const closingRules = [...RULES, ...QUALITY_RULES].filter((rule) => rule.sev !== 'info');

function* closingHits(file, text) {
  const lang = langOf(file);
  const rules = closingRules.filter((rule) => appliesTo(rule, file, lang));
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const rule = rules.find((candidate) => matches(candidate, line));
    if (rule) yield {
      key: digest(line.trim()),
      issue: { file, line: i + 1, rule: rule.id, title: rule.title, severity: rule.sev, category: rule.cat, code: line.trim().slice(0, 160) },
    };
  }
}

function workingTreeIssues(root, snapshot) {
  if (snapshot?.version !== 2 || !snapshot.files || !snapshot.hits) return null;
  const paths = tryGit(root, 'ls-files', '-co', '--exclude-standard', '-z');
  if (paths == null) return null;
  const realRoot = fs.realpathSync(root);
  const out = [];
  for (const file of new Set(paths.split('\0').filter(Boolean))) {
    if (shouldSkip(file) || isBinaryPath(file)) continue;
    const before = Object.hasOwn(snapshot.files, file) ? snapshot.files[file] : undefined;
    if (before === null) continue;
    const bytes = snapshotBytes(realRoot, path.join(realRoot, file));
    if (!bytes || bytes.includes(0) || digest(bytes) === before) continue;
    const baseline = Object.hasOwn(snapshot.hits, file) ? snapshot.hits[file] : {};
    const remaining = new Map(Object.entries(baseline));
    for (const { key, issue } of closingHits(file, bytes.toString('utf8'))) {
      const count = remaining.get(key) || 0;
      if (count) remaining.set(key, count - 1);
      else out.push(issue);
      if (out.length === 50) return out;
    }
  }
  return out;
}

// Working-tree reports use scan-time rule-hit counts. Commit-backed reports use Git hunks.
export function newIssues(root, data) {
  const base = data.meta.ref;
  if (!base) return workingTreeIssues(root, data.meta.snapshot);
  // How many occurrences of each reviewed line the review saw, per file.
  const known = new Map();
  const note = (file, code) => { const k = codeKey(file, code); known.set(k, (known.get(k) || 0) + 1); };
  for (const f of data.findings) for (const c of f.checks || []) note(f.file, c.code);
  for (const d of data.dismissed || []) for (const i of d.items) note(i.file, i.code);
  const tracked = (tryGit(root, 'diff', '--no-ext-diff', '--no-textconv', '--name-only', '-z', base, '--') || '').split('\0').filter(Boolean);
  const untracked = (tryGit(root, 'ls-files', '-o', '--exclude-standard', '-z') || '').split('\0').filter((p) => p && !p.startsWith('.codehawk/'));
  const out = [];
  for (const rel of [...new Set([...tracked, ...untracked])].filter((p) => !shouldSkip(p) && !isBinaryPath(p)).slice(0, 500)) {
    const text = readSafe(root, rel);
    if (text == null) continue;
    const lines = text.split(/\r?\n/);
    let ranges = null; // null = whole file (new)
    if (!untracked.includes(rel)) {
      ranges = [];
      const d = tryGit(root, 'diff', '--no-ext-diff', '--no-textconv', '-U0', base, '--', rel) || '';
      for (const m of d.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) { const a = +m[1], n = m[2] === undefined ? 1 : +m[2]; if (n) ranges.push([a, a + n - 1]); }
    }
    const lang = langOf(rel);
    const rs = closingRules.filter((r) => appliesTo(r, rel, lang));
    // A reviewed line is suppressed only while the file holds no more copies of it than were
    // there at scan time; an extra copy is a new occurrence and gets reported.
    const baseText = ranges ? tryGit(root, 'show', '--no-textconv', `${base}:${rel}`) : null;
    const allowed = new Map();
    const isKnown = (code) => {
      const k = codeKey(rel, code);
      if (!known.has(k)) return false;
      if (!allowed.has(k)) {
        const c = String(code).trim().slice(0, 220);
        const before = baseText != null ? countLines(baseText, c) : known.get(k);
        allowed.set(k, countLines(text, c) <= before);
      }
      return allowed.get(k);
    };
    lines.forEach((line, i) => {
      const n = i + 1;
      if (ranges && !ranges.some(([a, b]) => n >= a && n <= b)) return;
      if (isKnown(line)) return;
      const r = rs.find((x) => matches(x, line));
      if (r && out.length < 50) out.push({ file: rel, line: n, rule: r.id, title: r.title, severity: r.sev, category: r.cat, code: line.trim().slice(0, 160) });
    });
  }
  return out;
}
