// Fast re-check of one finding against the working tree: re-runs the exact rules that flagged it
// on the current version of its file. Used by `fix.mjs resolve` / `apply` so a fix can be marked
// verified in one step, without a full rescan.
//
//   clear     the rule no longer matches the fixed code
//   flagged   it still matches the original line, or a line where the fix went
//   unchecked no rule backs this finding (found in review, structural, dependency): Claude's own
//             re-read is the check
import path from 'node:path';
import fs from 'node:fs';
import { RULES, QUALITY_RULES, COMMENT, entropy } from './rules.mjs';
import { tryGit, shouldSkip, isBinaryPath, langOf, MAX_BYTES } from './common.mjs';

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
  try { text = fs.readFileSync(p, 'utf8'); } catch { return { state: 'clear', hits: [], reason: 'file removed' }; }
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
  try { text = fs.readFileSync(p, 'utf8'); } catch { return { ok: true, detail: `${f.file} was removed` }; }
  const lines = text.split(/\r?\n/).map((l) => l.trimEnd());
  const drift = Math.abs(lines.length - (f.fileLines || lines.length));
  const lo = Math.max(0, f.line - 21 - drift), hi = Math.min(lines.length - orig.length, f.endLine + 20 + drift);
  for (let i = lo; i <= hi; i++) if (orig.every((l, k) => lines[i + k] === l)) {
    return { ok: false, detail: `the flagged code is still there, unchanged (line ${i + 1}${orig.length > 1 ? `–${i + orig.length}` : ''})` };
  }
  return { ok: true, detail: f.endLine > f.line ? `lines ${f.line}–${f.endLine} differ from the scanned version` : `line ${f.line} differs from the scanned version` };
}

// For a fix that landed somewhere else (new middleware, a shared helper): does the cited file
// really differ from the version that was scanned? Checked with git, not taken on trust.
export function fileChangedSince(root, ref, rel) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) return { ok: false, detail: `${rel} is outside the repository` };
  const exists = fs.existsSync(p);
  const base = ref || 'HEAD';
  const tracked = tryGit(root, 'cat-file', '-e', `${base}:${rel}`) !== null;
  if (!tracked) return exists ? { ok: true, detail: `${rel} is new since the scan` } : { ok: false, detail: `${rel} doesn't exist` };
  if (!exists) return { ok: true, detail: `${rel} was removed` };
  const diff = (tryGit(root, 'diff', '--no-ext-diff', '--no-textconv', '--numstat', base, '--', rel) || '').trim();
  return diff ? { ok: true, detail: `${rel} changed since the scan (+${diff.split(/\s+/)[0]} −${diff.split(/\s+/)[1]})` } : { ok: false, detail: `${rel} is unchanged since the scan` };
}

// ── helpers for the two whole-repo checks below ──
const rulesOf = (ids) => [...new Set(ids)].map((id) => BY_ID.get(id)).filter(Boolean);
const appliesTo = (r, rel, lang) => (r.langs.includes('*') || r.langs.includes(lang)) && (!r.file || r.file.test(rel));
function readSafe(root, rel) {
  const p = path.resolve(root, rel);
  if (!p.startsWith(root + path.sep)) return null;
  try { const st = fs.lstatSync(p); if (!st.isFile() || st.size > MAX_BYTES) return null; return fs.readFileSync(p, 'utf8'); } catch { return null; }
}
function repoFiles(root) {
  const out = tryGit(root, 'ls-files', '-co', '--exclude-standard', '-z');
  return (out || '').split('\0').filter((rel) => rel && !shouldSkip(rel) && !isBinaryPath(rel)).slice(0, 20000);
}
const codeKey = (file, code) => `${file}\u0000${String(code || '').trim().slice(0, 220)}`;

// "Fixed everywhere", step 3, done by script for rule-backed findings: search the whole working
// tree for the same rule and say what each other match is: another finding, a hit the review
// dismissed, or something nobody has looked at. Claude only has to judge what's left.
export function findSiblings(root, f, data) {
  const rules = rulesOf((f.checks || []).map((c) => c.rule));
  if (!rules.length || /^\(.*\)$/.test(f.file)) return null;
  const dismissed = new Map();
  for (const d of data.dismissed || []) for (const i of d.items) dismissed.set(codeKey(i.file, i.code), d.reason);
  const files = repoFiles(root);
  const own = { lo: f.line - 3, hi: (f.fix ? f.fix.start + f.fix.after.length : f.endLine) + 3 + Math.abs(((readSafe(root, f.file) || '').split('\n').length) - (f.fileLines || 0)) };
  const hits = [];
  for (const rel of files) {
    const lang = langOf(rel);
    const rs = rules.filter((r) => appliesTo(r, rel, lang));
    if (!rs.length) continue;
    const text = readSafe(root, rel);
    if (text == null) continue;
    text.split(/\r?\n/).forEach((line, i) => {
      const n = i + 1;
      if (rel === f.file && n >= own.lo && n <= own.hi) return;
      const r = rs.find((x) => matches(x, line));
      if (!r || hits.length >= 50) return;
      const code = line.trim().slice(0, 220);
      const other = data.findings.find((o) => o.id !== f.id && o.file === rel && ((o.checks || []).some((c) => c.rule === r.id && (c.code || '').trim() === code) || (n >= o.line - 3 && n <= o.endLine + 3)));
      hits.push({ file: rel, line: n, rule: r.id, code: code.slice(0, 120), finding: other?.id || null, findingResolved: !!other?.resolution, dismissed: dismissed.get(codeKey(rel, code)) || null });
    });
  }
  return { files: files.length, hits };
}

// Issues the fixes may have introduced: every rule run over the lines added since the scan
// (git diff against the scanned commit, plus new untracked files). Hits that match code the
// review already saw (a finding or a dismissal) are left out.
export function newIssues(root, data) {
  const base = data.meta.ref || data.meta.head;
  if (!base) return [];
  const known = new Set();
  for (const f of data.findings) for (const c of f.checks || []) known.add(codeKey(f.file, c.code));
  for (const d of data.dismissed || []) for (const i of d.items) known.add(codeKey(i.file, i.code));
  const tracked = (tryGit(root, 'diff', '--no-ext-diff', '--no-textconv', '--name-only', '-z', base, '--') || '').split('\0').filter(Boolean);
  const untracked = (tryGit(root, 'ls-files', '-o', '--exclude-standard', '-z') || '').split('\0').filter((p) => p && !p.startsWith('.codehawk/'));
  const all = [...RULES, ...QUALITY_RULES].filter((r) => r.sev !== 'info');
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
    const rs = all.filter((r) => appliesTo(r, rel, lang));
    lines.forEach((line, i) => {
      const n = i + 1;
      if (ranges && !ranges.some(([a, b]) => n >= a && n <= b)) return;
      if (known.has(codeKey(rel, line))) return;
      const r = rs.find((x) => matches(x, line));
      if (r && out.length < 50) out.push({ file: rel, line: n, rule: r.id, title: r.title, severity: r.sev, category: r.cat, code: line.trim().slice(0, 160) });
    });
  }
  return out;
}
