#!/usr/bin/env node
// Turn .codehawk/findings.json (written by the reviewer) into:
//   .codehawk/report.html   self-contained interactive report
//   .codehawk/report.sarif  SARIF 2.1.0 for GitHub code scanning / IDEs
//   .codehawk/summary.md    a PR-comment-ready summary
// Validates the findings against the scope and the worksheet first.
//
//   node build.mjs <root> [--json] [--partial] [--no-open]
// The report opens in the default browser after every build unless --no-open is given,
// --json is used, or there is no display (CI, SSH without a desktop).
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { parseArgs, outDir, readJson, readAt, fail, SEVERITIES, CATEGORIES, kindOf, toolVersion, EVIDENCE } from './lib/common.mjs';
import { deductionLimit, loadResolutions, applyResolutions, renderOutputs } from './lib/render.mjs';
import { CATEGORY_CWE, CWE_TOP25_2024, OWASP_2021, owaspFor, cweName, cweUrl, top25Rank } from './lib/taxonomy.mjs';

const args = parseArgs(process.argv.slice(2));
const root = path.resolve(args._[0] || '.');
const JSON_OUT = !!args.json;
const dir = outDir(root);
const scope = readJson(path.join(dir, 'scope.json'), null);
if (!scope) fail('No scope yet. Run target.mjs, then scan.mjs, then write findings.json.', JSON_OUT);
const scanId = scope.scanId || scope.generatedAt || null;
const cand = readJson(path.join(dir, 'candidates.json'), null);
if (!cand || !Array.isArray(cand.candidates) || !Array.isArray(cand.readList) || cand.scanId !== scanId) {
  fail('Missing, invalid, or stale candidate results. Run scan.mjs for the current scope.', JSON_OUT);
}
const findingsFile = path.join(dir, 'findings.json');
if (!fs.existsSync(findingsFile)) fail(`Missing ${findingsFile}. Review the worksheet and write it (see references/findings-schema.md).`, JSON_OUT);
let doc;
try { doc = JSON.parse(fs.readFileSync(findingsFile, 'utf8')); } catch (e) { fail(`findings.json is not valid JSON: ${e.message}`, JSON_OUT); }

const errors = [];
const warnings = [];
const CONF = ['high', 'medium', 'low'];
const candById = new Map(cand.candidates.map((c) => [c.id, c]));
const accounted = new Set();
function account(id, where) {
  if (!candById.has(id)) errors.push(`${where}: unknown candidate ${id}`);
  else if (accounted.has(id)) errors.push(`${where}: candidate ${id} already has a disposition`);
  accounted.add(id);
}
const inScope = new Set(scope.files.map((f) => f.path));

// A ready patch: the scanned lines it replaces and the reviewer's replacement for them.
function makeFix(start, before, fixCode) {
  const indent = (before[0] || '').match(/^\s*/)[0];
  let after = fixCode.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n');
  // Re-indent the replacement if the model wrote it flush-left.
  if (after.length && after.every((l) => !l || !/^\s/.test(l)) && indent) after = after.map((l) => (l ? indent + l : l));
  return { start, before, after };
}

function sourceRemote(remote) {
  try {
    const url = new URL(remote);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    if (!/(^|\.)(github\.com|gitlab\.com|bitbucket\.org)$/.test(url.hostname)) return null;
    return url.origin + url.pathname.replace(/\/$/, '');
  } catch {
    return null;
  }
}

const sourceBase = sourceRemote(scope.remote);
const findings = (doc.findings || []).map((f, i) => {
  const where = `findings[${i}]${f.title ? ` "${f.title}"` : ''}`;
  for (const k of ['title', 'severity', 'category', 'file', 'line', 'description', 'fix']) if (f[k] === undefined || f[k] === '') errors.push(`${where}: missing "${k}"`);
  if (f.severity === 'unknown' && f.category !== 'vulnerable-dependency') errors.push(`${where}: unknown severity is reserved for dependency advisories awaiting assessment`);
  if (f.severity && !SEVERITIES.includes(f.severity)) errors.push(`${where}: severity must be one of ${SEVERITIES.join(', ')}`);
  if (f.category && !CATEGORIES[f.category]) errors.push(`${where}: unknown category "${f.category}" (use one of ${Object.keys(CATEGORIES).join(', ')})`);
  if (f.confidence && !CONF.includes(f.confidence)) errors.push(`${where}: confidence must be high, medium or low`);
  const maxDeduction = deductionLimit({ kind: kindOf(f.category), severity: f.severity });
  if (f.scoreDeduction !== undefined && (!Number.isFinite(f.scoreDeduction) || f.scoreDeduction < 0 || f.scoreDeduction > maxDeduction)) {
    errors.push(`${where}: scoreDeduction must be a number between 0 and ${maxDeduction ?? 'the severity limit'}`);
  }
  for (const id of f.candidates || []) account(id, where);
  // Standards: every finding gets a CWE (reviewer's, else its rule's, else its category's);
  // security findings also get an OWASP Top 10 (2021) category.
  const linked = (f.candidates || []).map((id) => candById.get(id)).filter(Boolean);
  let cwe = f.cwe != null && f.cwe !== '' ? String(f.cwe).trim().toUpperCase().replace(/^(CWE[-\s]?)?(\d+)$/, 'CWE-$2') : null;
  if (cwe && !/^CWE-\d+$/.test(cwe)) { warnings.push(`${where}: "${f.cwe}" isn't a CWE id like CWE-89; using the rule's CWE instead`); cwe = null; }
  cwe = cwe || linked.find((c) => c.cwe)?.cwe || CATEGORY_CWE[f.category] || null;
  let owasp = f.owasp ? String(f.owasp).trim().toUpperCase().replace(/^(A\d{2})(:2021)?$/, '$1:2021') : null;
  if (owasp && !OWASP_2021[owasp]) { warnings.push(`${where}: "${f.owasp}" isn't an OWASP Top 10 2021 id like A03:2021; derived it from the CWE instead`); owasp = null; }
  if (kindOf(f.category) === 'security') owasp = owasp || owaspFor(cwe, f.category);
  else owasp = null;
  const dep = linked.find((c) => c.dep)?.dep || null;
  const isMeta = /^\(.*\)$/.test(f.file || '');
  const deleted = scope.files.some((file) => file.path === f.file && file.status === 'deleted');
  const sourceRef = deleted ? scope.base : scope.ref;
  const text = f.file && !isMeta ? readAt(root, sourceRef, f.file) : null;
  if (isMeta) { /* PR description or commit message: no source lines to show */ }
  else if (f.file && text == null) errors.push(`${where}: can't read ${f.file}${scope.ref ? ` at ${scope.ref.slice(0, 7)}` : ''}`);
  else if (f.file && !inScope.has(f.file) && !(cand.deps?.lockfiles || []).some((l) => l.file === f.file)) warnings.push(`${where}: ${f.file} is outside the scanned scope (kept, shown as context)`);
  const lines = text ? text.split(/\r?\n/) : [];
  const line = +f.line || 1;
  const endLine = Math.max(line, +(f.endLine || line));
  if (!isMeta && text && (line < 1 || line > lines.length)) errors.push(`${where}: line ${line} is outside ${f.file} (${lines.length} lines)`);
  const ctx = 5;
  const start = Math.max(1, line - ctx);
  const end = Math.min(lines.length, endLine + ctx);
  const snippet = text ? { start, lines: lines.slice(start - 1, end), hl: [line, Math.min(endLine, lines.length)] } : null;
  const fix = typeof f.fixCode === 'string' && text ? makeFix(line, lines.slice(line - 1, endLine), f.fixCode) : null;
  return {
    id: f.id || null,
    title: f.title, kind: kindOf(f.category), severity: f.severity, category: f.category, categoryLabel: CATEGORIES[f.category] || f.category,
    cwe, cweName: cweName(cwe), top25: top25Rank(cwe), owasp, owaspName: owasp ? OWASP_2021[owasp] : null, confidence: f.confidence || 'medium',
    dep, scoreDeduction: f.scoreDeduction,
    file: f.file, line, endLine, lang: scope.files.find((x) => x.path === f.file)?.lang || 'text',
    description: f.description, impact: f.impact || '', exploit: f.exploit || '', fixText: f.fix,
    references: f.references || [], candidates: f.candidates || [], source: (f.candidates || []).length ? 'rule + review' : 'review',
    // What `fix.mjs resolve` re-runs on the fixed file to verify the fix.
    checks: linked.map(({ rule, line, code }) => ({ rule, line, code })), fileLines: lines.length || null,
    snippet, fix,
    link: sourceBase && (sourceRef || scope.head) && !(sourceRef == null && scope.mode !== 'repo')
      ? `${sourceBase}/blob/${sourceRef || scope.head}/${f.file}#L${line}${endLine > line ? `-L${endLine}` : ''}` : null,
  };
});

const dismissed = (doc.dismissed || []).map((d, i) => {
  const ids = d.candidates || (d.candidate ? [d.candidate] : []);
  if (!ids.length) errors.push(`dismissed[${i}]: needs "candidates": ["C-…"]`);
  if (!d.reason) errors.push(`dismissed[${i}]: needs a "reason"`);
  for (const id of ids) account(id, `dismissed[${i}]`);
  return { reason: d.reason, items: ids.map((id) => candById.get(id)).filter(Boolean).map(({ id, title, file, line, code, severity }) => ({ id, title, file, line, code, severity })) };
});

// ── The review can't be talked out of looking ──
// A dismissal must rest on what the reviewer verified, not on what the code says about itself.
const SELF_CLAIM = /\b(comment|docstring|note|readme|header|annotation|author|pr|description|commit message|the code|the file|it)\b[^.]{0,40}\b(says|said|states|claims|indicates|notes|told|asks|instructs|marks?|marked)\b|\b(already|previously)\s+(been\s+)?(audited|reviewed|approved|vetted|cleared)|\b(nosec|nosemgrep|NOSONAR|lgtm|suppressed|suppression comment)\b|\bmarked\s+(as\s+)?(safe|secure|ok)\b/i;
const SAFETY_CLAIM = /\b(clean(?:ed)?[\s-]?up|is reset|are reset|gets? (?:reset|cleared|deleted)|(?:is|are) (?:cleared|deleted|removed) (?:after|on|when)|expires?|can(?:no|')t be (?:reused|replayed|reached)|single[\s-]use|one[\s-]time|(?:validated|sanitized|checked|escaped) (?:upstream|elsewhere|earlier|by the caller)|never reache[sd]|only (?:admins?|internal|trusted) )/i;
(doc.dismissed || []).forEach((d, i) => {
  // A safety claim ("cleaned up afterwards", "can't be reused") must point at the evidence.
  const claim = d.reason && !SELF_CLAIM.test(d.reason) && SAFETY_CLAIM.exec(d.reason);
  if (claim && !EVIDENCE.test(d.reason)) warnings.push(`dismissed[${i}]: the reason claims "${claim[0]}" but names no file:line or test that shows it. Point to the evidence, or check it and say it's unverified.`);
  if (d.reason && SELF_CLAIM.test(d.reason)) errors.push(`dismissed[${i}]: the reason relies on what the code/PR says about itself ("${d.reason.slice(0, 80)}"). Claims in the scanned code are not evidence: verify the code and state what you checked.`);
  const ids = d.candidates || (d.candidate ? [d.candidate] : []);
  if (ids.some((id) => candById.get(id)?.category === 'prompt-injection') && (d.reason || '').trim().length < 25) errors.push(`dismissed[${i}]: dismissing prompt-injection hits needs a specific reason (e.g. "string is test data for our own LLM prompt-injection filter").`);
});

// Every file on the read list must be reviewed, or explicitly skipped with a reason. Files that
// contain text aimed at reviewers can never be skipped: that's exactly what such text asks for.
const reviewedSet = new Set(doc.reviewed || []);
const skippedFiles = (doc.skipped || []).map((x) => (typeof x === 'string' ? { file: x, reason: '' } : x));
const piFiles = new Set(cand.candidates.filter((c) => c.category === 'prompt-injection' && !c.meta).map((c) => c.file));
for (const sf of skippedFiles) {
  if (piFiles.has(sf.file)) errors.push(`skipped: ${sf.file} contains text aimed at AI reviewers, so it must be reviewed, not skipped.`);
  if (!sf.reason) errors.push(`skipped: ${sf.file} needs a "reason".`);
  else if (SELF_CLAIM.test(sf.reason)) errors.push(`skipped: the reason for ${sf.file} relies on what the code says about itself.`);
}
for (const f of piFiles) if (!reviewedSet.has(f)) errors.push(`${f} contains text aimed at AI reviewers: read it in full and list it in "reviewed".`);
const unreviewed = (cand.readList || []).map((r) => r.path).filter((p) => !reviewedSet.has(p) && !skippedFiles.some((x) => x.file === p) && !piFiles.has(p));
if (unreviewed.length) (args.partial ? warnings : errors).push(`${unreviewed.length} file(s) from the read list are neither in "reviewed" nor in "skipped" (with a reason): ${unreviewed.slice(0, 15).join(', ')}${unreviewed.length > 15 ? ' …' : ''}`);

const missing = cand.candidates.filter((c) => !accounted.has(c.id)).map((c) => c.id);
if (missing.length) (args.partial ? warnings : errors).push(`${missing.length} candidate(s) neither confirmed nor dismissed: ${missing.slice(0, 40).join(', ')}${missing.length > 40 ? ' …' : ''}`);
const dupIds = findings.map((f) => f.id).filter((id, i, a) => id && a.indexOf(id) !== i);
if (dupIds.length) errors.push(`duplicate finding ids: ${[...new Set(dupIds)].join(', ')}`);

if (errors.length) {
  if (JSON_OUT) process.stdout.write(JSON.stringify({ ok: false, errors, warnings }) + '\n');
  else { console.error(`codehawk: findings.json has ${errors.length} problem(s):`); for (const e of errors) console.error(`  ✗ ${e}`); for (const w of warnings) console.error(`  ! ${w}`); }
  process.exit(1);
}

// A rebuild of the same scan keeps the code as it was scanned. Working-tree scans read the files
// live, so without this a rebuild after a fix would show (and compare against) the fixed code.
{
  const prev = readJson(path.join(dir, 'report.json'), null);
  if (prev?.meta?.scanId && prev.meta.scanId === (scope.scanId || scope.generatedAt)) {
    const byKey = new Map(prev.findings.map((f) => [`${f.file}:${f.category}:${f.title}:${f.line}`, f]));
    for (const f of findings) {
      const old = byKey.get(`${f.file}:${f.category}:${f.title}:${f.line}`);
      if (!old?.snippet) continue;
      // Keep the scanned code (snippet and the lines a patch replaces), but take the replacement
      // from the current review: a corrected or removed fixCode must not bring the old patch back.
      const src = doc.findings[findings.indexOf(f)];
      const s = old.snippet;
      const before = old.fix?.before || s.lines.slice(f.line - s.start, f.endLine - s.start + 1);
      Object.assign(f, {
        snippet: s, fileLines: old.fileLines,
        fix: typeof src?.fixCode === 'string' && before.length ? makeFix(old.fix?.start || f.line, before, src.fixCode) : null,
      });
    }
  }
}

// ── score ──
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
findings.sort((a, b) => (a.kind === 'quality') - (b.kind === 'quality') || SEV_RANK[a.severity] - SEV_RANK[b.severity] || CONF.indexOf(a.confidence) - CONF.indexOf(b.confidence) || a.file.localeCompare(b.file) || a.line - b.line);
{ // number findings in display order (most severe first) unless the reviewer chose ids
  const used = new Set(findings.map((f) => f.id).filter(Boolean));
  let n = 0;
  const next = { security: 0, quality: 0 };
  for (const f of findings) if (!f.id) {
    const pre = f.kind === 'quality' ? 'CQ' : 'SEC';
    do f.id = `${pre}-${String(++next[f.kind]).padStart(3, '0')}`; while (used.has(f.id) && next[f.kind] < 1e4);
    used.add(f.id);
  }
}
// Two grades: security (attack surface) and code quality (bugs, robustness, maintainability).
const sec = findings.filter((f) => f.kind === 'security');
const qual = findings.filter((f) => f.kind === 'quality');
const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const kindCounts = { security: sec.length, quality: qual.length, nitpicks: qual.filter((f) => f.severity === 'info').length };

// Walkthrough: what the change does, file by file. Expected for change scans.
const wt = doc.walkthrough || null;
if (wt) {
  if (!wt.summary) errors.push('walkthrough: needs a "summary".');
  for (const [i, c] of (wt.changes || []).entries()) if (!c.summary || !Array.isArray(c.files) || !c.files.length) errors.push(`walkthrough.changes[${i}]: needs "files": [...] and "summary".`);
  if (wt.effort !== undefined && !(wt.effort >= 1 && wt.effort <= 5)) errors.push('walkthrough.effort must be 1–5.');
} else if (scope.mode !== 'repo') warnings.push('No "walkthrough": change reviews should summarize what the change does, file by file.');
if (errors.length) {
  if (JSON_OUT) process.stdout.write(JSON.stringify({ ok: false, errors, warnings }) + '\n');
  else { console.error(`codehawk: findings.json has ${errors.length} problem(s):`); for (const e of errors) console.error(`  ✗ ${e}`); }
  process.exit(1);
}

const fileMap = new Map();
for (const f of findings) {
  const e = fileMap.get(f.file) || { path: f.file, count: 0, worst: f.severity, bySev: {} };
  e.count++; e.bySev[f.severity] = (e.bySev[f.severity] || 0) + 1;
  if (SEV_RANK[f.severity] < SEV_RANK[e.worst]) e.worst = f.severity;
  fileMap.set(f.file, e);
}
const catMap = {};
for (const f of findings) catMap[f.category] = (catMap[f.category] || 0) + 1;

const totalLines = (cand.fileStats || []).reduce((s, x) => s + (x.lines || 0), 0);
const cweCount = {};
for (const f of findings) if (f.cwe) cweCount[f.cwe] = (cweCount[f.cwe] || 0) + 1;
const standards = {
  owasp: Object.entries(OWASP_2021).map(([id, name]) => ({ id, name, count: sec.filter((f) => f.owasp === id).length })),
  top25: CWE_TOP25_2024.map((c, i) => ({ cwe: c, rank: i + 1, name: cweName(c), count: cweCount[c] || 0 })).filter((x) => x.count),
  cwes: Object.entries(cweCount).sort((a, b) => b[1] - a[1]).map(([c, n]) => ({ cwe: c, name: cweName(c), count: n })),
};
const deps = cand.deps ? { ...cand.deps, sbom: cand.deps.sbom ? path.relative(root, cand.deps.sbom) : null } : null;
const depNote = !deps ? null
  : deps.status === 'offline' ? 'Dependencies were not checked for known vulnerabilities (scan ran with --offline).'
  : deps.status === 'error' ? `The known-vulnerability lookup (OSV.dev) failed, so dependencies were not checked: ${deps.error}.`
  : null;
const readableFiles = cand.fileStats?.length ?? 0;
const reviewedInScope = (cand.fileStats || []).filter((f) => reviewedSet.has(f.path)).length;
const coverageNotes = (deps?.inventoryIssues || []).map(({ file, reason }) => `Dependency inventory incomplete: ${file} (${reason}).`);
if (deps?.status === 'partial') coverageNotes.push(`OSV lookup incomplete for ${deps.incomplete} coordinates. Retained ${deps.advisories} advisory matches.`);
if (deps?.truncated) coverageNotes.push(`OSV matched ${deps.truncated} advisories whose details were unavailable or exceeded the detail limit. Their IDs are included, but severity and fix guidance may be incomplete.`);
if (reviewedInScope < readableFiles) coverageNotes.push(`Manual review recorded for ${reviewedInScope} of ${readableFiles} readable files in scope. Remaining files received automated triage only or were skipped.`);
if (cand.unreadable) coverageNotes.push(`${cand.unreadable} file(s) could not be read as source.`);
if (cand.truncated) coverageNotes.push(`${cand.truncated} automated match(es) were omitted by candidate limits.`);
if (args.partial) coverageNotes.push(...warnings.filter((w) => w.includes('neither')));
const data = {
  version: 1,
  meta: {
    scanId, snapshot: cand.snapshot || null,
    label: scope.label, mode: scope.mode, repo: scope.repoName, remote: scope.remote, ref: scope.ref, head: scope.head, base: scope.base,
    pr: scope.pr ? { ...scope.pr, body: undefined } : null, commit: scope.commit || null,
    generatedAt: new Date().toISOString(), filesScanned: readableFiles, linesScanned: totalLines,
    linesChanged: scope.files.reduce((s, f) => s + (f.additions || 0), 0),
    candidates: cand.candidates.length,
    trust: scope.trust || { level: 'unknown', reasons: [] },
    injectionHits: cand.candidates.filter((c) => c.category === 'prompt-injection').length,
  },
  summary: doc.summary || '', notes: [...(doc.notes || []), ...coverageNotes, ...(depNote && !(doc.notes || []).some((n) => /OSV|offline|not checked for known vulnerab/i.test(n)) ? [depNote] : []), ...skippedFiles.map((x) => `Not reviewed: \`${x.file}\` — ${x.reason}`), ...(scope.mode === 'repo' && scope.skipped ? [`${scope.skipped} vendored/built/lock/binary file(s) were outside this whole-repo scan.`] : [])], reviewed: doc.reviewed || [],
  counts, kindCounts, focus: cand.focus || 'all',
  walkthrough: wt,
  standards, deps,
  categories: Object.entries(catMap).sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ key: k, label: CATEGORIES[k] || k, count: n })),
  files: [...fileMap.values()].sort((a, b) => SEV_RANK[a.worst] - SEV_RANK[b.worst] || b.count - a.count),
  findings, dismissed,
};

// ── report.sarif ── (SARIF 2.1.0 with CWE and OWASP Top 10 taxonomies, for GitHub code scanning)
const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note', unknown: 'warning' };
const sarifLevel = (f) => (f.kind === 'quality' && f.severity !== 'critical' ? (f.severity === 'high' ? 'warning' : 'note') : LEVEL[f.severity]);
const SSEV = { critical: 9.5, high: 8.0, medium: 5.5, low: 3.0, info: 1.0 };
// GitHub ranks security alerts by security-severity: use the advisory's CVSS score when there is one.
const secSev = (f) => { const cv = Math.max(...(f.dep?.advisories || []).map((a) => a.cvss?.score ?? -1)); return (cv >= 0 ? cv : SSEV[f.severity])?.toFixed(1); };
const cweNum = (c) => String(c).replace(/\D/g, '');
const owaspUrl = (id) => `https://owasp.org/Top10/${id.replace(':', '_')}-${OWASP_2021[id].replace(/ /g, '_').replace('Server-Side_Request_Forgery', 'Server-Side_Request_Forgery_%28SSRF%29')}/`;
const ruleIds = new Map();
for (const f of findings) {
  const rid = `codehawk/${f.category}${f.cwe ? '/' + f.cwe : ''}`;
  if (!ruleIds.has(rid)) {
    const rels = [];
    if (f.cwe) rels.push({ target: { id: cweNum(f.cwe), toolComponent: { name: 'CWE' } }, kinds: ['superset'] });
    if (f.owasp) rels.push({ target: { id: f.owasp.slice(0, 3), toolComponent: { name: 'OWASP Top 10' } }, kinds: ['superset'] });
    const tags = f.kind === 'security'
      ? ['security', f.category, ...(f.cwe ? [`external/cwe/cwe-${cweNum(f.cwe).padStart(3, '0')}`] : []), ...(f.owasp ? [`external/owasp/${f.owasp.slice(0, 3).toLowerCase()}-2021`] : []), ...(f.top25 ? ['cwe-top-25'] : [])]
      : ['maintainability', 'quality', f.category, ...(f.cwe ? [`external/cwe/cwe-${cweNum(f.cwe).padStart(3, '0')}`] : [])];
    const label = `${f.categoryLabel}${f.cwe ? ` (${f.cwe}${f.cweName ? `: ${f.cweName}` : ''})` : ''}`;
    ruleIds.set(rid, {
      id: rid, name: f.categoryLabel.replace(/[^\w]+/g, ''), shortDescription: { text: label },
      fullDescription: { text: `${label}${f.owasp ? `. OWASP Top 10 ${f.owasp} ${f.owaspName}` : ''}.` },
      helpUri: cweUrl(f.cwe) || undefined,
      help: { text: `${label}.${f.cwe ? ` See ${cweUrl(f.cwe)}` : ''}`, markdown: `**${label}**${f.owasp ? ` · [OWASP ${f.owasp} ${f.owaspName}](${owaspUrl(f.owasp)})` : ''}${f.cwe ? `\n\n[${f.cwe} on cwe.mitre.org](${cweUrl(f.cwe)})` : ''}` },
      relationships: rels.length ? rels : undefined,
      properties: { tags, ...(f.kind === 'security' ? { 'security-severity': secSev(f) } : {}), precision: 'high' },
    });
  } else if (f.kind === 'security') {
    const r = ruleIds.get(rid);
    if (+secSev(f) > +(r.properties['security-severity'] ?? -1)) r.properties['security-severity'] = secSev(f);
  }
  f._rule = rid;
}
const usedCwes = [...new Set(findings.map((f) => f.cwe).filter(Boolean))];
const usedOwasp = [...new Set(findings.map((f) => f.owasp).filter(Boolean))].sort();
const sarif = {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
  runs: [{
    tool: { driver: {
      name: 'CodeHawk', informationUri: 'https://github.com/sudo-py-dev/codehawk', version: toolVersion(), semanticVersion: toolVersion(),
      rules: [...ruleIds.values()],
      supportedTaxonomies: [{ name: 'CWE', index: 0 }, { name: 'OWASP Top 10', index: 1 }],
    } },
    taxonomies: [
      { name: 'CWE', version: '4.16', organization: 'MITRE', informationUri: 'https://cwe.mitre.org/', shortDescription: { text: 'Common Weakness Enumeration' },
        taxa: usedCwes.map((c) => ({ id: cweNum(c), name: cweName(c) || c, helpUri: cweUrl(c), ...(top25Rank(c) ? { properties: { 'cwe-top-25-2024-rank': top25Rank(c) } } : {}) })) },
      { name: 'OWASP Top 10', version: '2021', organization: 'OWASP', informationUri: 'https://owasp.org/Top10/', shortDescription: { text: 'OWASP Top 10 Web Application Security Risks' },
        taxa: usedOwasp.map((id) => ({ id: id.slice(0, 3), name: OWASP_2021[id], helpUri: owaspUrl(id) })) },
    ],
    results: findings.map((f) => ({
      ruleId: f._rule, level: sarifLevel(f),
      message: { text: `${f.title}: ${f.description}${f.dep?.fixTo ? ` Evaluate ${f.dep.name} ${f.dep.fixTo} as an upgrade and recheck the exact version.` : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line, endLine: f.endLine } } }],
      partialFingerprints: { codehawkId: `${f.file}:${f.category}:${f.title}` },
      taxa: [
        ...(f.cwe ? [{ id: cweNum(f.cwe), toolComponent: { name: 'CWE', index: 0 } }] : []),
        ...(f.owasp ? [{ id: f.owasp.slice(0, 3), toolComponent: { name: 'OWASP Top 10', index: 1 } }] : []),
      ],
      properties: {
        findingId: f.id, kind: f.kind, severity: f.severity, confidence: f.confidence, cwe: f.cwe, owasp: f.owasp,
        ...(f.kind === 'security' ? { 'security-severity': secSev(f) } : {}),
        ...(f.dep ? { package: f.dep.name, version: f.dep.version, ecosystem: f.dep.ecosystem, purl: f.dep.purl, fixedVersion: f.dep.fixTo, advisories: f.dep.advisories.map((a) => a.cves[0] || a.id) } : {}),
      },
    })),
  }],
};
for (const f of findings) delete f._rule;
data.sarif = sarif;

// ── report.json / report.html / report.sarif / summary.md ──
// Fixes already marked resolved for this same scan survive a rebuild.
applyResolutions(data, loadResolutions(dir, data.meta.scanId));
renderOutputs(dir, data);

const { score, grade, qualityScore, qualityGrade, verdict } = data;
const reportPath = path.join(dir, 'report.html');
const out = { ok: true, score, grade, qualityScore, qualityGrade, verdict, counts, kindCounts, findings: findings.length, resolved: data.progress.resolved, dismissed: dismissed.reduce((n, d) => n + d.items.length, 0), warnings, report: reportPath, sarif: path.join(dir, 'report.sarif'), summary: path.join(dir, 'summary.md') };
if (JSON_OUT) process.stdout.write(JSON.stringify(out) + '\n');
else {
  console.log(`SECURITY ${grade} (${score}/100) · QUALITY ${qualityGrade} (${qualityScore}/100) · verdict: ${verdict}`);
  console.log(`TRACKS   security ${sec.length} · quality ${qual.length - kindCounts.nitpicks} actionable + ${kindCounts.nitpicks} nitpicks`);
  console.log(`FINDINGS ${SEVERITIES.map((s) => `${s} ${counts[s]}`).join(' · ')}`);
  if (data.progress.resolved) console.log(`RESOLVED ${data.progress.resolved} of ${data.progress.total} (${data.progress.verified} verified)`);
  for (const w of warnings) console.log(`  ! ${w}`);
  console.log(`REPORT   file://${reportPath}`);
  console.log(`SARIF    ${out.sarif}`);
  console.log(`COMMENT  ${out.summary}`);
}
const headless = !!process.env.CI || (process.platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY);
if (!args['no-open'] && (args.open || (!JSON_OUT && !headless))) {
  const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'explorer.exe' : 'xdg-open';
  try {
    const child = spawn(opener, [reportPath], { detached: true, stdio: 'ignore' });
    child.on('error', () => { /* no opener installed: the REPORT line above still has the path */ });
    child.unref();
    if (!JSON_OUT) console.log('OPENED   report in your default browser');
  } catch { /* headless */ }
}

