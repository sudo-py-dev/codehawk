// Shared output rendering: report.json, report.html, report.sarif and summary.md all come from one
// `data` object, so build.mjs (after a scan) and fix.mjs (after a finding is resolved) produce the
// exact same report.
//
// Resolution status lives in .codehawk/resolutions.json, separate from findings.json, so a rebuild
// of the same scan keeps it. It is tied to one scan (scope.scanId): a new scan starts clean, since a
// finding that shows up again after a rescan is, by definition, not fixed.
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { readJson, writeJson, QUALITY_LEVEL } from './common.mjs';
import { cweUrl } from './taxonomy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const TEMPLATE = path.join(here, '..', '..', 'assets', 'report.html');

// ── scoring ──
const CM = { high: 1, medium: 0.75, low: 0.5 };
const SEC_W = { critical: 30, high: 15, medium: 6, low: 2, info: 0 };
const QUAL_W = { critical: 25, high: 12, medium: 4, low: 1.5, info: 0.25 };
export const toGrade = (n) => (n >= 90 ? 'A' : n >= 80 ? 'B' : n >= 65 ? 'C' : n >= 45 ? 'D' : 'F');
const scoreOf = (list, W) => Math.max(0, Math.round(100 - list.reduce((s, f) => s + W[f.severity] * (CM[f.confidence] ?? CM.medium), 0)));
export function scoreFindings(findings) {
  const score = scoreOf(findings.filter((f) => f.kind === 'security'), SEC_W);
  const qualityScore = scoreOf(findings.filter((f) => f.kind === 'quality'), QUAL_W);
  return { score, grade: toGrade(score), qualityScore, qualityGrade: toGrade(qualityScore) };
}

// ── resolutions ──
export const RESOLUTION_METHODS = { patch: 'CodeHawk patch', manual: 'Manual fix' };
// One finding occurrence: two findings with the same title in one file but at different lines, or
// backed by different candidates, never share a resolution. Stable across rebuilds of one scan.
export const fingerprint = (f) => `${f.file}:${f.category}:${f.title}:${f.line ?? ''}-${f.endLine ?? f.line ?? ''}:${[...(f.candidates || [])].sort().join(',')}`;
// The fix checklist. A fix is "verified" only when all four pass.
export const FIX_STEPS = [
  ['changed', 'Code changed'],
  ['gone', 'Problem gone'],
  ['everywhere', 'Fixed everywhere'],
  ['regression', 'No regression'],
];
export const stepsPassed = (steps) => FIX_STEPS.filter(([k]) => steps?.[k]?.ok).length;

export function loadResolutions(dir, scanId) {
  const r = readJson(path.join(dir, 'resolutions.json'), null);
  if (!r || !scanId || r.scanId !== scanId || typeof r.items !== 'object') return { version: 1, scanId: scanId || null, items: {} };
  return r;
}
export function saveResolutions(dir, res) { writeJson(path.join(dir, 'resolutions.json'), res); }

// Attach each finding's resolution (only when its fingerprint still matches, so a reused id from a
// different finding never inherits a status) and compute progress plus the projected grades.
export function applyResolutions(data, res) {
  for (const f of data.findings) {
    const r = res.items[f.id];
    if (!r || r.fingerprint !== fingerprint(f)) { f.resolution = null; continue; }
    const passed = stepsPassed(r.steps);
    f.resolution = { status: 'resolved', method: r.method, steps: r.steps || {}, passed, verified: passed === FIX_STEPS.length, note: r.note || '', at: r.at, verifiedAt: r.verifiedAt || null };
  }
  const done = data.findings.filter((f) => f.resolution);
  const track = (k) => { const all = data.findings.filter((f) => f.kind === k); return { total: all.length, resolved: all.filter((f) => f.resolution).length }; };
  const verified = done.filter((f) => f.resolution.verified).length;
  data.newIssues = Array.isArray(res.newIssues) ? res.newIssues : [];
  data.progress = {
    total: data.findings.length, resolved: done.length, verified, attention: done.length - verified, open: data.findings.length - done.length,
    newIssues: data.newIssues.length,
    security: track('security'), quality: track('quality'),
    // Grades once the verified fixes land: only 4/4 fixes count, so the number isn't optimistic.
    projected: verified ? scoreFindings(data.findings.filter((f) => !f.resolution?.verified)) : null,
  };
  data.liveRev = Date.now();
  return data;
}

// ── writers ──
// live.js: the open report re-loads this small script every couple of seconds (a <script> tag
// works from file://, fetch doesn't) and animates whatever changed, so no reload is needed.
function writeLive(dir, data) {
  const msg = { scanId: data.meta.scanId || null, rev: data.liveRev || Date.now(), progress: data.progress, newIssues: data.newIssues || [], resolutions: Object.fromEntries(data.findings.map((f) => [f.id, f.resolution || null])) };
  const json = JSON.stringify(msg).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16));
  fs.writeFileSync(path.join(dir, 'live.js'), `window.__codehawkLive && window.__codehawkLive(${json});\n`);
}

export function renderOutputs(dir, data) {
  writeJson(path.join(dir, 'report.json'), data);
  // Code scanning should reflect what's still open: only fully verified fixes leave report.sarif;
  // a resolution that failed any check stays in the export.
  if (data.sarif) {
    const resolved = new Set(data.findings.filter((f) => f.resolution?.verified).map((f) => f.id));
    const sarif = JSON.parse(JSON.stringify(data.sarif));
    for (const run of sarif.runs) run.results = run.results.filter((r) => !resolved.has(r.properties?.findingId));
    writeJson(path.join(dir, 'report.sarif'), sarif);
  }
  const template = fs.readFileSync(TEMPLATE, 'utf8');
  const json = JSON.stringify(data).replace(/</g, '\\u003c').replace(/[\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16));
  const html = template
    .replace('__CODEHAWK_TITLE__', () => `CodeHawk · ${escapeHtml(data.meta.label)}`)
    .replace('"__CODEHAWK_DATA__"', () => json);
  fs.writeFileSync(path.join(dir, 'report.html'), html);
  fs.writeFileSync(path.join(dir, 'summary.md'), summaryMarkdown(data));
  writeLive(dir, data);
  return { report: path.join(dir, 'report.html'), sarif: path.join(dir, 'report.sarif'), summary: path.join(dir, 'summary.md') };
}

// summary.md: a PR comment with grades, walkthrough, the open findings by track, folded nitpicks,
// and a "Resolved" section once fixes land.
function summaryMarkdown(data) {
  const { grade, score, qualityGrade, qualityScore, verdict, standards, deps, walkthrough: wt, progress } = data;
  const LABEL = (f) => (f.kind === 'quality' ? `\`${QUALITY_LEVEL[f.severity].toUpperCase()}\`` : `\`${f.severity.toUpperCase()}\``);
  const VERDICT = { block: '**Verdict: blocks merge.** Fix the blocking issues before merging.', review: '**Verdict: needs attention.** No blockers, but worth fixing.', pass: '**Verdict: looks good.** Nothing significant found.' };
  const md = [];
  const loc = (f) => (f.link ? `[\`${f.file}:${f.line}\`](${f.link})` : `\`${f.file}:${f.line}\``);
  const open = data.findings.filter((f) => !f.resolution);
  const sec = open.filter((f) => f.kind === 'security');
  const qual = open.filter((f) => f.kind === 'quality');
  function detail(f, isOpen = false) {
    md.push(`<details${isOpen ? ' open' : ''}><summary>${LABEL(f)} <b>${escapeHtml(f.title)}</b> — ${loc(f).replace(/</g, '&lt;')}${f.cwe ? ` · ${f.cwe}` : ''}${f.owasp ? ` · OWASP ${f.owasp.slice(0, 3)}` : ''}</summary>`, '');
    md.push(f.description, '');
    if (f.cwe) md.push(`<sub>[${f.cwe}${f.cweName ? ` ${escapeHtml(f.cweName)}` : ''}](${cweUrl(f.cwe)})${f.top25 ? ` · CWE Top 25 #${f.top25}` : ''}${f.owasp ? ` · OWASP ${f.owasp} ${f.owaspName}` : ''}</sub>`, '');
    if (f.dep?.advisories?.length) {
      md.push(`**Advisories for \`${f.dep.name}@${f.dep.version}\`:**`, '');
      for (const a of f.dep.advisories.slice(0, 10)) md.push(`- [${a.cves[0] || a.id}](${a.url})${a.cvss?.score != null ? ` · CVSS ${a.cvss.score}` : ''} · ${a.severity}${a.malicious ? ' · malicious' : a.fixed ? ` · fixed in ${a.fixed}` : ' · no fix yet'}${a.summary ? ` — ${a.summary.replace(/\n/g, ' ')}` : ''}`);
      if (f.dep.advisories.length > 10) md.push(`- …and ${f.dep.advisories.length - 10} more`);
      md.push('');
    }
    if (f.impact) md.push(`**${f.kind === 'quality' ? 'Why it matters' : 'Impact'}:** ${f.impact}`, '');
    if (f.exploit) md.push(`**How it could be exploited:** ${f.exploit}`, '');
    md.push(`**${f.kind === 'quality' ? 'Suggestion' : 'Fix'}:** ${f.fixText}`, '');
    if (f.fix) { md.push('```diff'); for (const l of f.fix.before) md.push(`- ${l}`); for (const l of f.fix.after) md.push(`+ ${l}`); md.push('```', ''); }
    md.push('</details>');
  }
  md.push(`## CodeHawk review`, '');
  md.push(`**Security ${grade}** (${score}/100) · **Code quality ${qualityGrade}** (${qualityScore}/100)  `);
  md.push(`${VERDICT[verdict]}  `);
  md.push(`<sub>${data.meta.label} · ${data.meta.filesScanned} files · ${data.meta.candidates} rule hits triaged · ${data.kindCounts.security} security · ${data.kindCounts.quality} quality</sub>`, '');
  if (progress?.resolved) {
    const p = progress.projected;
    md.push(`**${progress.verified} of ${progress.total} fixed and verified** · ${progress.attention} need attention · ${progress.open} open${progress.newIssues ? ` · ${progress.newIssues} new since the scan` : ''}`, '');
    if (p) md.push(`After the verified fixes: Security **${p.grade}** (${p.score}/100) · Code quality **${p.qualityGrade}** (${p.qualityScore}/100)`, '');
  }
  {
    const ow = (standards?.owasp || []).filter((o) => o.count).map((o) => `${o.id.slice(0, 3)} ${o.name} ×${o.count}`);
    const t25 = (standards?.top25 || []).map((t) => `${t.cwe} (#${t.rank})`);
    const dl = !deps ? null
      : deps.status === 'ok' ? `${deps.checked} dependenc${deps.checked === 1 ? 'y' : 'ies'} checked against OSV.dev, ${deps.vulnerable} vulnerable`
      : deps.status === 'offline' ? '**dependencies not checked for CVEs (offline)**'
      : deps.status === 'error' ? '**dependency CVE check failed**'
      : deps.status === 'nothing-changed' ? 'no dependency versions changed'
      : null;
    const bits = [ow.length && `**OWASP Top 10:** ${ow.join(' · ')}`, t25.length && `**CWE Top 25:** ${t25.join(', ')}`, dl && `**Dependencies:** ${dl}`].filter(Boolean);
    if (bits.length) md.push(bits.join('  \n'), '');
  }
  if (data.summary) md.push(data.summary, '');
  if (data.meta.trust.level !== 'trusted' || data.meta.injectionHits) {
    md.push(`> [!WARNING]`, `> Reviewed code from an untrusted source${data.meta.injectionHits ? ` and found ${data.meta.injectionHits} line(s) of text aimed at AI reviewers or hidden characters` : ''}. AI-assisted reviews can be manipulated by prompt injection; a clean result is not a guarantee. Have a human check anything security-critical.`, '');
  }
  if (wt) {
    md.push('### Walkthrough', '', wt.summary, '');
    if (wt.changes?.length) {
      md.push('| Files | Change summary |', '|---|---|');
      for (const c of wt.changes) md.push(`| ${c.files.map((x) => `\`${x}\``).join('<br>')} | ${String(c.summary).replace(/\|/g, '\\|').replace(/\n/g, ' ')} |`);
      md.push('');
    }
    if (wt.effort) md.push(`**Estimated review effort:** ${wt.effort}/5 ${'●'.repeat(wt.effort)}${'○'.repeat(5 - wt.effort)}`, '');
  }
  if (sec.length) { md.push(`### Security — ${sec.length}${progress?.security.resolved ? ' open' : ''}`, ''); for (const f of sec) detail(f, f.severity === 'critical'); md.push(''); }
  const actionable = qual.filter((f) => f.severity !== 'info');
  const nits = qual.filter((f) => f.severity === 'info');
  if (actionable.length) { md.push(`### Code quality — ${actionable.length} actionable`, ''); for (const f of actionable) detail(f); md.push(''); }
  if (nits.length) {
    md.push(`<details><summary><b>Nitpicks (${nits.length})</b></summary>`, '');
    for (const f of nits) md.push(`- ${loc(f)} — **${escapeHtml(f.title)}.** ${f.fixText}`);
    md.push('', '</details>', '');
  }
  const attention = data.findings.filter((f) => f.resolution && !f.resolution.verified);
  if (attention.length) {
    md.push(`### Needs attention — ${attention.length}`, '', 'Marked fixed, but not every check has passed yet:', '');
    for (const f of attention) md.push(`- ${loc(f)} **${escapeHtml(f.title)}** \`${f.id}\` — missing: ${FIX_STEPS.filter(([k]) => !f.resolution.steps[k]?.ok).map(([k, l]) => `${l} (${String(f.resolution.steps[k]?.detail || 'not checked').replace(/\n/g, ' ')})`).join('; ')}`);
    md.push('');
  }
  if (data.newIssues?.length) {
    md.push(`### New since the scan — ${data.newIssues.length}`, '', 'Rule hits on lines changed after the scan (likely introduced by the fixes). Not reviewed yet:', '');
    for (const n of data.newIssues) md.push(`- \`${n.file}:${n.line}\` \`${n.severity.toUpperCase()}\` ${escapeHtml(n.title)} — \`${String(n.code).replace(/`/g, "'")}\``);
    md.push('');
  }
  const done = data.findings.filter((f) => f.resolution);
  if (done.length) {
    md.push(`### Resolved — ${done.length}`, '', '| | Finding | Where | How |', '|---|---|---|---|');
    const cell = (t) => String(t).replace(/\|/g, '\\|').replace(/\n/g, ' ');
    for (const f of done) {
      const r = f.resolution;
      const checks = FIX_STEPS.map(([k, label]) => `${r.steps[k]?.ok ? '☑' : '☐'} ${label}`).join(' · ');
      md.push(`| ${r.verified ? '✅' : `⚠️ ${r.passed}/${FIX_STEPS.length}`} | ${LABEL(f)} **${escapeHtml(f.title)}** \`${f.id}\` | ${loc(f)} | ${RESOLUTION_METHODS[r.method] || 'Fixed'}${r.note ? ` — ${cell(r.note)}` : ''}<br><sub>${checks}</sub> |`);
    }
    md.push('');
  }
  if (!data.findings.length) md.push('_No issues confirmed in this scope._');
  else if (data.findings.every((f) => f.resolution?.verified) && !data.newIssues?.length) md.push('_Every finding from this review is fixed and verified, and the changes introduced nothing new._');
  md.push('', `<sub>Generated by CodeHawk · ${data.dismissed.reduce((n, d) => n + d.items.length, 0)} rule hits checked and dismissed.</sub>`);
  return md.join('\n') + '\n';
}

export function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
