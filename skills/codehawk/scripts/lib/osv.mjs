// Known-vulnerability lookup against OSV.dev (https://osv.dev), the open database behind
// osv-scanner and GitHub's advisory feed. Sends package names, ecosystems and versions only —
// never source code. Also: CVSS v3 base scores and "which version fixes this".

// CODEHAWK_OSV_URL points the lookup at a mirror or a local mock (the tests use one).
const API = (process.env.CODEHAWK_OSV_URL || 'https://api.osv.dev/v1').replace(/\/$/, '');
const BATCH = 1000;          // OSV's querybatch limit
const MAX_DETAILS = 400;     // cap on advisories fetched in full per scan
const CONCURRENCY = 8;

async function post(url, body, timeoutMs) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'codehawk' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error(`OSV ${r.status} ${r.statusText}`);
  return r.json();
}
async function get(url, timeoutMs) {
  const r = await fetch(url, { headers: { 'user-agent': 'codehawk' }, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) throw new Error(`OSV ${r.status} ${r.statusText}`);
  return r.json();
}

/**
 * Look up packages ([{ name, version, ecosystem }]).
 * Returns { byKey: Map("eco|name|version" → [advisory]), advisories: n, error?, truncated? }.
 */
export async function lookup(pkgs, { timeoutMs = 30000 } = {}) {
  const byKey = new Map();
  const unique = [];
  const seen = new Set();
  for (const p of pkgs) { const k = keyOf(p); if (!seen.has(k)) { seen.add(k); unique.push(p); } }
  if (!unique.length) return { byKey, advisories: 0 };

  const idsByKey = new Map();
  for (let i = 0; i < unique.length; i += BATCH) {
    const chunk = unique.slice(i, i + BATCH);
    const res = await post(`${API}/querybatch`, { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }, timeoutMs);
    (res.results || []).forEach((r, j) => { if (r?.vulns?.length) idsByKey.set(keyOf(chunk[j]), r.vulns.map((v) => v.id)); });
  }

  const allIds = [...new Set([...idsByKey.values()].flat())];
  const ids = allIds.slice(0, MAX_DETAILS);
  const details = new Map();
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ids.length) }, async () => {
    while (next < ids.length) {
      const id = ids[next++];
      try { details.set(id, await get(`${API}/vulns/${encodeURIComponent(id)}`, timeoutMs)); } catch { /* keep the id, without details */ }
    }
  }));

  for (const p of unique) {
    const list = idsByKey.get(keyOf(p));
    if (!list) continue;
    byKey.set(keyOf(p), dedupe(list.map((id) => summarize(details.get(id) || { id }, p))));
  }
  return { byKey, advisories: allIds.length, truncated: allIds.length > ids.length ? allIds.length - ids.length : 0 };
}

export const keyOf = (p) => `${p.ecosystem}|${normName(p)}|${p.version}`;
const normName = (p) => (p.ecosystem === 'PyPI' ? p.name.toLowerCase().replace(/[-_.]+/g, '-') : p.ecosystem === 'NuGet' ? p.name.toLowerCase() : p.name);

// GHSA and CVE records for the same flaw both come back; keep one per alias group.
function dedupe(list) {
  const out = [];
  for (const a of list) {
    const ids = new Set([a.id, ...a.aliases]);
    const i = out.findIndex((b) => ids.has(b.id) || b.aliases.some((x) => ids.has(x)));
    if (i < 0) { out.push(a); continue; }
    const b = out[i];
    // Keep the record with a CVSS score (or the GHSA one), and merge everything it's known as.
    const [keep, other] = !b.cvss?.score && a.cvss?.score ? [a, b] : [b, a];
    const aliases = [...new Set([...keep.aliases, other.id, ...other.aliases])].filter((x) => x !== keep.id);
    out[i] = { ...keep, aliases, cves: [...new Set([...keep.cves, ...other.cves])], cwes: [...new Set([...keep.cwes, ...other.cwes])], fixed: keep.fixed || other.fixed };
  }
  return out;
}

/** Reduce an OSV record to what the worksheet and report need. */
export function summarize(v, pkg) {
  const aliases = (v.aliases || []).filter((a) => a !== v.id);
  const cves = [v.id, ...aliases].filter((x) => /^CVE-\d{4}-\d+$/.test(x));
  let cvss = null;
  for (const s of v.severity || []) {
    if (/^CVSS_V3/.test(s.type)) { const score = cvss3(s.score); if (score != null) { cvss = { version: '3.1', score, vector: s.score }; break; } }
  }
  if (!cvss) { const v4 = (v.severity || []).find((s) => s.type === 'CVSS_V4'); if (v4) cvss = { version: '4.0', score: null, vector: v4.score }; }
  const label = (v.database_specific?.severity || (v.affected || []).map((a) => a.database_specific?.severity || a.ecosystem_specific?.severity).find(Boolean) || '').toString().toLowerCase();
  const malicious = /^MAL-/.test(v.id);
  const severity = malicious ? 'critical' : cvss?.score != null ? severityOf(cvss.score) : { critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' }[label] || 'medium';
  const cwes = (v.database_specific?.cwe_ids || []).filter((c) => /^CWE-\d+$/.test(c));
  const fixed = fixedVersion(v, pkg);
  const advisoryUrl = (v.references || []).find((r) => r.type === 'ADVISORY')?.url || `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`;
  return {
    id: v.id, aliases, cves, summary: (v.summary || (v.details || '').split('\n')[0] || '').slice(0, 300),
    severity, cvss, cwes, fixed: fixed.version, fixedAll: fixed.all, malicious,
    published: v.published || null, url: advisoryUrl,
  };
}

export const severityOf = (score) => (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'info');

/** The lowest fixed version above the installed one, for the affected entry matching pkg. */
function fixedVersion(v, pkg) {
  const all = [];
  for (const a of v.affected || []) {
    if (pkg && a.package && (a.package.ecosystem !== pkg.ecosystem || normName({ ...pkg, name: a.package.name }) !== normName(pkg))) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) all.push(e.fixed);
  }
  const uniq = [...new Set(all)].sort(compareVersions);
  const above = pkg ? uniq.filter((x) => compareVersions(x, pkg.version) > 0) : uniq;
  return { version: above[0] || null, all: uniq };
}

/** Loose version comparison that works across semver, PEP 440, Go and Maven-style versions. */
export function compareVersions(a, b) {
  const norm = (s) => String(s).replace(/^v/, '').replace(/\+.*$/, '');
  const [ma, pa = ''] = norm(a).split(/-(.*)/s);
  const [mb, pb = ''] = norm(b).split(/-(.*)/s);
  const ta = ma.split(/[._]/), tb = mb.split(/[._]/);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i] ?? '0', y = tb[i] ?? '0';
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { if (+x !== +y) return +x - +y; continue; }
    // 1.0rc1 / 2.0b3 style: split numeric prefix from the tag
    const [, dx = '0', sx = ''] = x.match(/^(\d*)(.*)$/), [, dy = '0', sy = ''] = y.match(/^(\d*)(.*)$/);
    if (+dx !== +dy) return +dx - +dy;
    if (sx !== sy) return !sx ? 1 : !sy ? -1 : sx < sy ? -1 : 1;
  }
  if (pa === pb) return 0;
  if (!pa) return 1; // a release sorts after its pre-releases
  if (!pb) return -1;
  return pa < pb ? -1 : 1;
}

// ── CVSS v3.0 / v3.1 base score (FIRST specification, section 7) ──
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};
const roundup = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
export function cvss3(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map((kv) => kv.split(':')));
  const { AV, AC, PR, UI, S, C, I, A } = m;
  if (![AV, AC, PR, UI, S, C, I, A].every(Boolean)) return null;
  const changed = S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[PR];
  const iss = 1 - (1 - W.CIA[C]) * (1 - W.CIA[I]) * (1 - W.CIA[A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * W.AV[AV] * W.AC[AC] * pr * W.UI[UI];
  if ([W.AV[AV], W.AC[AC], pr, W.UI[UI]].some((x) => x === undefined) || Number.isNaN(impact)) return null;
  if (impact <= 0) return 0;
  return changed ? roundup(Math.min(1.08 * (impact + expl), 10)) : roundup(Math.min(impact + expl, 10));
}
