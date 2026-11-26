// Dependency inventory: find lockfiles and manifests, parse the exact package versions they pin
// (with the line each one is declared on), and build package URLs for the SBOM.
// Pure parsing — nothing here runs a package manager or touches the network.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { tryGit } from './common.mjs';

// Lockfiles first: they pin exact versions. Manifests only count where they pin exactly too.
const PARSERS = [
  [/(^|\/)(package-lock|npm-shrinkwrap)\.json$/, 'npm', parseNpmLock],
  [/(^|\/)yarn\.lock$/, 'npm', parseYarnLock],
  [/(^|\/)pnpm-lock\.ya?ml$/, 'npm', parsePnpmLock],
  [/(^|\/)(poetry|uv|pdm)\.lock$/, 'PyPI', parseTomlPackages],
  [/(^|\/)Pipfile\.lock$/, 'PyPI', parsePipfileLock],
  [/(^|\/)[^/]*requirements[^/]*\.(txt|in)$/i, 'PyPI', parseRequirements],
  [/(^|\/)go\.mod$/, 'Go', parseGoMod],
  [/(^|\/)Cargo\.lock$/, 'crates.io', parseTomlPackages],
  [/(^|\/)composer\.lock$/, 'Packagist', parseComposerLock],
  [/(^|\/)Gemfile\.lock$/, 'RubyGems', parseGemfileLock],
  [/(^|\/)pom\.xml$/, 'Maven', parsePom],
  [/(^|\/)(gradle\.lockfile|[^/]*\.lockfile)$/, 'Maven', parseGradleLock],
  [/(^|\/)packages\.lock\.json$/, 'NuGet', parseNugetLock],
  [/\.(csproj|fsproj|vbproj)$/, 'NuGet', parseCsproj],
];
// Installed or vendored copies are not the project's declared dependencies.
const SKIP = /(^|\/)(node_modules|vendor|bower_components|\.git|\.codehawk|\.venv|venv|\.tox|target|dist|build)\//;

export const isDepFile = (p) => !SKIP.test(p) && PARSERS.some(([re]) => re.test(p));
export const isTestPath = (p) => /(^|\/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|e2e|testdata)(\/|$)/i.test(p);

/** Every file in the scanned version of the repo (git object, index + untracked, or plain walk). */
export function listAllFiles(root, ref) {
  let out = null;
  if (ref) out = tryGit(root, 'ls-tree', '-r', '--name-only', '-z', ref);
  else out = tryGit(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z');
  if (out != null) return out.split('\0').filter(Boolean);
  const list = [];
  const walk = (dir, depth) => {
    if (depth > 12) return;
    let entries = [];
    try { entries = fs.readdirSync(path.join(root, dir), { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP.test(rel + '/')) walk(rel, depth + 1); } else if (e.isFile()) list.push(rel);
    }
  };
  walk('', 0);
  return list;
}

/** Parse one dependency file. Returns [{ name, version, ecosystem, line, dev? }]. */
export function parseDepFile(rel, text, { includeOccurrences = false, onIssue } = {}) {
  const hit = PARSERS.find(([re]) => re.test(rel));
  if (!hit) return [];
  if (text == null) {
    onIssue?.('unreadable or above the size limit');
    return [];
  }
  const [, ecosystem, fn] = hit;
  let pkgs = [];
  try { pkgs = fn(text, ecosystem) || []; } catch {
    onIssue?.('invalid dependency file');
    return [];
  }
  const seen = new Set();
  return pkgs
    .filter((p) => p.name && p.version && /^[\w.+~:-]+$/.test(p.version))
    .map((p) => ({ ecosystem, ...p, name: p.name.trim(), version: p.version.trim() }))
    .filter((p) => { const k = `${p.name}@${p.version}`; if (includeOccurrences) return true; if (seen.has(k)) return false; seen.add(k); return true; });
}

// ── helpers ──
const lineOf = (lines, re, from = 0) => { for (let i = from; i < lines.length; i++) if (re.test(lines[i])) return i + 1; return 0; };
// An npm alias can have a different installed name from the package in the registry.
const npmAlias = (specifier) => specifier.match(/^npm:((?:@[^/@]+\/)?[^@]+)@(.+)$/);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function parseNpmLock(text) {
  const doc = JSON.parse(text);
  const lines = text.split(/\r?\n/);
  const out = [];
  if (doc.packages) {
    const lineByKey = new Map();
    lines.forEach((l, i) => { const m = l.match(/^\s*"([^"]*node_modules\/[^"]+)"\s*:\s*\{/); if (m && !lineByKey.has(m[1])) lineByKey.set(m[1], i + 1); });
    for (const [key, p] of Object.entries(doc.packages)) {
      if (!key || p.link || !p.version) continue;
      const name = p.name || key.slice(key.lastIndexOf('node_modules/') + 13);
      out.push({ name, version: p.version, line: lineByKey.get(key) || 1, dev: !!(p.dev || p.devOptional) });
    }
  } else if (doc.dependencies) {
    let cursor = 0;
    const walk = (deps) => {
      for (const [name, p] of Object.entries(deps || {})) {
        const ln = lineOf(lines, new RegExp(`^\\s*"${esc(name)}"\\s*:\\s*\\{`), cursor);
        if (ln) cursor = ln;
        const alias = typeof p.version === 'string' && npmAlias(p.version);
        if (p.version && !/^(file|link|git|github|https?):/.test(p.version)) {
          out.push({ name: alias ? alias[1] : name, version: alias ? alias[2] : p.version, line: ln || 1, dev: !!p.dev });
        }
        walk(p.dependencies);
      }
    };
    walk(doc.dependencies);
  }
  return out;
}

function parseYarnLock(text) {
  const lines = text.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l || /^\s|^#/.test(l) || !l.endsWith(':') || l.startsWith('__metadata')) continue;
    const spec = l.slice(0, -1).split(',')[0].trim().replace(/^"|"$/g, '');
    const at = spec.indexOf('@', 1);
    if (at < 0) continue;
    const alias = npmAlias(spec.slice(at + 1));
    const name = alias ? alias[1] : spec.slice(0, at);
    for (let j = i + 1; j < Math.min(lines.length, i + 12) && /^\s/.test(lines[j]); j++) {
      const m = lines[j].match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (m) { if (!/use\.local|^0\.0\.0-use/.test(m[1])) out.push({ name, version: m[1], line: i + 1 }); break; }
    }
  }
  return out;
}

function parsePnpmLock(text) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let inPkgs = false;
  lines.forEach((l, i) => {
    if (/^\S/.test(l)) inPkgs = /^packages:\s*$/.test(l);
    if (!inPkgs) return;
    // v5: /name/1.2.3:  v6: /name@1.2.3:  v9: name@1.2.3:  (peer suffixes in parentheses)
    const m = l.match(/^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s('"]+)[@/](\d[^:('"\s_]*)/);
    if (m) out.push({ name: m[1], version: m[2], line: i + 1 });
  });
  return out;
}

function parseTomlPackages(text) {
  const lines = text.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\[\[package\]\]\s*$/.test(lines[i])) continue;
    let name = null, version = null, line = i + 1;
    for (let j = i + 1; j < lines.length && !/^\[/.test(lines[j]); j++) {
      const n = lines[j].match(/^name\s*=\s*"([^"]+)"/); if (n) { name = n[1]; line = j + 1; }
      const v = lines[j].match(/^version\s*=\s*"([^"]+)"/); if (v) version = v[1];
      if (name && version) break;
    }
    if (name && version) out.push({ name, version, line });
  }
  return out;
}

function parsePipfileLock(text) {
  const doc = JSON.parse(text);
  const lines = text.split(/\r?\n/);
  const out = [];
  for (const [section, dev] of [['default', false], ['develop', true]]) {
    for (const [name, p] of Object.entries(doc[section] || {})) {
      const v = String(p.version || '').replace(/^==/, '');
      if (v) out.push({ name, version: v, line: lineOf(lines, new RegExp(`^\\s*"${esc(name)}"\\s*:\\s*\\{`)) || 1, dev });
    }
  }
  return out;
}

function parseRequirements(text) {
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => {
    const m = l.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;#,]+)/);
    if (m) out.push({ name: m[1], version: m[3], line: i + 1 });
  });
  return out;
}

function parseGoMod(text) {
  const out = [];
  let inReq = false;
  text.split(/\r?\n/).forEach((l, i) => {
    const t = l.trim();
    if (/^require\s*\($/.test(t)) { inReq = true; return; }
    if (inReq && t === ')') { inReq = false; return; }
    const m = inReq ? t.match(/^([^\s/]+\.[^\s]+)\s+(v[^\s]+)/) : t.match(/^require\s+([^\s(]+)\s+(v[^\s]+)/);
    if (m) out.push({ name: m[1], version: m[2], line: i + 1 });
  });
  return out;
}

function parseComposerLock(text) {
  const doc = JSON.parse(text);
  const lines = text.split(/\r?\n/);
  const out = [];
  for (const [section, dev] of [['packages', false], ['packages-dev', true]]) {
    for (const p of doc[section] || []) {
      if (!p.name || !p.version || /^dev-/.test(p.version)) continue;
      out.push({ name: p.name, version: p.version.replace(/^v/, ''), line: lineOf(lines, new RegExp(`"name"\\s*:\\s*"${esc(p.name)}"`)) || 1, dev });
    }
  }
  return out;
}

function parseGemfileLock(text) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let inGem = false;
  lines.forEach((l, i) => {
    if (/^\S/.test(l)) inGem = l.trim() === 'GEM';
    if (!inGem) return;
    const m = l.match(/^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$/);
    if (m) out.push({ name: m[1], version: m[2].replace(/-(x86|x64|arm|aarch|java|universal|mingw|mswin|darwin|linux)[\w-]*$/, ''), line: i + 1 });
  });
  return out;
}

function parsePom(text) {
  const out = [];
  let line = 1;
  let newline = text.indexOf('\n');
  const re = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m;
  while ((m = re.exec(text))) {
    const body = m[1];
    const g = body.match(/<groupId>\s*([^<\s]+)\s*<\/groupId>/)?.[1];
    const artifact = body.match(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/);
    const a = artifact?.[1];
    const v = body.match(/<version>\s*([^<\s]+)\s*<\/version>/)?.[1];
    if (!g || !a || !v || v.includes('${') || /[[(,]/.test(v)) continue;
    const offset = m.index + '<dependency>'.length + artifact.index;
    while (newline !== -1 && newline < offset) {
      line++;
      newline = text.indexOf('\n', newline + 1);
    }
    out.push({ name: `${g}:${a}`, version: v, line, dev: /<scope>\s*test\s*</.test(body) });
  }
  return out;
}

function parseGradleLock(text) {
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => {
    const m = l.match(/^([\w.-]+):([\w.-]+):([^=\s]+)=(.*)$/);
    if (m) out.push({ name: `${m[1]}:${m[2]}`, version: m[3], line: i + 1, dev: !/(runtimeClasspath|compileClasspath)/.test(m[4]) && /test/i.test(m[4]) });
  });
  return out;
}

function parseNugetLock(text) {
  const doc = JSON.parse(text);
  const lines = text.split(/\r?\n/);
  const out = [];
  for (const deps of Object.values(doc.dependencies || {})) {
    for (const [name, p] of Object.entries(deps || {})) {
      if (p.resolved && p.type !== 'Project') out.push({ name, version: p.resolved, line: lineOf(lines, new RegExp(`^\\s*"${esc(name)}"\\s*:\\s*\\{`)) || 1 });
    }
  }
  return out;
}

function parseCsproj(text) {
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => {
    const name = l.match(/<PackageReference\b[^>]*\bInclude="([^"]+)"/i)?.[1];
    const version = l.match(/<PackageReference\b[^>]*\bVersion="([^"$[\]()*]+)"/i)?.[1];
    if (name && version) out.push({ name, version, line: i + 1 });
  });
  return out;
}

// ── package URLs (https://github.com/package-url/purl-spec) ──
const PURL_TYPE = { npm: 'npm', PyPI: 'pypi', Go: 'golang', 'crates.io': 'cargo', Packagist: 'composer', RubyGems: 'gem', Maven: 'maven', NuGet: 'nuget' };
const enc = (s) => encodeURIComponent(s).replace(/%2F/g, '/');
export function purlOf(p) {
  const type = PURL_TYPE[p.ecosystem];
  if (!type) return null;
  let ns = '', name = p.name;
  if (type === 'npm' && name.startsWith('@')) { [ns, name] = [name.slice(0, name.indexOf('/')), name.slice(name.indexOf('/') + 1)]; }
  else if (type === 'maven') [ns, name] = name.split(':');
  else if (type === 'composer' || type === 'golang') { const k = name.lastIndexOf('/'); if (k > 0) [ns, name] = [name.slice(0, k), name.slice(k + 1)]; }
  else if (type === 'pypi') name = name.toLowerCase().replace(/[-_.]+/g, '-');
  return `pkg:${type}/${ns ? enc(ns) + '/' : ''}${enc(name)}@${enc(p.version)}`;
}

/**
 * CycloneDX 1.5 SBOM (JSON): every pinned dependency found, plus the known vulnerabilities
 * that were looked up, linked to the affected components.
 */
export function cyclonedx({ packages, vulns = [], projectName, toolVersion, ref }) {
  const components = [];
  const seen = new Set();
  for (const p of packages) {
    const purl = purlOf(p);
    const ref_ = purl || `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(ref_)) continue;
    seen.add(ref_);
    const c = { type: 'library', 'bom-ref': ref_, name: p.name, version: p.version };
    if (p.ecosystem === 'Maven') { const [g, a] = p.name.split(':'); c.group = g; c.name = a; }
    else if (p.ecosystem === 'npm' && p.name.startsWith('@')) { c.group = p.name.slice(0, p.name.indexOf('/')); c.name = p.name.slice(p.name.indexOf('/') + 1); }
    if (purl) c.purl = purl;
    c.properties = [{ name: 'codehawk:ecosystem', value: p.ecosystem }, { name: 'codehawk:source', value: p.file }];
    if (p.dev) { c.scope = 'optional'; c.properties.push({ name: 'codehawk:dev', value: 'true' }); }
    components.push(c);
  }
  const vmap = new Map();
  for (const { pkg, adv } of vulns) {
    const ref_ = purlOf(pkg) || `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
    const recommendation = adv.fixed
      ? `Advisory lists ${adv.fixed} as fixed for this affected range. Verify the version you install.`
      : adv.malicious ? 'Remove this package and rotate any credentials on machines that installed it.' : undefined;
    const e = vmap.get(adv.id) || {
      id: adv.id,
      source: { name: 'OSV', url: `https://osv.dev/vulnerability/${encodeURIComponent(adv.id)}` },
      references: adv.aliases.map((id) => ({ id, source: { name: /^CVE-/.test(id) ? 'NVD' : 'OSV', url: /^CVE-/.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${encodeURIComponent(id)}` } })),
      ratings: [adv.cvss?.score != null ? { score: adv.cvss.score, severity: adv.severity, method: 'CVSSv31', vector: adv.cvss.vector } : { severity: adv.severity, method: 'other' }],
      cwes: adv.cwes.map((c) => +c.replace(/\D/g, '')),
      description: adv.summary || undefined,
      recommendation,
      advisories: [{ url: adv.url }],
      published: adv.published || undefined,
      affects: [],
    };
    if (e.recommendation !== recommendation) delete e.recommendation;
    if (!e.affects.some((x) => x.ref === ref_)) e.affects.push({ ref: ref_ });
    vmap.set(adv.id, e);
  }
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'CodeHawk', version: toolVersion }] },
      component: { type: 'application', 'bom-ref': 'root', name: projectName || 'project', ...(ref ? { version: ref.slice(0, 12) } : {}) },
    },
    components,
    dependencies: [{ ref: 'root', dependsOn: components.map((c) => c['bom-ref']) }],
    ...(vmap.size ? { vulnerabilities: [...vmap.values()] } : {}),
  };
}
