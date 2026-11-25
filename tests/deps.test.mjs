import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { summarize } from '../skills/codehawk/scripts/lib/osv.mjs';
import { parseDepFile } from '../skills/codehawk/scripts/lib/deps.mjs';
import { S, run, runEnv, git, repo, readList, cands } from './helpers/fixture.mjs';

const ADV = {
  'GHSA-35jh-r3h4-6jhm': { id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
    database_specific: { cwe_ids: ['CWE-77', 'CWE-94'], severity: 'HIGH' }, affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] },
  'GHSA-29mw-wpgm-hmr9': { id: 'GHSA-29mw-wpgm-hmr9', aliases: ['CVE-2020-28500'], summary: 'ReDoS in lodash', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }],
    affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.17.21' }] }] }] },
  'GHSA-8q59-q68h-6hv4': { id: 'GHSA-8q59-q68h-6hv4', aliases: ['CVE-2020-14343'], summary: 'Arbitrary code execution in PyYAML', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [{ package: { name: 'pyyaml', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '5.4' }] }] }] },
  // The same flaw again under another id: must be merged, not counted twice.
  'PYSEC-2021-142': { id: 'PYSEC-2021-142', aliases: ['CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'], affected: [{ package: { name: 'pyyaml', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '5.4' }] }] }] },
  'MAL-2099-1': { id: 'MAL-2099-1', summary: 'Malicious code in cors (npm)', affected: [{ package: { name: 'cors', ecosystem: 'npm' } }] },
};
const VULNS = { 'npm|lodash': ['GHSA-35jh-r3h4-6jhm', 'GHSA-29mw-wpgm-hmr9'], 'PyPI|PyYAML': ['GHSA-8q59-q68h-6hv4', 'PYSEC-2021-142'], 'npm|cors': ['MAL-2099-1'] };
const defaultResult = (q) => ({ vulns: (VULNS[`${q.package.ecosystem}|${q.package.name}`] || []).map((id) => ({ id })) });
async function mockOsv(result = defaultResult) {
  const bodies = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.method === 'POST' && req.url === '/querybatch') {
        const q = JSON.parse(body); bodies.push(q);
        return res.end(JSON.stringify({ results: q.queries.map(result) }));
      }
      const m = req.url.match(/^\/vulns\/(.+)$/);
      if (m && ADV[decodeURIComponent(m[1])]) return res.end(JSON.stringify(ADV[decodeURIComponent(m[1])]));
      res.statusCode = 404; res.end('{}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, bodies, close: () => server.close() };
}
const depsOf = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'candidates.json'), 'utf8')).deps;

test('dependency CVEs: CVSS severity, fixed version, merged aliases, malicious packages, SBOM', async () => {
  const osv = await mockOsv();
  try {
    const dir = repo();
    run('target.mjs', dir, '--repo');
    const out = await runEnv({ CODEHAWK_OSV_URL: osv.url }, 'scan.mjs', dir);
    assert.equal(out.deps.status, 'ok');
    const d = depsOf(dir);
    assert.equal(d.packages, 8);
    assert.equal(d.vulnerable, 3);
    // Only names, ecosystems and versions are sent: never code.
    for (const q of osv.bodies.flatMap((b) => b.queries)) { assert.deepEqual(Object.keys(q).sort(), ['package', 'version']); assert.deepEqual(Object.keys(q.package).sort(), ['ecosystem', 'name']); }
    const c = cands(dir).filter((x) => x.category === 'vulnerable-dependency');
    const lodash = c.find((x) => x.dep.name === 'lodash');
    assert.equal(lodash.severity, 'high'); // CVSS 7.2
    assert.equal(lodash.cwe, 'CWE-1395');
    assert.equal(lodash.file, 'package-lock.json');
    assert.match(lodash.code, /node_modules\/lodash/);
    assert.equal(lodash.dep.fixTo, '4.17.21');
    assert.deepEqual(lodash.dep.advisories.map((a) => a.cves[0]).sort(), ['CVE-2020-28500', 'CVE-2021-23337']);
    const yaml = c.find((x) => x.dep.name === 'PyYAML');
    assert.equal(yaml.severity, 'critical'); // CVSS 9.8
    assert.equal(yaml.dep.advisories.length, 1, 'GHSA and PYSEC records of one CVE are merged');
    assert.equal(yaml.dep.fixTo, '5.4');
    const cors = c.find((x) => x.dep.name === 'cors');
    assert.equal(cors.rule, 'dep-malicious');
    assert.equal(cors.severity, 'critical');
    assert.equal(cors.cwe, 'CWE-506');
    const sbom = JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'sbom.cdx.json'), 'utf8'));
    assert.equal(sbom.bomFormat, 'CycloneDX');
    assert.equal(sbom.components.length, 8);
    assert.ok(sbom.components.some((x) => x.purl === 'pkg:npm/lodash@4.17.20'));
    assert.ok(sbom.components.some((x) => x.purl === 'pkg:pypi/pyyaml@5.3'));
    const v = sbom.vulnerabilities.find((x) => x.id === 'GHSA-35jh-r3h4-6jhm');
    assert.equal(v.ratings[0].score, 7.2);
    assert.deepEqual(v.affects, [{ ref: 'pkg:npm/lodash@4.17.20' }]);

    // Build: CWE and OWASP are filled in, SARIF carries the taxonomies and the CVSS score.
    fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({
      reviewed: readList(dir),
      findings: [{ title: 'lodash 4.17.20 allows command injection through template()', severity: 'high', category: 'vulnerable-dependency', confidence: 'medium',
        file: lodash.file, line: lodash.line, candidates: [lodash.id], description: 'Known CVEs.', fix: 'Upgrade lodash.' }],
      dismissed: [{ candidates: cands(dir).filter((x) => x.id !== lodash.id).map((x) => x.id), reason: 'checked by hand in this test fixture' }],
    }));
    const b = run('build.mjs', dir);
    const data = JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'report.json'), 'utf8'));
    const f = data.findings[0];
    assert.equal(f.cwe, 'CWE-1395');
    assert.equal(f.owasp, 'A06:2021');
    assert.equal(f.dep.fixTo, '4.17.21');
    assert.equal(data.standards.owasp.find((o) => o.id === 'A06:2021').count, 1);
    const sarif = JSON.parse(fs.readFileSync(b.sarif, 'utf8')).runs[0];
    assert.deepEqual(sarif.taxonomies.map((t) => t.name), ['CWE', 'OWASP Top 10']);
    assert.ok(sarif.taxonomies[0].taxa.some((t) => t.id === '1395'));
    assert.ok(sarif.tool.driver.rules[0].properties.tags.includes('external/cwe/cwe-1395'));
    assert.equal(sarif.results[0].properties['security-severity'], '7.2');
    assert.ok(sarif.results[0].properties.advisories.includes('CVE-2021-23337'));
    assert.deepEqual(sarif.results[0].taxa.map((t) => t.toolComponent.name), ['CWE', 'OWASP Top 10']);
    const md = fs.readFileSync(b.summary, 'utf8');
    assert.match(md, /CVE-2021-23337/);
    assert.match(md, /OWASP Top 10:\*\* A06/);
  } finally { osv.close(); }
});

test('change scans only look up dependency versions the change touched', async () => {
  const osv = await mockOsv();
  try {
    const dir = repo();
    const lock = path.join(dir, 'package-lock.json');
    fs.writeFileSync(lock, fs.readFileSync(lock, 'utf8').replace('"version": "4.17.20"', '"version": "4.17.19"'));
    git(dir, 'commit', '-qam', 'downgrade lodash');
    run('target.mjs', dir, '--commit', 'HEAD');
    await runEnv({ CODEHAWK_OSV_URL: osv.url }, 'scan.mjs', dir);
    const d = depsOf(dir);
    assert.equal(d.scope, 'changed');
    assert.equal(d.checked, 1);
    assert.deepEqual(osv.bodies.flatMap((x) => x.queries).map((q) => `${q.package.name}@${q.version}`), ['lodash@4.17.19']);
    assert.deepEqual(cands(dir).filter((x) => x.dep).map((x) => x.dep.name), ['lodash']);
  } finally { osv.close(); }
});

test('an offline or failed CVE check is reported, never silent', () => {
  const dir = repo();
  run('target.mjs', dir, '--repo');
  run('scan.mjs', dir); // offline in tests
  assert.equal(depsOf(dir).status, 'offline');
  assert.ok(!cands(dir).some((x) => x.dep));
  assert.match(fs.readFileSync(path.join(dir, '.codehawk', 'worksheet.md'), 'utf8'), /Not checked for known vulnerabilities/);
  const sbom = JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'sbom.cdx.json'), 'utf8'));
  assert.equal(sbom.components.length, 8, 'the SBOM is written even offline');
  // A lookup that fails (nothing listening) is an error that reaches the report's notes.
  execFileSync('node', [path.join(S, 'scan.mjs'), dir, '--json'], { encoding: 'utf8', env: { ...process.env, CODEHAWK_OFFLINE: '0', CODEHAWK_OSV_URL: 'http://127.0.0.1:9' } });
  assert.equal(depsOf(dir).status, 'error');
  fs.writeFileSync(path.join(dir, '.codehawk', 'findings.json'), JSON.stringify({ reviewed: readList(dir), findings: [],
    dismissed: [{ candidates: cands(dir).map((x) => x.id), reason: 'checked by hand in this test fixture' }] }));
  run('build.mjs', dir);
  const data = JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'report.json'), 'utf8'));
  assert.ok(data.notes.some((n) => /OSV\.dev\) failed/.test(n)));
});

test('OSV queries the exact installed version and follows only paginated entries', async () => {
  const osv = await mockOsv((q) => {
    if (q.package.name !== 'lodash') return {};
    if (q.version !== '4.17.20') return {};
    const [first, second] = VULNS['npm|lodash'].map((id) => ({ id }));
    return q.page_token ? { vulns: [first, second] } : { vulns: [first], next_page_token: 'more-lodash' };
  });
  try {
    const dir = repo();
    run('target.mjs', dir, '--repo');
    await runEnv({ CODEHAWK_OSV_URL: osv.url }, 'scan.mjs', dir);
    assert.equal(depsOf(dir).vulnerable, 1);
    assert.equal(cands(dir).find((c) => c.dep?.name === 'lodash').dep.advisories.length, 2);
    assert.equal(osv.bodies.length, 2);
    assert.deepEqual(osv.bodies[1].queries, [
      { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20', page_token: 'more-lodash' },
    ]);

    const lock = path.join(dir, 'package-lock.json');
    fs.writeFileSync(lock, fs.readFileSync(lock, 'utf8').replaceAll('4.17.20', '4.17.21'));
    git(dir, 'commit', '-qam', 'update pinned version');
    run('target.mjs', dir, '--repo');
    await runEnv({ CODEHAWK_OSV_URL: osv.url }, 'scan.mjs', dir);
    assert.equal(depsOf(dir).vulnerable, 0);
  } finally { osv.close(); }
});

test('fixed release guidance uses the installed version’s affected interval', () => {
  const pkg = { name: 'example', ecosystem: 'npm' };
  const advisory = { id: 'TEST-1', affected: [{ package: pkg, ranges: [{ type: 'SEMVER', events: [
    { introduced: '1.0.0' }, { fixed: '1.5.0' },
    { introduced: '2.0.0-beta.2' }, { fixed: '2.0.0-beta.12' },
    { introduced: '3.0.0' }, { last_affected: '3.1.0' },
    { introduced: '4.0.0' }, { fixed: '4.1.0' },
  ] }] }] };
  for (const [version, fixed] of [['1.2.0', '1.5.0'], ['2.0.0-beta.10', '2.0.0-beta.12'], ['3.1.0', null]]) {
    assert.equal(summarize(advisory, { ...pkg, version }).fixed, fixed);
  }
});

test('npm aliases use the real registry name and exact pinned version', () => {
  const npmLock = JSON.stringify({ dependencies: { alias: { version: 'npm:@scope/pkg@1.2.3' } } });
  const yarnLock = '"alias@npm:@scope/pkg@^1.2.0":\n  version "1.2.3"\n';
  for (const [name, contents] of [['package-lock.json', npmLock], ['yarn.lock', yarnLock]]) {
    const [pkg] = parseDepFile(name, contents);
    assert.equal(pkg.name, '@scope/pkg');
    assert.equal(pkg.version, '1.2.3');
  }
});

test('change scans keep the changed lockfile occurrence of a repeated package version', async () => {
  const osv = await mockOsv();
  try {
    const dir = repo();
    const lock = path.join(dir, 'package-lock.json');
    const doc = JSON.parse(fs.readFileSync(lock, 'utf8'));
    const nested = 'node_modules/cors/node_modules/lodash';
    doc.packages[nested] = { version: '4.17.19' };
    const write = () => fs.writeFileSync(lock, JSON.stringify(doc, null, 2) + '\n');
    write();
    git(dir, 'commit', '-qam', 'add a nested copy');
    doc.packages[nested].version = '4.17.20';
    write();
    git(dir, 'commit', '-qam', 'change the nested copy');
    run('target.mjs', dir, '--commit', 'HEAD');
    await runEnv({ CODEHAWK_OSV_URL: osv.url }, 'scan.mjs', dir);
    const matches = cands(dir).filter((c) => c.dep?.name === 'lodash');
    assert.equal(matches.length, 1);
    assert.match(matches[0].code, /cors\/node_modules\/lodash/);
    assert.equal(matches[0].dep.version, '4.17.20');
  } finally { osv.close(); }
});
