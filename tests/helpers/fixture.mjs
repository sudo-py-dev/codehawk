import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('../', import.meta.url));
export const S = path.join(here, '..', 'skills', 'codehawk', 'scripts');
// Tests never reach the real OSV.dev: offline by default, or a local mock (see mockOsv).
export const OFFLINE = { ...process.env, CODEHAWK_OFFLINE: '1' };
export const run = (script, ...args) => JSON.parse(execFileSync('node', [path.join(S, script), ...args, '--json'], { encoding: 'utf8', env: OFFLINE }));
export const runEnv = async (env, script, ...args) => JSON.parse((await promisify(execFile)('node', [path.join(S, script), ...args, '--json'], { encoding: 'utf8', env: { ...process.env, CODEHAWK_OFFLINE: '0', ...env } })).stdout);
export const runFail = (script, ...args) => {
  try { execFileSync('node', [path.join(S, script), ...args, '--json'], { encoding: 'utf8', stdio: 'pipe', env: OFFLINE }); } catch (e) { return JSON.parse(e.stdout); }
  throw new Error('expected failure');
};
export const git = (cwd, ...a) => execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', ...a], { cwd, encoding: 'utf8' });

export function repo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-'));
  fs.cpSync(path.join(here, 'fixtures', 'vuln-app'), dir, { recursive: true });
  git(dir, 'init', '-q'); git(dir, 'add', '-A'); git(dir, 'commit', '-qm', 'initial');
  return dir;
}
export const readList = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'candidates.json'), 'utf8')).readList.map((r) => r.path);
export const cands = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.codehawk', 'candidates.json'), 'utf8')).candidates;
