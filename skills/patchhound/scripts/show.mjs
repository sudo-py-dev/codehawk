#!/usr/bin/env node
// Read-only viewer for the reviewer: prints a file as the scan saw it, or its diff in the
// scanned change. SKILL.md pre-approves this instead of raw `git show/diff/log`, which accept
// --output=<file> and so can write anywhere without a permission prompt.
//
//   node show.mjs <root> <path> [--from <line>] [--to <line>]
//   node show.mjs <root> --diff <path>
import path from 'node:path';
import { parseArgs, OUT_DIR, readJson, readAt, tryGit, fail } from './lib/common.mjs';

const args = parseArgs(process.argv.slice(2));
const root = path.resolve(args._[0] || '.');
const scope = readJson(path.join(root, OUT_DIR, 'scope.json'), null);
if (!scope) fail('No scope yet. Run target.mjs first.');
const SHA = /^[0-9a-f]{7,40}$/i;
const diff = typeof args.diff === 'string';
const rel = String(diff ? args.diff : args._[1] || '');
if (!rel || rel.startsWith('-') || path.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) fail(`Give a path inside the repo, e.g. src/app.js (got "${rel}").`);

if (diff) {
  if (!scope.base) fail('This scope has no base to diff against (whole-repo scan). Show the file instead.');
  if (!SHA.test(scope.base) || (scope.ref && !SHA.test(scope.ref))) fail('scope.json has an unexpected base/ref. Re-run target.mjs.');
  const range = scope.ref ? [scope.base, scope.ref] : [scope.base];
  const out = tryGit(root, 'diff', '--no-color', '--no-ext-diff', '--no-textconv', ...range, '--', rel);
  if (out == null) fail(`git diff failed for ${rel}.`);
  process.stdout.write(out || `(no changes to ${rel} in this scope)\n`);
} else {
  const text = readAt(root, scope.ref, rel);
  if (text == null) fail(`Can't read ${rel}${scope.ref ? ` at ${scope.ref.slice(0, 7)}` : ''} (missing, binary, too large, or outside the repo).`);
  const lines = text.split(/\r?\n/);
  const from = Math.max(1, +args.from || 1), to = Math.min(lines.length, +args.to || lines.length);
  const w = String(to).length;
  for (let i = from; i <= to; i++) process.stdout.write(`${String(i).padStart(w)}  ${lines[i - 1]}\n`);
}
