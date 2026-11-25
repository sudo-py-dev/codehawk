// Shared helpers for CodeHawk scripts. Zero dependencies: Node 18+ only.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const OUT_DIR = '.codehawk';
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const CATEGORIES = {
  injection: 'Injection',
  xss: 'Cross-site scripting',
  secrets: 'Leaked secret',
  crypto: 'Weak cryptography',
  auth: 'Auth & access control',
  deserialization: 'Unsafe deserialization',
  ssrf: 'Server-side request forgery',
  'path-traversal': 'Path traversal',
  dos: 'Denial of service',
  'unsafe-code': 'Unsafe code',
  memory: 'Memory safety',
  config: 'Insecure configuration',
  'supply-chain': 'Supply chain & CI',
  'vulnerable-dependency': 'Vulnerable dependency',
  'info-leak': 'Information exposure',
  logic: 'Logic flaw',
  'prompt-injection': 'Prompt injection / hidden text',
};

// Code-quality categories: the review track that isn't about attackers, but about code that is
// wrong, fragile, slow or hard to maintain.
export const QUALITY_CATEGORIES = {
  bug: 'Likely bug',
  'error-handling': 'Error handling',
  performance: 'Performance',
  concurrency: 'Async & concurrency',
  resources: 'Resource leaks',
  complexity: 'Complexity',
  maintainability: 'Maintainability',
  duplication: 'Duplicated code',
  readability: 'Readability',
  'dead-code': 'Dead & debug code',
  types: 'Type safety',
  testing: 'Tests',
  docs: 'Docs & comments',
  'best-practice': 'Best practice',
};
Object.assign(CATEGORIES, QUALITY_CATEGORIES);
export const kindOf = (category) => (QUALITY_CATEGORIES[category] ? 'quality' : 'security');
// What each severity means on the quality track (reviewer-style levels).
export const QUALITY_LEVEL = { critical: 'Will break', high: 'Likely bug', medium: 'Should fix', low: 'Refactor suggestion', info: 'Nitpick' };

// Something a reader can check: a file:line, a line number, or a test.
export const EVIDENCE = /[\w./-]+\.\w+:\d+|\bline \d+|\btests?\b|\bspec\b/i;

export function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=');
      if (v !== undefined) args[k] = v;
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) args[k] = argv[++i];
      else args[k] = true;
    } else args._.push(a);
  }
  return args;
}

export function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, {
    cwd: opts.cwd,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', opts.quiet === false ? 'inherit' : 'pipe'],
  });
}

export function trySh(cmd, args, opts = {}) {
  try { return sh(cmd, args, opts); } catch { return null; }
}

// Scanned folders are untrusted: a copied (not cloned) .git/config can run commands via
// fsmonitor or hooks. Diffs additionally pass --no-ext-diff --no-textconv (see target.mjs).
const GIT_SAFE = ['--no-pager', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.ext.allow=never'];
export function git(root, ...args) { return sh('git', [...GIT_SAFE, ...args], { cwd: root }); }
export function tryGit(root, ...args) { return trySh('git', [...GIT_SAFE, ...args], { cwd: root }); }

export function isGitRepo(root) {
  return (tryGit(root, 'rev-parse', '--is-inside-work-tree') || '').trim() === 'true';
}

export function outDir(root) {
  const d = path.join(root, OUT_DIR);
  fs.mkdirSync(d, { recursive: true });
  const gi = path.join(d, '.gitignore');
  if (!fs.existsSync(gi)) fs.writeFileSync(gi, '# CodeHawk scan output\n*\n');
  return d;
}

export function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
    if (fallback !== undefined) return fallback;
    throw new Error(`Could not read ${file}: ${e.message}`);
  }
}

export function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

/** Read a file either from the working tree (ref null) or from a git object. */
const blobCache = new Map();
export function readAt(root, ref, rel) {
  const key = `${ref || ''}:${rel}`;
  if (blobCache.has(key)) return blobCache.get(key);
  let text = null;
  try {
    if (ref) text = git(root, 'show', '--no-textconv', `${ref}:${rel}`);
    else {
      const p = path.join(root, rel);
      const real = fs.realpathSync(p), base = fs.realpathSync(root);
      const st = fs.statSync(real);
      if ((real === base || real.startsWith(base + path.sep)) && st.isFile() && st.size <= MAX_BYTES) text = fs.readFileSync(real, 'utf8');
    }
  } catch { text = null; }
  if (text && text.includes('\u0000')) text = null; // binary
  blobCache.set(key, text);
  return text;
}

export const MAX_BYTES = 1_500_000;

const SKIP_DIRS = /(^|\/)(node_modules|vendor|bower_components|\.git|dist|build|out|target|\.next|\.nuxt|coverage|__pycache__|\.venv|venv|\.tox|\.gradle|\.idea|\.vscode|Pods|\.codehawk|\.terraform|third_party)(\/|$)/;
const SKIP_FILES = /(\.min\.(js|css)|\.map|\.lock|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/i;
const BINARY = /\.(png|jpe?g|gif|webp|ico|bmp|tiff?|svg|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|so|dylib|dll|exe|bin|o|a|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|ogg|wav|flac|psd|sketch|fig|db|sqlite3?|parquet|pyc)$/i;

export function isBinaryPath(rel) { return BINARY.test(rel) || /(^|\/)\.git\//.test(rel); }

/** Paths skipped in WHOLE-REPO scans only (vendored, built, lock files). Change scans
 * (PR/commit/branch) never skip them: hiding code in vendor/ or a .min.js is a known trick. */
export function shouldSkip(rel) {
  return SKIP_DIRS.test(rel) || SKIP_FILES.test(rel) || BINARY.test(rel);
}

const LANGS = [
  [/\.(m?js|cjs|jsx)$/i, 'javascript'],
  [/\.(ts|tsx|mts|cts)$/i, 'typescript'],
  [/\.(vue|svelte|astro)$/i, 'javascript'],
  [/\.py$/i, 'python'],
  [/\.go$/i, 'go'],
  [/\.(java|kt|kts|scala|groovy)$/i, 'java'],
  [/\.(cs|cshtml|razor)$/i, 'csharp'],
  [/\.php$/i, 'php'],
  [/\.(rb|erb|rake)$/i, 'ruby'],
  [/\.rs$/i, 'rust'],
  [/\.(c|h|cc|cpp|cxx|hpp|hh|m|mm)$/i, 'c'],
  [/\.swift$/i, 'swift'],
  [/\.(sh|bash|zsh)$/i, 'shell'],
  [/(^|\/)Dockerfile[^/]*$|\.dockerfile$/i, 'docker'],
  [/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i, 'gha'],
  [/\.(ya?ml)$/i, 'yaml'],
  [/\.(tf|hcl)$/i, 'terraform'],
  [/\.(html?|ejs|hbs|handlebars|njk|jinja2?|j2|twig|liquid)$/i, 'html'],
  [/\.sql$/i, 'sql'],
  [/(^|\/)\.env(\.[^/]*)?$/i, 'env'],
  [/\.(json|toml|ini|cfg|conf|properties|xml|plist|gradle)$/i, 'config'],
];
export function langOf(rel) {
  for (const [re, l] of LANGS) if (re.test(rel)) return l;
  return 'text';
}

/** CodeHawk's own version, from the plugin manifest next to the skill. */
let _version;
export function toolVersion() {
  if (_version) return _version;
  try { _version = JSON.parse(fs.readFileSync(new URL('../../../../.claude-plugin/plugin.json', import.meta.url), 'utf8')).version; } catch { _version = '0.0.0'; }
  return _version;
}

export function shortSha(s) { return s ? String(s).slice(0, 7) : ''; }

export function fail(msg, json) {
  if (json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + '\n');
  else process.stderr.write(`codehawk: ${msg}\n`);
  process.exit(1);
}
