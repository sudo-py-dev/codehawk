// Structural code-quality checks: things a single-line regex can't see.
// Deliberately simple and language-agnostic (brace counting / indentation), so they're fast and
// dependency-free. They produce candidates; the reviewer decides which deserve a comment.

const BRACE_LANGS = new Set(['javascript', 'typescript', 'go', 'java', 'csharp', 'c', 'rust', 'php', 'swift']);
const CONTROL = /^\s*(if|for|while|switch|catch|else|do|try|return|with|using|lock|foreach|unless|until)\b/;
const FN_START = {
  brace: /^\s*(export\s+)?(default\s+)?(async\s+)?function\b|^\s*(?:(?:public|private|protected|internal|static|final|async|override|virtual|abstract|synchronized|readonly|export|default|pub(?:\(\w+\))?|unsafe|extern)\s+)*(?:[\w$<>\[\],.?*&: ]+\s+)?[\w$]+\s*\([^;]*\)\s*(?::\s*[^{=;]+|->\s*[^{=;]+|throws\s+[\w., ]+)?\s*\{\s*$|=>\s*\{\s*$|^\s*func\b|^\s*(pub\s+)?(async\s+)?fn\s+\w+/,
  python: /^(\s*)(async\s+)?def\s+\w+/,
};
const LOOP_START = /^\s*(for|while)\b|\.(forEach|map|flatMap|filter|reduce|each|times)\(\s*(async\s*)?(\(|[\w$]+\s*=>|function|do\b|\|)/;
const BRANCH = /\b(if|elif|else\s+if|for|while|case|catch|except|when)\b|&&|\|\||\?\?|(?<![?.])\?(?![.?:])/g;
const DATA_CALL = /(\bdb|\bpool|\bconn(?:ection)?|\bclient|\bprisma\.\w+|\bknex|\bsequelize|\bmodel|\brepo(?:sitory)?|\bsession|\b[A-Z]\w+)\.(query|execute|find\w*|select|insert|update|upsert|delete|destroy|save|create|where|count|aggregate|get)\(|\bcursor\.execute\(|\.objects\.(get|filter|all|create)\(|\brequests\.(get|post|put|patch|delete)\(|\bfetch\(|\baxios(\.\w+)?\(|\bhttp\.(Get|Post)\(|\bhttpx\.\w+\(/;

const stripCode = (l) => l.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""').replace(/\/\/.*$/, '').replace(/#.*$/, '');
const indentOf = (l) => (l.match(/^\s*/)[0].replace(/\t/g, '    ').length);

/** Find the last line of a block that starts on line i (0-based). */
function blockEnd(lines, i, lang) {
  if (BRACE_LANGS.has(lang)) {
    // Brace-less body: `for (…) stmt;` on one line, or the statement on the next line.
    if (!stripCode(lines[i]).includes('{')) {
      const next = (lines[i + 1] || '').trim();
      if (!next.startsWith('{')) return /[;)]\s*$/.test(stripCode(lines[i]).trim()) && !/\)\s*$/.test(stripCode(lines[i]).trim()) ? i : Math.min(i + 1, lines.length - 1);
    }
    let depth = 0, opened = false;
    for (let k = i; k < lines.length && k < i + 3000; k++) {
      const s = stripCode(lines[k]);
      for (const ch of s) { if (ch === '{') { depth++; opened = true; } else if (ch === '}') depth--; }
      if (opened && depth <= 0) return k;
    }
    return Math.min(lines.length - 1, i + 3000);
  }
  // indentation languages (python, ruby-ish, yaml)
  const base = indentOf(lines[i]);
  let last = i;
  for (let k = i + 1; k < lines.length; k++) {
    if (!lines[k].trim()) continue;
    if (indentOf(lines[k]) <= base) break;
    last = k;
  }
  return last;
}

const overlaps = (a, b, ranges) => !ranges || ranges.some(([s, e]) => a <= e && b >= s);

/**
 * @returns candidate-like objects: { rule, title, severity, category, line, endLine, code, hint }
 */
export function structure(lines, lang, changed, { mode } = {}) {
  const out = [];
  const isBrace = BRACE_LANGS.has(lang);
  const fnRe = isBrace ? FN_START.brace : lang === 'python' ? FN_START.python : null;

  if (fnRe) {
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (!fnRe.test(l) || CONTROL.test(l) || l.length > 400) continue;
      const end = blockEnd(lines, i, lang);
      const len = end - i + 1;
      if (len < 8) continue;
      if (!overlaps(i + 1, end + 1, changed)) continue;
      const name = (l.match(/(?:function\s+|def\s+|func\s+(?:\([^)]*\)\s*)?|fn\s+)?([\w$]+)\s*\(/) || [])[1] || 'function';
      let complexity = 1, maxDepth = 0, deepLine = i;
      const baseIndent = indentOf(l);
      let depth = 0;
      for (let k = i; k <= end; k++) {
        const s = stripCode(lines[k]);
        complexity += (s.match(BRANCH) || []).length;
        if (isBrace) {
          for (const ch of s) { if (ch === '{') { depth++; if (depth - 1 > maxDepth) { maxDepth = depth - 1; deepLine = k; } } else if (ch === '}') depth--; }
        } else if (lines[k].trim()) {
          const d = Math.floor((indentOf(lines[k]) - baseIndent) / 4) - 1;
          if (d > maxDepth) { maxDepth = d; deepLine = k; }
        }
      }
      const code = l.trim().slice(0, 220);
      if (len > 80) out.push({ rule: 'long-function', title: `Long function: ${name} (${len} lines)`, severity: len > 150 ? 'medium' : 'low', category: 'maintainability', line: i + 1, endLine: end + 1, code,
        hint: 'Hard to read, test and change safely. Does it do more than one thing? Suggest the concrete pieces to extract.' });
      if (complexity > 15) out.push({ rule: 'complex-function', title: `High complexity: ${name} (~${complexity} branches)`, severity: complexity > 30 ? 'medium' : 'low', category: 'complexity', line: i + 1, endLine: end + 1, code,
        hint: 'Many paths means many untested cases. Early returns, lookup tables or smaller helpers usually help.' });
      if (maxDepth > 4) out.push({ rule: 'deep-nesting', title: `Deeply nested code in ${name} (${maxDepth} levels)`, severity: 'low', category: 'readability', line: deepLine + 1, endLine: deepLine + 1, code: lines[deepLine].trim().slice(0, 220),
        hint: 'Guard clauses / early returns and extracting the inner block flatten this.' });
    }
  }

  // Loops doing I/O per iteration (N+1) or awaiting sequentially.
  const reported = new Set();
  for (let i = 0; i < lines.length; i++) {
    if (!LOOP_START.test(lines[i]) || lines[i].length > 400) continue;
    const end = blockEnd(lines, i, lang);
    for (let k = i + 1; k <= end; k++) {
      if (reported.has(k)) continue;
      const s = stripCode(lines[k]);
      if (DATA_CALL.test(s)) {
        if (overlaps(k + 1, k + 1, changed) || overlaps(i + 1, i + 1, changed)) {
          out.push({ rule: 'query-in-loop', title: 'Database / network call inside a loop (N+1)', severity: 'medium', category: 'performance', line: k + 1, endLine: k + 1, code: lines[k].trim().slice(0, 220),
            hint: `One round-trip per item (loop starts at line ${i + 1}). Batch it (WHERE id IN …, bulk insert, Promise.all with a concurrency limit) or move it out of the loop.` });
        }
        reported.add(k);
        break;
      }
      if (/\bawait\b/.test(s) && (lang === 'javascript' || lang === 'typescript' || lang === 'python')) {
        if (overlaps(k + 1, k + 1, changed)) out.push({ rule: 'await-in-loop', title: 'Sequential await inside a loop', severity: 'low', category: 'concurrency', line: k + 1, endLine: k + 1, code: lines[k].trim().slice(0, 220),
          hint: 'Each iteration waits for the previous one. If the calls are independent, run them concurrently (Promise.all / asyncio.gather) with a limit.' });
        reported.add(k);
        break;
      }
    }
  }

  if (lines.length > 800 && (mode === 'repo' || !changed)) out.push({ rule: 'large-file', title: `Large file (${lines.length} lines)`, severity: 'info', category: 'maintainability', line: 1, endLine: 1, code: (lines[0] || '').trim().slice(0, 220),
    hint: 'Big files usually mix responsibilities. Only worth a comment if it is hard to navigate or keeps growing.' });
  return out;
}

/**
 * Find blocks of >= `min` significant lines that appear in two places.
 * files: [{ path, lines, changed }] — returns candidates placed on the later occurrence.
 */
export function duplicates(files, { min = 6, max = 25 } = {}) {
  const sig = (l) => {
    const t = l.trim().replace(/\s+/g, ' ');
    if (t.length < 12) return null;
    if (/^(import|from|using|#include|package|require\(|export \{|\}|\)|\]|\/\/|#|\*|<\/)/.test(t)) return null;
    return t;
  };
  const seen = new Map();
  const out = [];
  for (const f of files) {
    const rows = [];
    f.lines.forEach((l, i) => { const s = sig(l); if (s) rows.push({ s, n: i + 1 }); });
    let skipUntil = -1;
    for (let r = 0; r + min <= rows.length; r++) {
      const key = rows.slice(r, r + min).map((x) => x.s).join('\n');
      const here = { path: f.path, start: rows[r].n, end: rows[r + min - 1].n };
      const prev = seen.get(key);
      if (!prev) { seen.set(key, here); continue; }
      if (prev.path === here.path && prev.end >= here.start) continue; // overlapping window, same place
      if (here.start <= skipUntil) continue;
      // Extend the match as far as it goes.
      let len = min;
      const prevFile = files.find((x) => x.path === prev.path);
      const prevRows = [];
      prevFile.lines.forEach((l, i) => { const s = sig(l); if (s) prevRows.push({ s, n: i + 1 }); });
      const p0 = prevRows.findIndex((x) => x.n === prev.start);
      while (r + len < rows.length && p0 + len < prevRows.length && rows[r + len].s === prevRows[p0 + len].s && !(prev.path === here.path && prevRows[p0 + len].n >= here.start)) len++;
      const endLine = rows[r + len - 1].n;
      skipUntil = endLine;
      if (!overlaps(here.start, endLine, f.changed)) continue;
      out.push({ rule: 'duplicate-block', title: `Duplicated block (${len} lines, also in ${prev.path.split('/').pop()}:${prev.start})`, severity: len >= 15 ? 'medium' : 'low', category: 'duplication',
        file: f.path, line: here.start, endLine, code: rows[r].s.slice(0, 220),
        hint: `Same ${len} lines as ${prev.path}:${prev.start}. Extract a shared helper so fixes land in one place.` });
      if (out.length >= max) return out;
    }
  }
  return out;
}
