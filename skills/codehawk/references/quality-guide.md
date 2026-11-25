# Code-quality review guide

The quality track is the review a strong senior engineer leaves on a PR: specific, actionable, and focused on what will actually bite. It sits next to the security track, not instead of it.

## Levels

Quality findings use the same `severity` field, with these meanings (shown in the report and PR comment):

| severity | Label | Use for |
|---|---|---|
| `critical` | **Will break** | Crashes, data loss or corruption on a normal path; a change that obviously breaks callers |
| `high` | **Likely bug** | Wrong behavior on a realistic input: off-by-one, unawaited promise, wrong comparison, missing null/empty case, race |
| `medium` | **Should fix** | Fragile or costly code: swallowed errors, N+1 queries, blocking I/O on hot paths, leaks, missing input validation |
| `low` | **Refactor suggestion** | Maintainability: long/complex functions, duplication, confusing names, deep nesting, missing tests for new logic |
| `info` | **Nitpick** | Style and polish: naming, small readability wins, stray TODOs/debug lines, idioms. Never more than ~10 per review. |

`confidence` works as for security: `high` when you traced it, `low` when it depends on things you couldn't see.

## What to look for

**Correctness first — read the change as a test author would.**
- Edge cases: empty lists, `null`/`undefined`/`None`, zero, negative numbers, very large inputs, Unicode, time zones, leap years.
- Off-by-one in loops, slices, pagination; inclusive vs exclusive ranges.
- Async: unawaited promises (`forEach(async …)`), missing `await`, fire-and-forget without error handling, shared mutable state across requests, check-then-act races.
- Wrong operator or comparison: `=` vs `==`, `==` vs `===`, `is` vs `==`, string `==` in Java, NaN comparisons, integer division, float equality.
- Changed contracts: a function now returns a different shape, throws where it didn't, or a renamed field/route that callers (or old clients) still use.
- Copy-paste mistakes: duplicated branch bodies, wrong variable in the second copy.

**Regressions — what the change breaks (the most-missed class of bug).** On every change review:
- **Read the old code, not just the new.** For each replaced or removed block (worksheet section 1c), list the inputs it handled, then check the new code still handles each one. A fix that closes one hole often drops a case the old code got right.
- **Name the counterexample.** A regression finding states one concrete input and its result before and after: "for `{\rtf1\uc0\u945\'42}` the old parser returns `αB`, the new one `α`". If you can't name one, it's a question, not a finding.
- **Sibling paths.** When the change fixes or hardens one path (DOCX but not ODF, one route but not its twin, Linux but not Windows), find the parallel code and check it got the same fix *in the same order*. Inconsistency between siblings is a strong signal.
- **Limits before work.** A size, depth or copy budget must be checked *before* building, copying or allocating, against what's left of the budget, not after the data already exists. Watch nested and recursive input, where each level can spend the whole budget again.
- **Every token form, alone and mixed.** Where a parser branches on the next input (after an escape, a prefix, a delimiter), list every form the grammar allows there and trace each, then a mix: RTF after `\uN` can be followed by a plain character, `\'hh`, an escaped symbol (`\\ \{ \}`), a control word or a group brace. A branch that handles one form and gives up on the rest is the usual bug; a fix for one form usually needs the others too.
- **Half-applied fixes.** When the change adjusts a setting or list in one call site, search for every other site that sets it (`allowlist-inconsistent` lists them). If one site runs before another (a probe before a conversion, validation before use), the stricter one decides, and the fix has no effect.
- **Formats and specs.** Parsers and writers for standard formats (RTF, ODF/OOXML, CSV, JSON, HTTP, URLs, archives, media containers) follow rules that depend on state: count prefixes, escape widths, modes such as RTF `\ucN`, encodings, optional fields. Check the change against the spec, not against the one sample in the test. If a docs tool is available, look the rule up.
- **Tool flags and allow-lists.** When code restricts what an external tool or library may do (FFmpeg `-protocol_whitelist`, curl protocols, XML entity settings, CORS origins, file-type lists), list what legitimate inputs need: sub-resources the tool opens by itself (HLS segments over `crypto:`, `concat:`, `data:`), encrypted or nested variants. Too narrow is a regression; too wide is a hole.
- **Tests that only prove the happy path.** If the new test covers the case the author had in mind, ask which input it doesn't cover, and suggest that test.

**Error handling.**
- Swallowed errors (`catch {}` / `except: pass`), errors logged but execution continues in a bad state, generic catch-alls hiding real failures.
- Missing cleanup on failure paths (files, locks, transactions, timers, subscriptions).
- User-facing failures that leak internals or give no way to recover.

**Performance — only where it matters.**
- N+1 queries and network calls inside loops; sequential awaits that could run concurrently.
- Blocking/sync I/O or CPU-heavy work on request paths; unbounded in-memory loads; missing pagination.
- Quadratic work on collections that can be large (nested `find`/`includes` in loops).
- Re-renders/recomputation in UI code from unstable props, missing memoization on hot paths.

**Maintainability & readability.**
- Functions doing several things; long parameter lists; boolean flag arguments; deep nesting (suggest guard clauses).
- Duplicated logic that should live in one helper (and will drift).
- Names that don't say what a thing is or does; magic numbers/strings that deserve a constant.
- Dead code, commented-out code, debug prints, stale TODOs.
- Types: `any`, unchecked casts, ignored type errors.

**Tests & docs.**
- New logic or a bug fix without a test proving it; tests that can't fail; tests asserting implementation details.
- Public API, config or behavior changes without docs/changelog updates.

## Writing quality comments

- **Be concrete.** Name the input that breaks it, or the cost ("one query per order: 500 orders = 501 queries").
- **Suggest, don't lecture.** Put the improved code in `fixCode` whenever a local edit does it. For refactors too large for a patch, describe the shape in `fix` (which function to extract, what it takes and returns).
- **One finding per root cause.** Five similar lines → one finding listing the places.
- **Respect the codebase.** Match its style, libraries and conventions; don't push a personal preference as a finding. If the project clearly prefers a pattern, it's not a nitpick to use it.
- **Diffs first.** On PR/commit reviews, comment on changed lines and what they affect. Pre-existing issues only when the change makes them worse or touches them directly.
- **Signal over volume.** A great review has a handful of high-value comments. Dismiss rule hits that are idiomatic or harmless, in groups, with a short reason.

## Walkthrough (change reviews)

For PR/commit/branch scans, write a `walkthrough`:
- `summary`: 2–4 sentences on what the change does and why it matters, in plain language.
- `changes`: group related files and say what changed in each group (one row per cohesive change, not per file if many files change together).
- `effort`: 1–5, how hard this is to review (1 = trivial, 5 = large, risky, cross-cutting).
