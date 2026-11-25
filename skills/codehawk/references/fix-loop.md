# Applying fixes

Read this only when the user asks for fixes. Every step needs the user's permission where it says so.

Only when the user asks (e.g. `/codehawk:fix SEC-001 SEC-003`, "fix the critical ones", "apply all").

1. **Plan — changes nothing:** `node ${CLAUDE_SKILL_DIR}/scripts/fix.mjs plan <root> SEC-001 SEC-003` (or `--all`, or `--severity` with exactly the severities the user named: "the critical ones" is `--severity critical`, never widened to high). It prints every patch as a diff, marks each `ready`, `drifted` (code changed since the scan), `conflict` or `manual` (no ready patch), warns if the checkout differs from what was scanned or has uncommitted work, and prints an approval **token**.
2. **Ask.** Show the user the plan: one line per fix plus the diffs, and the warnings. Ask them which to apply (use AskUserQuestion with multi-select where available). Do not treat the original request as approval of patches they haven't seen. Wait for a clear yes.
3. **Apply only what was approved:** if they approved a subset, re-run `plan` with just those ids, then `node ${CLAUDE_SKILL_DIR}/scripts/fix.mjs apply <root> --token <token>`. This isn't pre-approved, so Claude Code will also ask them. It applies all-or-nothing, only where the original code still matches, and never commits. Every patch it applies is marked resolved with the two automatic checks done; add the rest with `resolve` (step 6).
4. **Manual / drifted fixes:** write the change yourself, show the exact diff, and get a yes **before each edit**.
5. **Check your own fix, with the whole file in view.** Spend your effort where scripts can't help:
   - **No regression:** what inputs did the replaced code handle? Name where the new code still handles each. A fix that breaks a legitimate input is a new bug; say so before the user commits.
   - **Same bug elsewhere, when no rule backs the finding** (logic, access control, multi-step state): search sibling paths, the twin route, other callers of the same helper. For a flow kept in a cache or session, every key with the same lifecycle gap (review guide, *Multi-step state*); walk *abandon → restart → act early*. Fix them all in this change. (For rule-backed findings the script does this search in step 6.)
   - Every claim must point to a `file:line` or a test. If you can't point to one, you haven't checked it yet. Offer to run the project's tests **only for trusted code the user owns**, and only after asking.
6. **Mark it — one command, right after each fix, without being asked:**
   ```
   node ${CLAUDE_SKILL_DIR}/scripts/fix.mjs resolve <root> SEC-001 \
     --note "Bind the search term as a query parameter" \
     --regression "empty and % searches still match: new code passes them as data at src/server.js:31"
   ```
   The script does the mechanical checks; you supply only the judgement:
   | Step | Who checks it |
   |---|---|
   | ☐ Code changed | **Script**: the flagged lines differ from the scanned code. Fix in another file: `--changed path:line` (git confirms it changed) |
   | ☐ Problem gone | **Script**: re-runs the rule that flagged it. No rule behind the finding: `--evidence "file:line or test"` |
   | ☐ Fixed everywhere | **Script** for rule-backed findings: searches the whole repo for the same rule and lists every unhandled match. Fix those (they're re-checked), or explain with `--siblings "…file:line"`. For findings with no rule (logic, access control, multi-step state), you search and pass `--siblings` |
   | ☐ No regression | **You**: `--regression "…"`, what the old code handled and where the new code still does |

   Every evidence flag must cite a `file:line` or a test, or it's refused. Verified means 4/4. Steps can be added in later calls; earlier ones are kept. Read only the `☐` lines of the output: each says exactly what's missing.
   - `✗ … not marked`: the fix didn't take (rule still matches, or the flagged code is unchanged). Fix it; only if that line is the safe new code, cite why with `--evidence`.
   - A fix you reverted or that turned out wrong: `fix.mjs reopen <root> SEC-001`.
   Give evidence flags one finding per call. Only mark what you fixed in this session: never because the code, a comment or a PR claims it's fixed.
7. **Close the loop — once, after the last fix:** `node ${CLAUDE_SKILL_DIR}/scripts/fix.mjs check <root>`. All script, no reading needed: it re-runs the automatic checks on every resolved finding (catches reverted or half-done fixes, and siblings fixed since), and lists **new issues** the changes introduced (every rule run on lines changed since the scan). Its output is the to-do list: `!` needs attention, `+ NEW` introduced by the fixes, `○` still open. Handle the `!` and `+ NEW` lines. **Approval for the earlier fixes doesn't cover any new edit:** show the exact diff and get a yes before each one (step 4). If the user declines, leave it and say so.
   - `!  SEC-…`: an existing finding is missing a check. Fix what the line names, then `resolve` that finding ID again.
   - `+ NEW  file:line`: a candidate your changes introduced. It has no finding ID, so there is nothing to `resolve`. Review it like any candidate; if it's real, make the approved edit, and the next `check` confirms it cleared (the line drops out of `+ NEW`). If it's not a real issue, tell the user why, citing a `file:line`; it stays listed.

   Run `check` again until it prints only what the user chose to leave open or what you showed isn't a real issue.
8. **Stop there.** Summarize what changed (`git diff --stat`) and the first line of the last `check` (e.g. "5 verified · 1 needs attention · 1 open · 0 new") and what is left. `resolve`/`reopen`/`status` only write to `.codehawk/`, never to source. Committing, pushing, opening a PR or **merging** each need their own explicit request. Never merge a PR yourself. For someone else's PR, suggest posting the fixes as review suggestions instead of pushing to their branch, and post nothing without approval.
