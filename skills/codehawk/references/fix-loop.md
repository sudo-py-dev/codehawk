# Apply and verify fixes

Use the latest CodeHawk report for the selected checkout. Use `fix.mjs status <root>` to inspect findings or resume the cycle.

1. **Plan.** Run `fix.mjs plan <root> SEC-001 SEC-003`, `--all`, or `--severity critical,high` using the exact selection the user requested. Report the checkout warnings, planned diffs and findings that need manual work. Planning writes `.codehawk/fix-plan.json`.
2. **Approve.** Get approval for the exact source changes shown. If the user chooses a subset, re-plan with those IDs and compare the new plan with the approved one. Get fresh approval if any patch differs or a previously blocked patch becomes ready. For manual, missing, drifted or conflicting patches, prepare and show the proposed diff before editing.
3. **Apply.** Run `fix.mjs apply <root> --token <token>` with the token from the approved plan. Apply changes the working tree and records initial checks for each patch. If apply reports that the source changed, re-plan. If it reports that source edits succeeded but report publication failed, follow the recovery command it prints.
4. **Resolve.** Review the changed code in context. Check that previously supported inputs still work and trace sibling paths for the same issue. Run project tests only for trusted code with the user's authorization. Record the result per finding:

   ```bash
   node /absolute/path/to/codehawk/scripts/fix.mjs resolve . SEC-001 \
     --regression "Empty and wildcard searches still work through src/server.js:31"
   ```

   | Check | How to satisfy it |
   |---|---|
   | Code changed | The script compares against the scan. Use `--changed path:line` when the fix landed elsewhere. |
   | Problem gone | The script reruns the original rule. Use `--evidence` for a finding with no rule or to explain why a remaining match is safe. |
   | Fixed everywhere | The script searches for matches of the same rule. Use `--siblings` to explain remaining matches, incomplete coverage, or the sibling paths you reviewed for a finding with no rule. |
   | No regression | Use `--regression` to identify the behavior preserved and the code or test that supports it. |

   Evidence must reference an existing repository file and line or a test file. Unchecked steps remain visible in the report. Use `fix.mjs reopen <root> <id>` to clear a resolution when needed.
5. **Check.** Run `fix.mjs check <root>` after the last fix. Address `!` by reviewing the missing check and resolving the finding again. Review `+ NEW` as a candidate on changed lines. Follow the approval step for any additional source edit, then rerun `check`. Stop when checks are complete or the remaining work has been recorded and the user has declined or deferred it.
6. **Summarize.** Report the working-tree changes, final verification counts and remaining findings or dismissed candidates from `check`. Committing, pushing and posting each require separate authorization.
