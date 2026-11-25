---
description: Apply CodeHawk fixes (security and code quality) — shows every change and asks before editing
argument-hint: "<SEC-001 SEC-004 … | all | critical>"
---
Use the codehawk skill's "Applying fixes" procedure for these findings from the latest CodeHawk report: $ARGUMENTS
(If the argument is "all" use --all. If it names severities, pass exactly those to --severity, comma-separated and nothing added: "critical" is `--severity critical`, "critical high" is `--severity critical,high`. Don't read report.json for this.)
Plan first, show me every change and ask before applying anything. Do not commit, push or merge.
Right after each fix, mark it with `fix.mjs resolve <root> <id> --note "…" --regression "…"` (plus `--siblings`/`--evidence` when its output asks), citing a file:line or test for each. Keep going until every fixed finding shows 4/4, then run `fix.mjs check`. For anything it lists that needs a new edit, show me the diff and wait for my yes before each one, as for the first fixes. Re-`resolve` `!` findings by ID; `+ NEW` lines have no ID, so after fixing one just run `check` again to confirm it cleared.
