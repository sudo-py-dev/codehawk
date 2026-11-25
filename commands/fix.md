---
description: Apply CodeHawk fixes (security and code quality) — shows every change and asks before editing
argument-hint: "<SEC-001 SEC-004 … | all | critical>"
---
Use the codehawk skill's "Applying fixes" procedure for these findings from the latest CodeHawk report: $ARGUMENTS
(If the argument is "all" use --all; if it names severities, use --severity critical,high. Don't read report.json for this.)
Plan first, show me every change and ask before applying anything. Do not commit, push or merge.
Right after each fix, mark it with `fix.mjs resolve <root> <id> --note "…" --regression "…"` (plus `--siblings`/`--evidence` when its output asks), citing a file:line or test for each. Keep going until every fixed finding shows 4/4, then run `fix.mjs check` and handle anything it lists.
