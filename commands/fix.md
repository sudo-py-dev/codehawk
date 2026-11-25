---
description: Apply CodeHawk fixes (security and code quality) — shows every change and asks before editing
argument-hint: "<SEC-001 SEC-004 … | all | critical>"
---
Use the codehawk skill's "Applying fixes" procedure for these findings from the latest CodeHawk report: $ARGUMENTS
(If the argument is "all" use --all; if it names a severity, pick the finding ids with that severity from .codehawk/report.json.)
Plan first, show me every change and ask before applying anything. Do not commit, push or merge.
