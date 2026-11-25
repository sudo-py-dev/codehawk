---
description: Review your branch and uncommitted work for security and code quality before opening a PR
argument-hint: "[base-branch]"
---
Use the codehawk skill to review (security + code quality, with a walkthrough) the current branch against "$ARGUMENTS" (scope: `--base`, with the branch name if given; if empty, use `--base` alone for the default branch). Follow the skill end to end and finish with the report. If the code is not mine (public repo, fork, other author), warn me about prompt injection before reviewing.
