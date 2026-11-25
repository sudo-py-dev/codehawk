---
description: Full security audit of the repository (optionally at a commit/tag) with PatchHound
argument-hint: "[--at <sha-or-tag>] [path]"
---
Use the patchhound skill to audit the whole repository (scope: `--repo`, plus `--at` if given). Arguments: $ARGUMENTS. Follow the skill end to end and finish with the report. If the code is not mine (public repo, fork, other author), warn me about prompt injection before reviewing.
