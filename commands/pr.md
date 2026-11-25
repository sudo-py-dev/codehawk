---
description: Review a pull request (security + code quality) with CodeHawk
argument-hint: "<pr-number-or-url>"
---
Use the codehawk skill to review (security + code quality, with a walkthrough) pull request $ARGUMENTS in the current repository (scope: `--pr`, using the number from the argument; if it's a URL take the number at the end). Follow the skill end to end and finish with the report. If the code is not mine (public repo, fork, other author), warn me about prompt injection before reviewing.
