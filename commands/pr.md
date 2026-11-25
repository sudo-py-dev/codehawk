---
description: Review a pull request (security + code quality) with CodeHawk
argument-hint: "<pr-number-or-url>"
---
Use the codehawk skill to review (security + code quality, with a walkthrough) pull request $ARGUMENTS in the current repository (scope: `--pr <argument>`, passing the argument exactly as given, number or full URL. Never strip a URL down to its number: target.mjs checks that the URL's repository is this checkout's origin and stops if it isn't. If it stops, tell me and don't retry with just the number. If it says the base can't be verified, ask me which branch the PR targets and pass it as `--pr-base`; don't guess the default branch). Follow the skill end to end and finish with the report. If the code is not mine (public repo, fork, other author), warn me about prompt injection before reviewing.
