# Example output

This is a saved review of the deliberately vulnerable app in [the test fixtures](../../tests/fixtures/vuln-app). The review includes planted prompt-injection text. The demo uses the saved [review snapshot](snapshot.json) and [SARIF](report.sarif), so refreshing the UI needs neither a new scan nor a network connection.

From the repository root, run `npm run example` to refresh [the interactive report](report.html) and [the review summary](summary.md). Run `npm run check:example` to check for drift without changing files.

When the report layout changes, open `report.html?still&theme=light` and `report.html?still&theme=dark` in a browser. Refresh the overview, finding detail, and walkthrough screenshots in [the docs assets](../assets/). Open **Supporting analysis** before capturing the walkthrough.
