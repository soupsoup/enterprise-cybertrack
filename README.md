# Enterprise CyberTrack

A static, dependency-free tracker for vulnerabilities that threaten enterprises: VPN and edge appliances, identity, email, backup, file transfer, remote management and DevOps platforms. Filter by category, vendor and severity, show only CISA KEV entries, and sort by a risk score (CVSS + KEV + EPSS).

## Run

    python3 -m http.server 8000   # then open http://localhost:8000

## Data

`data/cves.json` ships with a small hand-curated sample (EPSS empty). To load live data:

    NVD_API_KEY=... node scripts/update-data.mjs 30

The script pulls the last N days from NVD, keeps High/Critical CVEs for the vendors listed in `scripts/update-data.mjs`, and adds CISA KEV and EPSS. `.github/workflows/update-data.yml` does this daily; add an `NVD_API_KEY` repo secret for faster runs.

## Am I affected?

Pick a vendor, product and version to list the loaded CVEs that apply, with the version that fixes each. It uses the affected version ranges NVD publishes (`affects` in `data/cves.json`), and `version.js` does the matching (`npm test` runs its tests). Windows is left out because its versions are part of the product name. Only the CVEs in the data file are checked, so a longer history (`node scripts/update-data.mjs 365`) makes it more useful.

In a sandbox that routes traffic through a proxy, run the update script with `NODE_USE_ENV_PROXY=1`.

## Vendor news

`news.html` lists recent posts and advisories from leading security companies, sortable by company, type and date. `data/companies.json` holds each company's candidate feed URLs plus a page to auto-discover the feed from. `node scripts/update-news.mjs` fetches them into `data/news.json` (a feed that fails keeps its old items and shows as "Failed" under Feed status). `npm test` covers the feed parser.
