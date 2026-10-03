# Enterprise CyberTrack

A static, dependency-free tracker for vulnerabilities that threaten enterprises: VPN and edge appliances, identity, email, backup, file transfer, remote management and DevOps platforms. Filter by category, vendor and severity, show only CISA KEV entries, and sort by a risk score (CVSS + KEV + EPSS).

## Run

    python3 -m http.server 8000   # then open http://localhost:8000

## Data

`data/cves.json` ships with a small hand-curated sample (EPSS empty). To load live data:

    NVD_API_KEY=... node scripts/update-data.mjs 30

The script pulls the last N days from NVD, keeps High/Critical CVEs for the vendors listed in `scripts/update-data.mjs`, and adds CISA KEV and EPSS. `.github/workflows/update-data.yml` does this daily; add an `NVD_API_KEY` repo secret for faster runs.
