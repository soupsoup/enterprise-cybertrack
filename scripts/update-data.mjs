// Refreshes data/cves.json from NVD, CISA KEV and FIRST EPSS.
// Usage: node scripts/update-data.mjs [days=30]   (set NVD_API_KEY for higher rate limits)
import { readFile, writeFile } from 'node:fs/promises';

const DAYS = Number(process.argv.find((a) => /^\d+$/.test(a)) || 30);
const OUT = new URL('../data/cves.json', import.meta.url);
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// CPE vendor -> display name. Only vendors listed here are tracked.
const VENDORS = {
  microsoft: 'Microsoft', cisco: 'Cisco', fortinet: 'Fortinet', paloaltonetworks: 'Palo Alto Networks',
  ivanti: 'Ivanti', citrix: 'Citrix', vmware: 'VMware', broadcom: 'Broadcom', f5: 'F5', sonicwall: 'SonicWall',
  juniper: 'Juniper', checkpoint: 'Check Point', atlassian: 'Atlassian', progress: 'Progress', veeam: 'Veeam',
  sap: 'SAP', oracle: 'Oracle', jetbrains: 'JetBrains', connectwise: 'ConnectWise', gitlab: 'GitLab',
  barracuda: 'Barracuda', zyxel: 'Zyxel', apache: 'Apache', netapp: 'NetApp', okta: 'Okta', crowdstrike: 'CrowdStrike',
};

// First matching rule wins; checked against "vendor product" lowercased (vendor is the display name).
const CATEGORY_RULES = [
  [/spring cloud|msal|diagnostics\.runtime|neethi|wss4j|opennlp|freemarker|\bant\b|parquet|intellij|\.net|visual studio|apache-airflow-providers/, 'Developer Tools & Libraries'],
  [/asyncos|secure email|exchange|outlook|sharepoint|confluence|skype|teams|email|mail/, 'Email & Collaboration'],
  [/vpn|gateway|netscaler|globalprotect|forti(os|gate|proxy|web|manager)|connect secure|policy secure|\basa\b|firepower|sonicos|big-ip|\badc\b|pan-os|check point|gaia/, 'Edge / VPN'],
  [/active directory|entra|okta|ldap|kerberos|print spooler|netlogon|adfs|access manager|identity (manager|services)|internet directory|identity|authenticator/, 'Identity & Directory'],
  [/esxi|vcenter|hyper-v|vsphere|proxmox|virtualbox/, 'Virtualization'],
  [/veeam|backup|commvault|veritas/, 'Backup & Storage'],
  [/moveit|goanywhere|file transfer|accellion/, 'File Transfer'],
  [/screenconnect|anydesk|teamviewer|rmm|kaseya|remote desktop|endpoint manager|neurons|itsm/, 'IT & Remote Management'],
  [/gitlab|jenkins|teamcity|jira|bitbucket|bamboo|jetbrains/, 'DevOps & Collaboration'],
  [/hyperion|peoplesoft|siebel|netweaver|e-business|webcenter|product hub|purchasing|agile product|irecruitment|dynamics|\bsap\b/, 'ERP & Business Apps'],
  [/airflow|nifi|kafka|impala|camel|activemq|artemis|zookeeper|nutch/, 'Data & Messaging'],
  [/http server|httpd|tomcat|nginx|jboss|wildfly|jetty|websphere/, 'Web & Application Servers'],
  [/sql server|mysql|weblogic|coherence|helidon|oracle forms|\bforms\b/, 'Databases & Middleware'],
  [/azure|copilot|foundry|dataverse|power platform|power automate|\bfabric\b|cosmos|hdinsight|cyclecloud|vm repair/, 'Cloud & AI Services'],
  [/^microsoft windows|365 apps|office|edge chromium|image extension|video extensions|media extensions|xbox/, 'Windows & Endpoint'],
  [/ios|nx-os|junos|switch|router|openssh|firewall|sd-wan|catalyst/, 'Network Infrastructure'],
];
const categorize = (s) => CATEGORY_RULES.find(([re]) => re.test(s.toLowerCase()))?.[1] ?? 'Application Platforms';

// First sentence of the description, cut at a word boundary.
const shorten = (desc, max = 110) => {
  const first = desc.split(/(?<=\.)\s/)[0];
  if (first.length <= max) return first;
  return first.slice(0, max).replace(/\s+\S*$/, '') + '...';
};

// Collapse per-release product names ("windows 10 1607", "sql server 2017") into one product.
const cleanProduct = (p) => p
  .replace(/^windows (10|11|server|\d).*$/, (m) => m.startsWith('windows server') ? 'windows server' : 'windows')
  .replace(/^sql server \d+$/, 'sql server');

async function getJson(url, headers = {}, tries = 4) {
  for (let i = 0; i < tries; i++) {
    const r = await fetch(url, { headers });
    if (r.ok) return r.json();
    if (![403, 429, 503].includes(r.status)) throw new Error(`${r.status} ${url}`);
    await sleep(6000 * (i + 1));
  }
  throw new Error(`gave up on ${url}`);
}

async function fetchNvd() {
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const delay = process.env.NVD_API_KEY ? 700 : 6500;
  const found = [];
  const MAX_SPAN = 120 * 864e5; // NVD rejects publication-date ranges longer than 120 days
  const now = Date.now();
  for (let from = now - DAYS * 864e5; from < now; from += MAX_SPAN) {
    const to = Math.min(from + MAX_SPAN, now);
    for (let idx = 0; ; ) {
      const qs = new URLSearchParams({
        pubStartDate: new Date(from).toISOString(), pubEndDate: new Date(to).toISOString(),
        resultsPerPage: '2000', startIndex: String(idx),
      });
      const j = await getJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?${qs}`, headers);
      found.push(...j.vulnerabilities.map((x) => x.cve));
      idx += j.resultsPerPage;
      if (idx >= j.totalResults) break;
      await sleep(delay);
    }
    await sleep(delay);
  }
  return found;
}

function normalize(c) {
  const cpes = (c.configurations ?? []).flatMap((cfg) => cfg.nodes ?? []).flatMap((n) => n.cpeMatch ?? [])
    .map((m) => m.criteria.split(':'));            // cpe:2.3:a:vendor:product:...
  const hit = cpes.find((p) => VENDORS[p[3]]);
  if (!hit) return null;
  const m = c.metrics ?? {};
  const metric = (m.cvssMetricV31 ?? m.cvssMetricV40 ?? m.cvssMetricV30 ?? [])[0];
  const product = cleanProduct(hit[4].replace(/_/g, ' '));
  const desc = c.descriptions?.find((d) => d.lang === 'en')?.value ?? '';
  return {
    id: c.id, vendor: VENDORS[hit[3]], product, category: categorize(`${VENDORS[hit[3]]} ${product}`),
    cvss: metric?.cvssData?.baseScore ?? null, kev: false, published: c.published.slice(0, 10),
    title: shorten(desc), summary: desc,
  };
}

async function recategorize() {
  const j = JSON.parse(await readFile(OUT, 'utf8'));
  for (const v of j.cves) {
    v.product = cleanProduct(v.product.toLowerCase());
    v.category = categorize(`${v.vendor} ${v.product}`.toLowerCase());
    if (v.summary) v.title = shorten(v.summary);
  }
  await writeFile(OUT, JSON.stringify(j, null, 1));
  console.log(`Recategorized ${j.cves.length} CVEs`);
}

async function main() {
  if (process.argv.includes('--recategorize')) return recategorize();
  const prev = JSON.parse(await readFile(OUT, 'utf8').catch(() => '{"cves":[]}'));
  const byId = new Map(prev.seed ? [] : prev.cves.map((v) => [v.id, v]));

  console.log(`NVD: last ${DAYS} days`);
  for (const c of await fetchNvd()) {
    const v = normalize(c);
    if (v && (v.cvss == null || v.cvss >= 7)) byId.set(v.id, { ...byId.get(v.id), ...v });
  }

  console.log('CISA KEV');
  const kev = new Map((await getJson(KEV_URL)).vulnerabilities.map((v) => [v.cveID, v.dateAdded]));
  for (const v of byId.values()) {
    v.kev = kev.has(v.id);
    if (v.kev) v.kevAdded = kev.get(v.id); // date CISA confirmed exploitation in the wild
  }

  console.log('EPSS');
  const ids = [...byId.keys()];
  for (let i = 0; i < ids.length; i += 100) {
    const j = await getJson(`https://api.first.org/data/v1/epss?cve=${ids.slice(i, i + 100).join(',')}`);
    for (const e of j.data) byId.get(e.cve).epss = Number(e.epss);
  }

  const cves = [...byId.values()].sort((a, b) => b.published.localeCompare(a.published));
  await writeFile(OUT, JSON.stringify({ generated: new Date().toISOString(), cves }, null, 1));
  console.log(`Wrote ${cves.length} CVEs`);
}
main().catch((e) => { console.error(e); process.exit(1); });
