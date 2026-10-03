// Builds static RSS feeds from data/cves.json into feeds/.
// Usage: SITE_URL=https://example.github.io/enterprise-cybertrack node scripts/build-feeds.mjs
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';

const SITE = (process.env.SITE_URL || 'https://soupsoup.github.io/enterprise-cybertrack').replace(/\/$/, '');
const ROOT = new URL('../', import.meta.url);
const LIMIT = 100;

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const rfc822 = (d) => new Date(d + 'T00:00:00Z').toUTCString();

const fmtDate = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });

function page({ title, description, file, items, dateOf }) {
  const depth = file.split('/').length - 1;           // feeds/x.xml -> 1, feeds/vendor/x.xml -> 2
  const up = '../'.repeat(depth);
  const rss = file.split('/').pop();
  const cards = items.map((v) => {
    const pills = [`<span class="pill">CVSS ${v.cvss ?? 'n/a'}</span>`,
      v.kev ? `<span class="pill kev">Known exploited${v.kevAdded ? ' ' + esc(v.kevAdded) : ''}</span>` : '',
      v.epss != null ? `<span class="pill">EPSS ${(v.epss * 100).toFixed(1)}%</span>` : '',
      `<span class="pill">${esc(v.category)}</span>`].join(' ');
    return `<article>
<time datetime="${esc(dateOf(v))}">${esc(fmtDate(dateOf(v)))}</time>
<h2><a href="${up}#cve=${encodeURIComponent(v.id)}">${esc(v.id)}: ${esc(v.title)}</a></h2>
<p class="who">${esc(v.vendor)} ${esc(v.product)}</p>
<p>${esc(v.summary)}</p>
<div class="meta">${pills} <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}" rel="noopener">NVD record</a></div>
</article>`;
  }).join('\n');
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="alternate" type="application/rss+xml" title="${esc(title)}" href="${rss}">
<link rel="stylesheet" href="${up}styles.css">
</head>
<body>
<header class="top"><div class="wrap">
<p class="crumb"><a href="${up}">Enterprise CyberTrack</a> / feeds</p>
<h1>${esc(title)}</h1>
<p class="tag">${esc(description)}</p>
<p class="tag"><a href="${rss}">Subscribe with RSS</a> (paste the link into a feed reader). Showing the latest ${items.length}.</p>
</div></header>
<main class="wrap news">
${cards || '<p class="empty">Nothing here yet.</p>'}
</main>
<footer class="wrap foot">Generated ${new Date().toISOString().slice(0, 10)} from NVD, CISA KEV and FIRST EPSS. Check the vendor advisory before acting.</footer>
</body>
</html>
`;
  return writeFile(new URL(file.replace(/\.xml$/, '.html'), ROOT), html);
}

async function feed(opts) {
  const { title, description, file, items, dateOf } = opts;
  const sorted = [...items].sort((a, b) => dateOf(b).localeCompare(dateOf(a))).slice(0, LIMIT);
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>${esc(title)}</title>
<link>${SITE}/${file.replace(/\.xml$/, '.html')}</link>
<description>${esc(description)}</description>
<atom:link href="${SITE}/${file}" rel="self" type="application/rss+xml"/>
${sorted.map((v) => {
    const bits = [v.summary, `CVSS ${v.cvss ?? 'n/a'}`, v.kev ? `Known exploited (CISA KEV${v.kevAdded ? ', added ' + v.kevAdded : ''})` : null,
      v.epss != null ? `EPSS ${(v.epss * 100).toFixed(1)}%` : null].filter(Boolean).join(' | ');
    return `<item>
<title>${esc(`${v.id} ${v.vendor} ${v.product}: ${v.title}`)}</title>
<link>${SITE}/#cve=${encodeURIComponent(v.id)}</link>
<guid isPermaLink="false">${esc(v.id)}</guid>
<pubDate>${rfc822(dateOf(v))}</pubDate>
<category>${esc(v.category)}</category>
<description>${esc(bits)}</description>
</item>`;
  }).join('\n')}
</channel>
</rss>
`;
  await writeFile(new URL(file, ROOT), xml);
  await page({ ...opts, items: sorted });
}

const { cves } = JSON.parse(await readFile(new URL('data/cves.json', ROOT), 'utf8'));
await rm(new URL('feeds/', ROOT), { recursive: true, force: true });
await mkdir(new URL('feeds/vendor/', ROOT), { recursive: true });

const kev = cves.filter((v) => v.kev);
await feed({ title: 'Enterprise CyberTrack: known exploited', description: 'Enterprise vulnerabilities confirmed exploited in the wild (CISA KEV), newest first.',
  file: 'feeds/exploited.xml', items: kev, dateOf: (v) => v.kevAdded || v.published });
await feed({ title: 'Enterprise CyberTrack: critical', description: 'Newly published critical (CVSS 9.0+) enterprise vulnerabilities.',
  file: 'feeds/critical.xml', items: cves.filter((v) => (v.cvss ?? 0) >= 9), dateOf: (v) => v.published });

const vendors = [...new Set(cves.map((v) => v.vendor))];
for (const vendor of vendors) {
  await feed({ title: `Enterprise CyberTrack: ${vendor}`, description: `High and critical ${vendor} vulnerabilities.`,
    file: `feeds/vendor/${slug(vendor)}.xml`, items: cves.filter((v) => v.vendor === vendor), dateOf: (v) => v.published });
}
await writeFile(new URL('feeds/vendors.json', ROOT), JSON.stringify(vendors.sort().map((name) => ({ name, page: `feeds/vendor/${slug(name)}.html`, rss: `feeds/vendor/${slug(name)}.xml` }))));
console.log(`Wrote feeds: exploited (${kev.length}), critical, ${vendors.length} vendors`);
