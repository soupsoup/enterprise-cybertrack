// Builds static RSS feeds from data/cves.json into feeds/.
// Usage: SITE_URL=https://example.github.io/enterprise-cybertrack node scripts/build-feeds.mjs
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';

const SITE = (process.env.SITE_URL || 'https://soupsoup.github.io/enterprise-cybertrack').replace(/\/$/, '');
const ROOT = new URL('../', import.meta.url);
const LIMIT = 100;

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const rfc822 = (d) => new Date(d + 'T00:00:00Z').toUTCString();

function feed({ title, description, file, items, dateOf }) {
  const sorted = [...items].sort((a, b) => dateOf(b).localeCompare(dateOf(a))).slice(0, LIMIT);
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>${esc(title)}</title>
<link>${SITE}/</link>
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
  return writeFile(new URL(file, ROOT), xml);
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
await writeFile(new URL('feeds/vendors.json', ROOT), JSON.stringify(vendors.sort().map((name) => ({ name, file: `feeds/vendor/${slug(name)}.xml` }))));
console.log(`Wrote feeds: exploited (${kev.length}), critical, ${vendors.length} vendors`);
