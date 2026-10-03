// Fetches each company's public feeds into data/news.json.
// Usage: node scripts/update-news.mjs   (behind a proxy: NODE_USE_ENV_PROXY=1 NODE_EXTRA_CA_CERTS=...)
// A feed that fails keeps its previous items, so one outage never empties a company.
import { readFile, writeFile } from 'node:fs/promises';
import { parseFeed, discoverFeeds, looksLikeFeed } from './feed-parser.mjs';

const ROOT = new URL('../', import.meta.url);
const OUT = new URL('data/news.json', ROOT);
const PER_FEED = 30;
const UA = 'EnterpriseCyberTrack/1.0 (+https://github.com/soupsoup/enterprise-cybertrack)';

async function get(url) {
  const r = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(25000),
    headers: { 'user-agent': UA, accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, text/html;q=0.8, */*;q=0.5' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}

// Try the known URLs, then any feed the company's page advertises. Returns { url, items }.
async function loadFeed(feed) {
  const errors = [];
  const tryUrl = async (url) => {
    try {
      const text = await get(url);
      if (!looksLikeFeed(text)) throw new Error('not a feed');
      const items = parseFeed(text);
      if (!items.length) throw new Error('no items');
      return { url, items };
    } catch (e) { errors.push(`${url}: ${e.cause?.code || e.message}`); return null; }
  };
  for (const u of feed.urls) { const r = await tryUrl(u); if (r) return r; }
  if (feed.discover) {
    try {
      for (const u of discoverFeeds(await get(feed.discover), feed.discover)) {
        if (feed.urls.includes(u)) continue;
        const r = await tryUrl(u); if (r) return r;
      }
    } catch (e) { errors.push(`${feed.discover}: ${e.cause?.code || e.message}`); }
  }
  throw new Error(errors.join(' | ').slice(0, 400));
}

async function pool(tasks, n) {
  const q = [...tasks]; const run = async () => { while (q.length) await q.shift()(); };
  await Promise.all(Array.from({ length: n }, run));
}

async function main() {
  const { companies } = JSON.parse(await readFile(new URL('data/companies.json', ROOT), 'utf8'));
  const prev = JSON.parse(await readFile(OUT, 'utf8').catch(() => '{"items":[]}'));
  // Drop old items whose company or feed was removed from companies.json.
  const live = new Set(companies.flatMap((c) => c.feeds.map((f) => c.id + '|' + f.label)));
  const byLink = new Map(prev.items.filter((i) => live.has(i.company + '|' + i.feed)).map((i) => [i.link, i]));
  const now = new Date().toISOString();
  const status = [];

  await pool(companies.flatMap((c) => c.feeds.map((f) => async () => {
    const s = { company: c.id, label: f.label, url: f.urls[0], ok: false, checked: now };
    try {
      const { url, items } = await loadFeed(f);
      s.ok = true; s.url = url; s.count = items.length;
      // Feeds are not always newest-first (some run to thousands of items), so sort before trimming.
      const newest = [...items].sort((a, b) => (b.date || '').localeCompare(a.date || '')).slice(0, PER_FEED);
      for (const it of newest) byLink.set(it.link, { company: c.id, feed: f.label, ...it });
    } catch (e) { s.error = e.message; }
    status.push(s);
    console.log(`${s.ok ? 'ok  ' : 'FAIL'} ${c.name} / ${f.label}${s.ok ? ` (${s.count})` : ': ' + s.error.slice(0, 120)}`);
  })), 6);

  // Keep the newest PER_FEED items per company+feed so the file stays small.
  const groups = new Map();
  for (const it of byLink.values()) {
    const k = it.company + '|' + it.feed;
    (groups.get(k) || groups.set(k, []).get(k)).push(it);
  }
  const items = [...groups.values()].flatMap((g) => g.sort((a, b) => (b.date || '').localeCompare(a.date || '')).slice(0, PER_FEED))
    .sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  status.sort((a, b) => a.company.localeCompare(b.company) || a.label.localeCompare(b.label));
  await writeFile(OUT, JSON.stringify({ generated: now, status, items }, null, 1));
  console.log(`Wrote ${items.length} items; ${status.filter((s) => s.ok).length}/${status.length} feeds ok`);
}
main().catch((e) => { console.error(e); process.exit(1); });
