// Fetches each company's public feeds into data/news.json.
// Usage: node scripts/update-news.mjs   (behind a proxy: NODE_USE_ENV_PROXY=1 NODE_EXTRA_CA_CERTS=...)
// A feed that fails keeps its previous items, so one outage never empties a company.
import { readFile, writeFile } from 'node:fs/promises';
import { parseFeed, discoverFeeds, looksLikeFeed, parseSitemap, parseMeta, listingLinks } from './feed-parser.mjs';

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

// For sites with no RSS. The listing pages say which articles are newest and in what order; the
// sitemap supplies a date for each; each new article's own page supplies its title and description.
// The site shows no publication dates, and the sitemap's last-modified time is bumped when old posts are
// re-published, so a date is capped at the date of the article listed above it: an estimate, never earlier
// articles looking newer than later ones. Articles we already have are reused, so a normal run fetches
// only the new ones.
async function loadSitemap(feed, known) {
  const { url, prefix, limit = 30 } = feed.sitemap;
  const mod = new Map(parseSitemap(await get(url)).filter((e) => e.loc.startsWith(prefix) && e.lastmod).map((e) => [e.loc, e.lastmod]));
  let order = [];
  if (feed.listing) {
    for (let p = 1; p <= (feed.listing.pages || 1) && order.length < limit; p++) {
      const fresh = listingLinks(await get(`${feed.listing.url}?page=${p}`), feed.listing.url, prefix).filter((l) => !order.includes(l));
      if (!fresh.length) break;
      order.push(...fresh);
    }
  } else order = [...mod.keys()].sort((a, b) => mod.get(b).localeCompare(mod.get(a)));
  order = order.filter((l) => mod.has(l)).slice(0, limit);
  if (!order.length) throw new Error(`no articles under ${prefix}`);
  let cap = null;
  const dated = order.map((loc) => { let date = mod.get(loc); if (cap && date > cap) date = cap; cap = date; return { loc, date }; });
  const items = [];
  await pool(dated.map((e) => async () => {
    const old = known.get(e.loc);
    if (old?.title) { items.push({ title: old.title, link: e.loc, date: e.date, summary: old.summary || '' }); return; }
    try {
      const m = parseMeta(await get(e.loc));
      if (m.title) items.push({ title: m.title, link: e.loc, date: e.date, summary: m.summary });
    } catch { /* skip an article that will not load; it is retried next run */ }
  }), 4);
  if (!items.length) throw new Error('could not read any article titles');
  return { url: feed.page || url, items };
}

// Try the known URLs, then any feed the company's page advertises. Returns { url, items }.
async function loadFeed(feed, known) {
  if (feed.sitemap) return loadSitemap(feed, known);
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
  for (const u of feed.urls || []) { const r = await tryUrl(u); if (r) return r; }
  if (feed.discover) {
    try {
      for (const u of discoverFeeds(await get(feed.discover), feed.discover)) {
        if ((feed.urls || []).includes(u)) continue;
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

  // Fetch in parallel, but apply results in config order so an item that appears in two feeds
  // always gets the label of the first one listed.
  const jobs = companies.flatMap((c) => c.feeds.map((f) => ({ c, f })));
  const results = new Array(jobs.length);
  await pool(jobs.map(({ c, f }, idx) => async () => {
    const s = { company: c.id, label: f.label, url: f.page || f.urls?.[0], ok: false, checked: now };
    if (f.sitemap) s.page = f.page;      // a web page, not an RSS feed
    if (f.note) s.note = f.note;
    try {
      const { url, items } = await loadFeed(f, byLink);
      s.ok = true; s.url = url; s.count = items.length;
      // Feeds are not always newest-first (some run to thousands of items), so sort before trimming.
      results[idx] = [...items].sort((a, b) => (b.date || '').localeCompare(a.date || '')).slice(0, PER_FEED);
    } catch (e) { s.error = e.message; }
    status.push(s);
    console.log(`${s.ok ? 'ok  ' : 'FAIL'} ${c.name} / ${f.label}${s.ok ? ` (${s.count})` : ': ' + s.error.slice(0, 120)}`);
  }), 6);
  const claimed = new Set();
  jobs.forEach(({ c, f }, idx) => {
    // A listing-based feed is re-ranked from scratch each run (its dates are estimates), so replace
    // what we stored for it rather than merging into it. RSS feeds keep accumulating history.
    if (f.sitemap && results[idx]) for (const [k, v] of byLink) if (v.company === c.id && v.feed === f.label) byLink.delete(k);
    for (const it of results[idx] || []) {
      if (claimed.has(it.link)) continue;
      claimed.add(it.link);
      byLink.set(it.link, { company: c.id, feed: f.label, ...it });
    }
  });

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
