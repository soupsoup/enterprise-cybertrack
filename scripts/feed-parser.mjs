// Minimal, dependency-free RSS 2.0 / Atom / RDF parser. Returns plain-text items.
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', ndash: '–', mdash: '—', hellip: '…' };
const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
  if (e[0] === '#') {
    const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : '';
  }
  return ENTITIES[e.toLowerCase()] ?? m;
});

// Feed text may be wrapped in CDATA and may itself contain escaped HTML.
export function toText(raw, max = 280) {
  if (raw == null) return '';
  let s = String(raw).replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  s = decode(s);                                   // &lt;p&gt; -> <p>
  s = s.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]*>/g, ' ');
  s = decode(s).replace(/\s+/g, ' ').trim();       // decode again: &amp;amp; and friends
  return s.length > max ? s.slice(0, max).replace(/\s+\S*$/, '') + '...' : s;
}

const tag = (block, names) => {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, 'i'));
    if (m) return m[1];
  }
  return null;
};

const safeUrl = (u) => {
  try { const x = new URL(String(u).trim()); return x.protocol === 'http:' || x.protocol === 'https:' ? x.href : null; }
  catch { return null; }
};

function linkOf(block) {
  // Atom: <link rel="alternate" href="..."/>; prefer alternate, else first with href.
  const links = [...block.matchAll(/<link\b([^>]*?)\/?>/gi)].map((m) => m[1]);
  const pick = links.find((a) => /rel=["']alternate["']/i.test(a)) || links.find((a) => !/rel=/i.test(a)) || links[0];
  const href = pick && pick.match(/href=["']([^"']+)["']/i);
  if (href) return safeUrl(decode(href[1]));
  const text = tag(block, ['link']);               // RSS: <link>url</link>
  if (text) return safeUrl(toText(text, 2000));
  const guid = tag(block, ['guid', 'id']);
  return guid ? safeUrl(toText(guid, 2000)) : null;
}

export function parseFeed(xml) {
  const blocks = xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) || [];
  const items = [];
  for (const b of blocks) {
    const title = toText(tag(b, ['title']), 200);
    const link = linkOf(b);
    if (!title || !link) continue;
    const when = toText(tag(b, ['pubDate', 'published', 'updated', 'dc:date']), 60);
    const t = Date.parse(when);
    items.push({
      title, link,
      date: Number.isNaN(t) ? null : new Date(t).toISOString(),
      summary: toText(tag(b, ['description', 'summary', 'content:encoded', 'content'])),
    });
  }
  return items;
}

// Find feed URLs advertised in an HTML page: <link rel="alternate" type="application/rss+xml" href="...">.
export function discoverFeeds(html, base) {
  const out = [];
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const t = m[0];
    if (!/rel=["']alternate["']/i.test(t) || !/type=["']application\/(rss|atom)\+xml["']/i.test(t)) continue;
    const href = t.match(/href=["']([^"']+)["']/i);
    if (!href) continue;
    try { out.push(new URL(decode(href[1]), base).href); } catch { /* ignore bad href */ }
  }
  return out;
}

export const looksLikeFeed = (text) => /<(rss|feed|rdf:RDF)[\s>]/i.test(text.slice(0, 4000));
