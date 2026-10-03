import test from 'node:test';
import assert from 'node:assert';
import { parseFeed, toText, discoverFeeds, looksLikeFeed } from '../scripts/feed-parser.mjs';

const RSS = `<?xml version="1.0"?><rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><title>Blog</title>
<item><title><![CDATA[Zero-day in <b>Widget</b> &amp; friends]]></title><link>https://ex.com/a?x=1&amp;y=2</link>
<pubDate>Tue, 29 Sep 2026 14:00:00 GMT</pubDate><description><![CDATA[<p>Attackers abused&nbsp;a bug &mdash; patch now.</p>]]></description></item>
<item><title>Escaped &lt;i&gt;html&lt;/i&gt; summary</title><link>https://ex.com/b</link><pubDate>not a date</pubDate>
<description>&lt;p&gt;Hello &amp;amp; welcome&lt;/p&gt;</description></item>
<item><title>Bad link</title><link>javascript:alert(1)</link></item>
<item><link>https://ex.com/no-title</link></item>
</channel></rss>`;

const ATOM = `<feed xmlns="http://www.w3.org/2005/Atom"><title>T</title>
<entry><title type="html">Atom post</title><link rel="self" href="https://ex.com/self"/><link rel="alternate" href="https://ex.com/atom-1"/>
<published>2026-10-01T08:30:00Z</published><updated>2026-10-02T00:00:00Z</updated><summary>Short &amp; sweet</summary></entry></feed>`;

test('RSS: CDATA, entities, tags stripped, link decoded', () => {
  const [a, b] = parseFeed(RSS);
  assert.equal(a.title, 'Zero-day in Widget & friends');
  assert.equal(a.link, 'https://ex.com/a?x=1&y=2');
  assert.equal(a.date, '2026-09-29T14:00:00.000Z');
  assert.equal(a.summary, 'Attackers abused a bug — patch now.');
  assert.equal(b.summary, 'Hello & welcome');
  assert.equal(b.date, null);
});

test('RSS: drops items with unsafe links or no title', () => {
  const items = parseFeed(RSS);
  assert.equal(items.length, 2);
  assert.ok(items.every((i) => /^https?:/.test(i.link)));
});

test('Atom: prefers rel=alternate and published date', () => {
  const [e] = parseFeed(ATOM);
  assert.equal(e.link, 'https://ex.com/atom-1');
  assert.equal(e.date, '2026-10-01T08:30:00.000Z');
  assert.equal(e.summary, 'Short & sweet');
});

test('toText truncates at a word boundary and drops scripts', () => {
  const t = toText('<script>alert(1)</script>' + 'word '.repeat(100), 50);
  assert.ok(t.length <= 53 && t.endsWith('...') && !t.includes('alert'));
});

test('discoverFeeds resolves relative hrefs and ignores non-feed links', () => {
  const html = `<link rel="stylesheet" href="/a.css"><link rel="alternate" type="application/rss+xml" href="/blog/rss/">
    <link rel="alternate" type="application/atom+xml" href="https://ex.com/atom.xml"><link rel="alternate" type="text/html" href="/fr">`;
  assert.deepEqual(discoverFeeds(html, 'https://ex.com/blog/'), ['https://ex.com/blog/rss/', 'https://ex.com/atom.xml']);
});

test('looksLikeFeed rejects HTML', () => {
  assert.ok(looksLikeFeed(ATOM) && looksLikeFeed(RSS));
  assert.ok(!looksLikeFeed('<!doctype html><html><body>blocked</body></html>'));
});
