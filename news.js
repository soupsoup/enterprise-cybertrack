(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safe = (u) => (/^https?:\/\//i.test(u) ? u : '#');   // feed data is untrusted: only http(s) links
  const fmt = (d) => (d ? new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }) : 'Undated');

  let companies = [], items = [], status = [];
  let advisory = new Set();   // "company|feed label" pairs that are advisory firehoses, hidden unless asked for
  const byId = () => new Map(companies.map((c) => [c.id, c]));
  const FIELDS = { q: 'q', co: 'company', type: 'feed', days: 'range', sort: 'sort' };

  function save() {
    const p = new URLSearchParams();
    for (const [k, id] of Object.entries(FIELDS)) if ($(id).value && !(id === 'sort' && $(id).value === 'date')) p.set(k, $(id).value);
    if ($('adv').checked) p.set('adv', '1');
    const h = p.toString();
    history.replaceState(null, '', h ? '#' + h : location.pathname + location.search);
  }
  function load() {
    const p = new URLSearchParams(location.hash.slice(1));
    for (const [k, id] of Object.entries(FIELDS)) if (p.has(k)) $(id).value = p.get(k);
    $('adv').checked = p.get('adv') === '1';
  }

  const newest = (a, b) => (b.date || '').localeCompare(a.date || '');

  const isAdvisory = (i) => advisory.has(i.company + '|' + i.feed);
  // Advisories show when the box is ticked, or when the Type filter asks for that feed by name.
  const advisoryVisible = () => $('adv').checked || [...advisory].some((k) => k.split('|')[1] === $('feed').value);

  function filtered() {
    const q = $('q').value.trim().toLowerCase(), co = $('company').value, ty = $('feed').value, days = Number($('range').value);
    const since = days ? Date.now() - days * 864e5 : 0;
    const showAdv = advisoryVisible();
    return items.filter((i) => (showAdv || !isAdvisory(i)) && (!co || i.company === co) && (!ty || i.feed === ty) &&
      (!since || (i.date && Date.parse(i.date) >= since)) &&
      (!q || (i.title + ' ' + i.summary).toLowerCase().includes(q))).sort(newest);   // never trust file order
  }

  const card = (i, names, showCo) => `
    <article>
      <div class="meta">${showCo ? `<span class="pill">${esc(names.get(i.company)?.name || i.company)}</span>` : ''}<span class="pill">${esc(i.feed)}</span>
        <time datetime="${esc(i.date || '')}">${esc(fmt(i.date))}</time></div>
      <h3><a href="${esc(safe(i.link))}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a></h3>
      ${i.summary ? `<p>${esc(i.summary)}</p>` : ''}
    </article>`;

  function render() {
    const rows = filtered(), names = byId(), sort = $('sort').value;
    save();
    $('reset').hidden = !($('q').value || $('company').value || $('feed').value || $('range').value);
    const hiddenAdv = advisoryVisible() ? 0 : items.filter(isAdvisory).length;
    $('count').textContent = `${rows.length} of ${items.length - hiddenAdv} items` + (hiddenAdv ? ` (${hiddenAdv} security advisories hidden)` : '');
    const counts = new Map();
    for (const i of items) if (advisoryVisible() || !isAdvisory(i)) counts.set(i.company, (counts.get(i.company) || 0) + 1);
    document.querySelectorAll('.chip span').forEach((s) => { s.textContent = counts.get(s.parentElement.dataset.id) || 0; });
    document.querySelectorAll('.chip').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.id === $('company').value)));
    if (!rows.length) { $('results').innerHTML = '<p class="empty">Nothing matches these filters.</p>'; return; }
    if (sort === 'date') { $('results').innerHTML = `<div class="news">${rows.map((i) => card(i, names, true)).join('')}</div>`; return; }

    // Grouped by company, either A-Z or by how many items match.
    const groups = new Map();
    for (const i of rows) (groups.get(i.company) || groups.set(i.company, []).get(i.company)).push(i);
    const order = [...groups.keys()].sort((a, b) => sort === 'active'
      ? groups.get(b).length - groups.get(a).length || (names.get(a)?.name || a).localeCompare(names.get(b)?.name || b)
      : (names.get(a)?.name || a).localeCompare(names.get(b)?.name || b));
    $('results').innerHTML = order.map((id) => {
      const c = names.get(id) || { name: id }, g = groups.get(id);
      const feeds = status.filter((s) => s.company === id && s.ok).map((s) => `<a class="rss" href="${esc(safe(s.url))}" rel="noopener">${esc(s.label)} ${s.page ? 'page' : 'RSS'}</a>`).join(' ');
      return `<section class="group"><h2>${esc(c.name)} <span class="hint">${g.length} item${g.length > 1 ? 's' : ''}</span></h2>
        <p class="links">${c.site ? `<a href="${esc(safe(c.site))}" target="_blank" rel="noopener">Website</a>` : ''} ${feeds}</p>
        <div class="news">${g.map((i) => card(i, names, false)).join('')}</div></section>`;
    }).join('');
  }

  function health() {
    const names = byId();
    $('healthRows').innerHTML = status.map((s) => `<tr><td>${esc(names.get(s.company)?.name || s.company)}</td><td>${esc(s.label)}</td>
      <td>${s.ok ? `Loaded ${s.count} items` : `<span class="bad">Failed</span> <span class="hint">${esc((s.error || '').slice(0, 160))}</span>`}${s.note ? `<br><span class="hint">${esc(s.note)}</span>` : ''}</td></tr>`).join('');
    const ok = status.filter((s) => s.ok).length, b = $('banner');
    if (!status.length || ok === status.length) return;
    b.hidden = false;
    b.textContent = ok === 0
      ? 'No feeds have loaded yet. Run the news update (node scripts/update-news.mjs, or the daily workflow) to fill this page.'
      : `${ok} of ${status.length} feeds loaded. The others failed on the last update (see Feed status below), so some companies may be missing or out of date.`;
  }

  Promise.all([fetch('data/companies.json', { cache: 'no-cache' }).then((r) => r.json()), fetch('data/news.json', { cache: 'no-cache' }).then((r) => r.json())]).then(([c, n]) => {
    companies = c.companies; items = n.items || []; status = n.status || [];
    advisory = new Set(companies.flatMap((co) => co.feeds.filter((f) => f.advisory).map((f) => co.id + '|' + f.label)));
    const counts = new Map();
    for (const i of items) counts.set(i.company, (counts.get(i.company) || 0) + 1);
    for (const co of [...companies].sort((a, b) => a.name.localeCompare(b.name))) {
      $('company').add(new Option(co.name, co.id));
      const b = document.createElement('button');
      b.className = 'chip'; b.dataset.id = co.id; b.type = 'button';
      b.innerHTML = `${esc(co.name)} <span>${counts.get(co.id) || 0}</span>`;
      b.addEventListener('click', () => { $('company').value = $('company').value === co.id ? '' : co.id; render(); });
      $('chips').append(b);
    }
    for (const f of [...new Set(items.map((i) => i.feed))].sort()) $('feed').add(new Option(f, f));
    if (n.generated) $('updated').textContent = 'Updated ' + new Date(n.generated).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) + '.';
    load(); health(); render();
  }).catch(() => { $('count').textContent = 'Could not load the news data. Serve this folder over HTTP.'; });

  $('reset').addEventListener('click', () => { for (const id of ['q', 'company', 'feed', 'range']) $(id).value = ''; render(); });
  for (const id of ['q', 'company', 'feed', 'range', 'sort', 'adv']) $(id).addEventListener('input', render);
})();
