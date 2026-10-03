(() => {
  const $ = (id) => document.getElementById(id);
  const sev = (c) => c == null ? 'none' : c >= 9 ? 'critical' : c >= 7 ? 'high' : c >= 4 ? 'medium' : 'low';
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  // Heuristic: CVSS base, +3 if on the CISA KEV list, up to +2 from EPSS.
  const risk = (v) => (v.cvss ?? 0) + (v.kev ? 3 : 0) + (v.epss != null ? v.epss * 2 : 0);

  const HIDDEN = 'Windows & Endpoint'; // high-volume patch noise, hidden unless opted in or picked as a category
  let all = [];
  const FIELDS = { q: 'q', category: 'category', vendor: 'vendor', severity: 'severity', sort: 'sort' };

  // Filters and the open CVE live in the URL hash so any view can be shared as a link.
  function saveState(cve) {
    const p = new URLSearchParams();
    for (const id of Object.keys(FIELDS)) if ($(id).value && !(id === 'sort' && $(id).value === 'risk')) p.set(id, $(id).value);
    if ($('kev').checked) p.set('kev', '1');
    if ($('win').checked) p.set('win', '1');
    if (cve) p.set('cve', cve);
    const h = p.toString();
    history.replaceState(null, '', h ? '#' + h : location.pathname + location.search);
  }
  function loadState() {
    const p = new URLSearchParams(location.hash.slice(1));
    for (const id of Object.keys(FIELDS)) if (p.has(id)) $(id).value = p.get(id);
    $('kev').checked = p.get('kev') === '1';
    $('win').checked = p.get('win') === '1';
    return p.get('cve');
  }

  function fill(sel, values) {
    for (const v of [...new Set(values)].sort()) sel.add(new Option(v, v));
  }

  function render() {
    const q = $('q').value.trim().toLowerCase();
    const cat = $('category').value, ven = $('vendor').value, sv = $('severity').value;
    const kev = $('kev').checked, sort = $('sort').value, win = $('win').checked;
    let rows = all.filter((v) =>
      (!cat || v.category === cat) && (win || cat === HIDDEN || v.category !== HIDDEN) && (!ven || v.vendor === ven) && (!kev || v.kev) &&
      (!sv || (sv === 'medium' ? sev(v.cvss) !== 'critical' && sev(v.cvss) !== 'high' : sev(v.cvss) === sv)) &&
      (!q || [v.id, v.vendor, v.product, v.title, v.summary].join(' ').toLowerCase().includes(q)));
    const key = { risk, cvss: (v) => v.cvss ?? 0, epss: (v) => v.epss ?? -1, date: (v) => Date.parse(v.published),
      // Date CISA added the CVE to KEV; CVEs with no known exploitation sort last.
      exploited: (v) => v.kevAdded ? Date.parse(v.kevAdded) : -Infinity };
    rows.sort((a, b) => key[sort](b) - key[sort](a));
    const hidden = all.filter((v) => v.category === HIDDEN).length;
    saveState();
    $('count').textContent = `${rows.length} of ${all.length} vulnerabilities` + (win || cat === HIDDEN ? '' : ` (${hidden} Windows & Endpoint hidden)`);
    $('list').innerHTML = rows.map((v) => `
      <li><button class="item" data-id="${esc(v.id)}">
        <div class="score s-${sev(v.cvss)}" title="CVSS base score">${v.cvss != null ? v.cvss.toFixed(1) : 'n/a'}</div>
        <div><h3><span class="id">${esc(v.id)}</span>${esc(v.title)}</h3>
          <div class="meta">
            <span class="pill">${esc(v.vendor)} ${esc(v.product)}</span>
            <span class="pill">${esc(v.category)}</span>
            ${v.kev ? `<span class="pill kev">Known exploited${v.kevAdded ? ' ' + esc(v.kevAdded) : ''}</span>` : ''}
            ${v.epss != null ? `<span class="pill">EPSS ${(v.epss * 100).toFixed(1)}%</span>` : ''}
            <span class="pill">${esc(v.published)}</span>
          </div></div></button></li>`).join('');
  }

  function stats() {
    const n = (f) => all.filter(f).length;
    const cells = [
      [all.length, 'Tracked CVEs'], [n((v) => v.kev), 'Known exploited'],
      [n((v) => sev(v.cvss) === 'critical'), 'Critical severity'],
      [new Set(all.map((v) => v.vendor)).size, 'Vendors'],
    ];
    $('stats').innerHTML = cells.map(([b, s]) => `<div class="stat"><b>${b}</b><span>${s}</span></div>`).join('');
  }

  function detail(id) {
    const v = all.find((x) => x.id === id), d = $('detail');
    d.innerHTML = `<h2>${esc(v.id)}: ${esc(v.title)}</h2><p>${esc(v.summary)}</p>
      <dl><dt>Vendor</dt><dd>${esc(v.vendor)}</dd><dt>Product</dt><dd>${esc(v.product)}</dd>
      <dt>Category</dt><dd>${esc(v.category)}</dd>
      <dt>CVSS</dt><dd>${v.cvss ?? 'n/a'} (${sev(v.cvss)})</dd>
      <dt>EPSS</dt><dd>${v.epss != null ? (v.epss * 100).toFixed(2) + '%' : 'not loaded'}</dd>
      <dt>Known exploited</dt><dd>${v.kev ? 'Yes, listed in CISA KEV' : 'Not listed'}</dd>
      ${v.kevAdded ? `<dt>First known exploited</dt><dd>${esc(v.kevAdded)} (date added to CISA KEV)</dd>` : ''}
      <dt>Published</dt><dd>${esc(v.published)}</dd>
      <dt>Risk score</dt><dd>${risk(v).toFixed(1)}</dd></dl>
      <p><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}" target="_blank" rel="noopener">NVD record</a></p>
      <button id="close">Close</button>`;
    d.showModal();
    saveState(id);
    $('close').onclick = () => d.close();
    d.onclose = () => saveState();
  }

  fetch('data/cves.json').then((r) => r.json()).then((j) => {
    all = j.cves;
    if (j.seed) {
      const b = $('banner');
      b.hidden = false;
      b.textContent = 'Showing a small bundled sample. Run "node scripts/update-data.mjs" (or enable the daily workflow) to load live NVD, CISA KEV and EPSS data.';
    }
    fill($('category'), all.map((v) => v.category));
    fill($('vendor'), all.map((v) => v.vendor));
    stats();
    const open = loadState();
    render();
    if (open && all.some((v) => v.id === open)) detail(open);
    if (j.generated && !j.seed) $('updated').textContent = 'Data updated ' + new Date(j.generated).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) + '. ';
  }).catch(() => { $('count').textContent = 'Could not load data/cves.json. Serve this folder over HTTP.'; });

  for (const id of ['q', 'category', 'vendor', 'severity', 'sort', 'kev', 'win']) $(id).addEventListener('input', render);
  $('list').addEventListener('click', (e) => { const b = e.target.closest('.item'); if (b) detail(b.dataset.id); });
})();
