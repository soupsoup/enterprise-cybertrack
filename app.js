(() => {
  const $ = (id) => document.getElementById(id);
  const sev = (c) => c == null ? 'none' : c >= 9 ? 'critical' : c >= 7 ? 'high' : c >= 4 ? 'medium' : 'low';
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  // Heuristic: CVSS base, +3 if on the CISA KEV list, up to +2 from EPSS.
  const risk = (v) => (v.cvss ?? 0) + (v.kev ? 3 : 0) + (v.epss != null ? v.epss * 2 : 0);

  let all = [];

  function fill(sel, values) {
    for (const v of [...new Set(values)].sort()) sel.add(new Option(v, v));
  }

  function render() {
    const q = $('q').value.trim().toLowerCase();
    const cat = $('category').value, ven = $('vendor').value, sv = $('severity').value;
    const kev = $('kev').checked, sort = $('sort').value;
    let rows = all.filter((v) =>
      (!cat || v.category === cat) && (!ven || v.vendor === ven) && (!kev || v.kev) &&
      (!sv || (sv === 'medium' ? sev(v.cvss) !== 'critical' && sev(v.cvss) !== 'high' : sev(v.cvss) === sv)) &&
      (!q || [v.id, v.vendor, v.product, v.title, v.summary].join(' ').toLowerCase().includes(q)));
    const key = { risk, cvss: (v) => v.cvss ?? 0, epss: (v) => v.epss ?? -1, date: (v) => Date.parse(v.published) };
    rows.sort((a, b) => key[sort](b) - key[sort](a));
    $('count').textContent = `${rows.length} of ${all.length} vulnerabilities`;
    $('list').innerHTML = rows.map((v) => `
      <li><button class="item" data-id="${esc(v.id)}">
        <div class="score s-${sev(v.cvss)}" title="CVSS base score">${v.cvss != null ? v.cvss.toFixed(1) : 'n/a'}</div>
        <div><h3><span class="id">${esc(v.id)}</span>${esc(v.title)}</h3>
          <div class="meta">
            <span class="pill">${esc(v.vendor)} ${esc(v.product)}</span>
            <span class="pill">${esc(v.category)}</span>
            ${v.kev ? '<span class="pill kev">Known exploited</span>' : ''}
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
      <dt>Published</dt><dd>${esc(v.published)}</dd>
      <dt>Risk score</dt><dd>${risk(v).toFixed(1)}</dd></dl>
      <p><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}" target="_blank" rel="noopener">NVD record</a></p>
      <button id="close">Close</button>`;
    d.showModal();
    $('close').onclick = () => d.close();
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
    render();
  }).catch(() => { $('count').textContent = 'Could not load data/cves.json. Serve this folder over HTTP.'; });

  for (const id of ['q', 'category', 'vendor', 'severity', 'sort', 'kev']) $(id).addEventListener('input', render);
  $('list').addEventListener('click', (e) => { const b = e.target.closest('.item'); if (b) detail(b.dataset.id); });
})();
