// Version comparison and affected-range matching for "Am I affected?".
// Works in the browser (window.CT_VERSION) and in Node (module.exports) so it can be tested.
(function (root) {
  // Split "13.1-64.23" into [13, 1, 64, 23]; "1.0rc1" into [1, 0, "rc", 1].
  const tokens = (v) => (String(v).toLowerCase().match(/\d+|[a-z]+/g) || []).map((t) => (/^\d/.test(t) ? Number(t) : t));

  // Numbers compare numerically, words alphabetically. A word sorts before a number,
  // so "1.0rc1" < "1.0". A missing token counts as 0, so "1.0" equals "1.0.0".
  function compare(a, b) {
    const x = tokens(a), y = tokens(b), n = Math.max(x.length, y.length);
    for (let i = 0; i < n; i++) {
      const p = x[i] ?? 0, q = y[i] ?? 0;
      if (p === q) continue;
      const pn = typeof p === 'number', qn = typeof q === 'number';
      if (pn && qn) return p < q ? -1 : 1;
      if (!pn && !qn) return p < q ? -1 : 1;
      return pn ? 1 : -1;
    }
    return 0;
  }

  // Is `version` inside one affected entry {from, fromExcl, to, toExcl, version}?
  function inRange(e, version) {
    if (e.version) return compare(version, e.version) === 0;
    if (e.from && compare(version, e.from) < 0) return false;
    if (e.fromExcl && compare(version, e.fromExcl) <= 0) return false;
    if (e.to && compare(version, e.to) > 0) return false;
    if (e.toExcl && compare(version, e.toExcl) >= 0) return false;
    return true;
  }

  // Check one CVE against a product and version. Returns null when it does not apply,
  // otherwise { entries, fixedIn } where fixedIn is the version that fixes it (or null).
  function check(cve, vendor, product, version) {
    const mine = (cve.affects || []).filter((e) => e.vendor === vendor && e.product === product);
    if (!mine.length) return null;
    const hits = version ? mine.filter((e) => inRange(e, version)) : mine;
    if (!hits.length) return null;
    const fixes = hits.map((e) => e.toExcl).filter(Boolean).sort(compare);
    return { entries: hits, fixedIn: fixes.length === hits.length ? fixes[fixes.length - 1] : null };
  }

  // Human text for one range, e.g. "13.1 up to (not including) 13.1-64.23".
  function describe(e) {
    if (e.version) return `exactly ${e.version}`;
    const lo = e.from ? `${e.from} and later` : e.fromExcl ? `after ${e.fromExcl}` : '';
    const hi = e.toExcl ? `before ${e.toExcl}` : e.to ? `through ${e.to}` : '';
    return [lo, hi].filter(Boolean).join(', ') || 'all versions';
  }

  const api = { compare, inRange, check, describe };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.CT_VERSION = api;
})(typeof window !== 'undefined' ? window : globalThis);
