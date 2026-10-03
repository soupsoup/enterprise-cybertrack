const test = require('node:test');
const assert = require('node:assert');
const { compare, inRange, check, describe } = require('../version.js');
const data = require('../data/cves.json');

test('compare', () => {
  assert.equal(compare('1.0', '1.0.0'), 0);
  assert.equal(compare('13.1-64.23', '13.1-64.9'), 1);
  assert.equal(compare('14.1-73.37', '14.1-73.37'), 0);
  assert.equal(compare('2.9', '2.10'), -1);
  assert.equal(compare('1.0rc1', '1.0'), -1);
  assert.equal(compare('18.11.12', '18.11.2'), 1);
});

test('ranges respect inclusive and exclusive bounds', () => {
  const e = { from: '13.1', toExcl: '13.1-64.23' };
  assert.ok(inRange(e, '13.1-60.1'));
  assert.ok(inRange(e, '13.1'));
  assert.ok(!inRange(e, '13.1-64.23'));
  assert.ok(!inRange(e, '12.9'));
  assert.ok(inRange({ to: '5.0' }, '5.0'));
  assert.ok(!inRange({ fromExcl: '5.0' }, '5.0'));
  assert.ok(inRange({ version: '2.4.1' }, '2.4.1'));
  assert.ok(inRange({}, '99'));            // no bounds means every version
});

test('check returns the fix version', () => {
  const cve = { affects: [
    { vendor: 'Citrix', product: 'netscaler gateway', from: '13.1', toExcl: '13.1-64.23' },
    { vendor: 'Citrix', product: 'netscaler gateway', from: '14.1', toExcl: '14.1-73.37' }] };
  assert.equal(check(cve, 'Citrix', 'netscaler gateway', '13.1-60.1').fixedIn, '13.1-64.23');
  assert.equal(check(cve, 'Citrix', 'netscaler gateway', '14.1-80.1'), null);
  assert.equal(check(cve, 'Citrix', 'netscaler adc', '13.1-60.1'), null);
  assert.equal(check({ affects: [{ vendor: 'A', product: 'p', to: '1.2' }] }, 'A', 'p', '1.0').fixedIn, null);
  assert.equal(describe({ from: '13.1', toExcl: '13.1-64.23' }), '13.1 and later, before 13.1-64.23');
});

test('real data: a vulnerable and a patched Citrix NetScaler', () => {
  const cve = data.cves.find((v) => v.id === 'CVE-2026-88771');
  if (!cve) return;                         // data window moved on
  assert.ok(check(cve, 'Citrix', 'netscaler gateway', '14.1-60.0'));
  assert.equal(check(cve, 'Citrix', 'netscaler gateway', '14.1-80.0'), null);
});
