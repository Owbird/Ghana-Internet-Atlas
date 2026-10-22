const { test } = require('node:test')
const assert = require('node:assert/strict')
const ts = require('typescript')
const fs = require('node:fs')
const vm = require('node:vm')
const source = fs.readFileSync(require('node:path').join(__dirname, '../lib/exposure.ts'), 'utf8')
const context = { exports: {} }
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText, context)
const { announcedAddresses, rate, riskyPorts, riskyTags } = context.exports

test('announced addresses merge overlapping, duplicated, and adjacent ranges', () => {
  assert.equal(announcedAddresses(['41.0.0.0/24', '41.0.0.128/25', '41.0.0.0/24', '41.0.1.0/24']), 512)
  assert.equal(announcedAddresses(['41.0.0.255/32', '41.0.0.0/32']), 2)
  assert.equal(announcedAddresses(['0.0.0.0/0']), 4294967296)
  assert.equal(announcedAddresses([]), 0)
})
test('unknown denominators remain unavailable; known zero counts remain zero', () => {
  assert.equal(rate(0, 0), null)
  assert.equal(rate(0, 100), 0)
  assert.equal(rate(37, 100), 37)
  assert.equal(rate(8, 1000), 0.8)
})
test('exposure includes the requested six ports and five tags without duplicates', () => {
  assert.deepEqual(Array.from(riskyPorts, p => p.port), [179, 23, 21, 3306, 161, 8291])
  assert.deepEqual(Array.from(riskyTags, t => t.tag), ['eol-product', 'eol-os', 'database', 'vpn', 'self-signed'])
})
