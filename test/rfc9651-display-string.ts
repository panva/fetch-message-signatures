import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { component, createSignatureBase } from '../index.ts'
import type { StructuredFieldType } from '../index.ts'

function request(value: string): Request {
  return new Request('https://example.com/', { headers: { example: value } })
}

function expected(identifier: string, value: string): string {
  return `${identifier}: ${value}\n"@signature-params": (${identifier})`
}

function rfc9651Base(value: string, type: StructuredFieldType): string {
  return createSignatureBase(request(value), {
    components: [component('example', { sf: true })],
    structuredFields: { example: { type, version: 'rfc9651' } },
  })
}

function assertRfc8941Rejects(value: string, type: StructuredFieldType, key?: string): void {
  const covered =
    key === undefined ? component('example', { sf: true }) : component('example', { key })

  for (const definition of [type, { type, version: 'rfc8941' }] as const) {
    assert.throws(
      () =>
        createSignatureBase(request(value), {
          components: [covered],
          structuredFields: { example: definition },
        }),
      /not part of RFC 8941 Structured Fields/,
    )
  }
}

describe('RFC 9651 Display String item contexts', () => {
  it('parses and serializes direct and Inner List members in a List', () => {
    const value =
      '%"direct";item=%"item parameter", (%"inner";nested=%"nested parameter");list=%"list parameter"'

    assert.equal(rfc9651Base(value, 'list'), expected('"example";sf', value))
  })

  it('parses and serializes direct, Inner List, and implicit-Boolean Dictionary members', () => {
    const value =
      'direct=%"value";item=%"item parameter", nested=(%"inner");list=%"list parameter", implicit;label=%"implicit parameter"'

    assert.equal(rfc9651Base(value, 'dictionary'), expected('"example";sf', value))
  })

  it('retains Display String member parameters selected with ;key', () => {
    const value = 'selected=%"value";label=%"parameter"'
    const identifier = '"example";key="selected"'

    assert.equal(
      createSignatureBase(request(value), {
        components: [component('example', { key: 'selected' })],
        structuredFields: { example: { type: 'dictionary', version: 'rfc9651' } },
      }),
      expected(identifier, '%"value";label=%"parameter"'),
    )
  })

  it('canonicalizes safe percent-encoded bytes and preserves an empty value', () => {
    assert.equal(rfc9651Base('%"%41"', 'item'), expected('"example";sf', '%"A"'))
    assert.equal(rfc9651Base('%""', 'item'), expected('"example";sf', '%""'))
  })

  it('rejects Display Strings in every exercised RFC 8941 item context', () => {
    assertRfc8941Rejects('%"item"', 'item')
    assertRfc8941Rejects('(%"nested")', 'list')
    assertRfc8941Rejects('1;parameter=%"nested"', 'item')
    assertRfc8941Rejects('selected=%"member"', 'dictionary', 'selected')
  })
})
