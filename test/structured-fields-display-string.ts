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

function structuredFieldBase(value: string, type: StructuredFieldType): string {
  return createSignatureBase(request(value), {
    components: [component('example', { sf: true })],
    structuredFields: { example: type },
  })
}

describe('Structured Field Display String item contexts', () => {
  it('parses and serializes direct and Inner List members in a List', () => {
    const value =
      '%"direct";item=%"item parameter", (%"inner";nested=%"nested parameter");list=%"list parameter"'

    assert.equal(structuredFieldBase(value, 'list'), expected('"example";sf', value))
  })

  it('parses and serializes direct, Inner List, and implicit-Boolean Dictionary members', () => {
    const value =
      'direct=%"value";item=%"item parameter", nested=(%"inner");list=%"list parameter", implicit;label=%"implicit parameter"'

    assert.equal(structuredFieldBase(value, 'dictionary'), expected('"example";sf', value))
  })

  it('retains Display String member parameters selected with ;key', () => {
    const value = 'selected=%"value";label=%"parameter"'
    const identifier = '"example";key="selected"'

    assert.equal(
      createSignatureBase(request(value), {
        components: [component('example', { key: 'selected' })],
        structuredFields: { example: 'dictionary' },
      }),
      expected(identifier, '%"value";label=%"parameter"'),
    )
  })

  it('canonicalizes safe percent-encoded bytes and preserves an empty value', () => {
    assert.equal(structuredFieldBase('%"%41"', 'item'), expected('"example";sf', '%"A"'))
    assert.equal(structuredFieldBase('%""', 'item'), expected('"example";sf', '%""'))
  })

  it('accepts Display Strings in every Structured Field item context', () => {
    assert.equal(structuredFieldBase('%"item"', 'item'), expected('"example";sf', '%"item"'))
    assert.equal(
      structuredFieldBase('(%"nested")', 'list'),
      expected('"example";sf', '(%"nested")'),
    )
    assert.equal(
      structuredFieldBase('1;parameter=%"nested"', 'item'),
      expected('"example";sf', '1;parameter=%"nested"'),
    )
    assert.equal(
      createSignatureBase(request('selected=%"member"'), {
        components: [component('example', { key: 'selected' })],
      }),
      expected('"example";key="selected"', '%"member"'),
    )
  })
})
