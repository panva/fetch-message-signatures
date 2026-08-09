import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { component, createSignatureBase, decimal } from '../index.ts'

describe('HTTP field component canonicalization', () => {
  it('strictly serializes Structured Field dictionaries with ;sf', () => {
    const request = new Request('https://example.com/', {
      headers: { 'example-dict': 'a=1; one;   two=2,b=2;x=1; y=2,c=(a  b c);   outer' },
    })
    assert.equal(
      createSignatureBase(request, {
        components: [component('example-dict', { sf: true })],
        structuredFields: { 'example-dict': 'dictionary' },
      }),
      [
        '"example-dict";sf: a=1;one;two=2, b=2;x=1;y=2, c=(a b c);outer',
        '"@signature-params": ("example-dict";sf)',
      ].join('\n'),
    )
    assert.throws(
      () =>
        createSignatureBase(
          new Request('https://example.com/', { headers: { 'example-dict': 'a=1;\tinvalid=2' } }),
          {
            components: [component('example-dict', { sf: true })],
            structuredFields: { 'example-dict': 'dictionary' },
          },
        ),
      /Invalid Structured Field key/,
    )
  })

  it('requires the Structured Field top-level type for ;sf', () => {
    const request = new Request('https://example.com/', { headers: { example: 'a=1' } })
    assert.throws(
      () => createSignatureBase(request, { components: [component('example', { sf: true })] }),
      /Structured Field type for "example" is required/,
    )
    const inheritedName = new Request('https://example.com/', { headers: { constructor: '' } })
    assert.throws(
      () =>
        createSignatureBase(inheritedName, {
          components: [component('constructor', { sf: true })],
          structuredFields: {},
        }),
      /Structured Field type for "constructor" is required/,
    )
  })

  it('selects and strictly serializes one dictionary member with ;key', () => {
    const request = new Request('https://example.com/', {
      headers: { 'example-dict': 'a=1, b=2;x=1;y=2, c=(a b c)' },
    })
    assert.equal(
      createSignatureBase(request, { components: [component('example-dict', { key: 'b' })] }),
      ['"example-dict";key="b": 2;x=1;y=2', '"@signature-params": ("example-dict";key="b")'].join(
        '\n',
      ),
    )
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: [component('example-dict', { key: 'missing' })],
        }),
      /has no member "missing"/,
    )
  })

  it('binary-wraps each raw field occurrence with ;bs', () => {
    const request = {
      method: 'GET',
      url: 'https://example.com/',
      headers: { example: [' first ', `second\u00ff`] },
    }
    assert.equal(
      createSignatureBase(request, { components: [component('example', { bs: true })] }),
      ['"example";bs: :Zmlyc3Q=:, :c2Vjb25k/w==:', '"@signature-params": ("example";bs)'].join(
        '\n',
      ),
    )
  })

  it('requires explicit field occurrences for ;bs under Fetch', () => {
    const request = new Request('https://example.com/', { headers: { example: 'value' } })
    assert.throws(
      () => createSignatureBase(request, { components: [component('example', { bs: true })] }),
      /explicit field occurrences/,
    )

    const headers = new Headers({ 'set-cookie': 'a=1, b=2' }) as Headers & {
      getSetCookie?: undefined
    }
    Object.defineProperty(headers, 'getSetCookie', { value: undefined })
    const withoutGetSetCookie = {
      method: 'GET',
      url: 'https://example.com/',
      headers,
    } as unknown as Request
    assert.throws(
      () =>
        createSignatureBase(withoutGetSetCookie, {
          components: [component('set-cookie', { bs: true })],
        }),
      /explicit field occurrences/,
    )
  })

  it('rejects incompatible ;bs combinations and invalid flags', () => {
    const request = new Request('https://example.com/', { headers: { example: 'a=1' } })
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: [
            component('example', [
              ['bs', true],
              ['sf', true],
            ]),
          ],
        }),
      /"bs" is incompatible with "sf" and "key"/,
    )
    assert.throws(
      () => createSignatureBase(request, { components: [component('example', { sf: false })] }),
      /Component parameter "sf" must be a bare Boolean true/,
    )
  })

  it('uses explicit trailer occurrences from a related request descriptor', () => {
    const request = {
      method: 'GET',
      url: 'https://example.com/',
      headers: { example: 'request header' },
      trailers: { example: ['trailer value'] },
    }
    const response = { status: 204, headers: {} }
    assert.equal(
      createSignatureBase(response, {
        request,
        components: [
          component('example', [
            ['tr', true],
            ['req', true],
          ]),
        ],
      }),
      ['"example";tr;req: trailer value', '"@signature-params": ("example";tr;req)'].join('\n'),
    )
  })

  it('normalizes occurrences in wire order and rejects absent fields', () => {
    const request = {
      method: 'GET',
      url: 'https://example.com/',
      headers: { 'cache-control': [' max-age=60 ', '\tmust-revalidate\t'] },
    }
    assert.equal(
      createSignatureBase(request, { components: ['cache-control'] }),
      [
        '"cache-control": max-age=60, must-revalidate',
        '"@signature-params": ("cache-control")',
      ].join('\n'),
    )
    assert.throws(
      () => createSignatureBase(request, { components: ['missing'] }),
      /Header field "missing" is not present/,
    )
    assert.throws(
      () =>
        createSignatureBase(
          {
            method: 'GET',
            url: 'https://example.com/',
            headers: { example: ['invalid\u0000value'] },
          },
          { components: ['example'] },
        ),
      /invalid control character|invalid header value/i,
    )
  })

  it('serializes Decimal metadata exactly at the RFC range boundary', () => {
    const request = new Request('https://example.com/')
    assert.match(
      createSignatureBase(request, {
        components: ['@method'],
        parameters: { first: decimal(999_999_999_999.001), last: decimal(999_999_999_999.999) },
      }),
      /;first=999999999999\.001;last=999999999999\.999$/,
    )
    assert.equal(
      createSignatureBase(request, {
        components: [],
        parameters: {
          down: decimal(999_157_158_878.5494),
          up: decimal(1_034_555.6005000001),
          even: decimal(0.0025),
          odd: decimal(0.0015),
        },
      }),
      '"@signature-params": ();down=999157158878.549;up=1034555.601;even=0.002;odd=0.002',
    )
  })
})
