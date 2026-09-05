import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import fc from 'fast-check'
import type { Arbitrary } from 'fast-check'

import {
  component,
  createSignatureBase,
  date,
  decimal,
  displayString,
  parseStructuredField,
  serializeStructuredField,
  sign,
  token,
  verify,
} from '../index.ts'
import type {
  StructuredFieldBareItem,
  StructuredFieldDictionary,
  StructuredFieldInnerList,
  StructuredFieldItem,
  StructuredFieldList,
  StructuredFieldMember,
  StructuredFieldParameter,
} from '../index.ts'
import { RFC_CREATED, webCryptoSigner, webCryptoVerifier, verificationPolicy } from './support.ts'

const options = { numRuns: 100 }

function stringFrom(
  firstCharacters: string,
  remainingCharacters: string,
  maxLength = 16,
): Arbitrary<string> {
  return fc
    .tuple(
      fc.constantFrom(...firstCharacters),
      fc.array(fc.constantFrom(...remainingCharacters), { maxLength: maxLength - 1 }),
    )
    .map(([first, remaining]) => first + remaining.join(''))
}

const keyArbitrary = stringFrom(
  'abcdefghijklmnopqrstuvwxyz*',
  'abcdefghijklmnopqrstuvwxyz0123456789_.*-',
)

const printableStringArbitrary = fc
  .array(fc.integer({ min: 0x20, max: 0x7e }), { maxLength: 32 })
  .map((characters) => String.fromCharCode(...characters))

const integerArbitrary = fc.oneof(
  fc.integer({ min: -1_000_000_000, max: 1_000_000_000 }),
  fc.constantFrom(-999_999_999_999_999, 999_999_999_999_999),
)

const decimalArbitrary = fc.oneof(
  fc.integer({ min: -1_000_000_000, max: 1_000_000_000 }).map((value) => decimal(value / 1000)),
  fc.constantFrom(decimal(-999_999_999_999.999), decimal(999_999_999_999.999)),
)

const bareItemArbitrary: Arbitrary<StructuredFieldBareItem> = fc.oneof(
  printableStringArbitrary,
  integerArbitrary,
  fc.boolean(),
  fc.uint8Array({ maxLength: 64 }),
  keyArbitrary.map(token),
  decimalArbitrary,
  integerArbitrary.map(date),
  fc.string({ unit: 'grapheme', maxLength: 24 }).map(displayString),
)

const parametersArbitrary: Arbitrary<StructuredFieldParameter[]> = fc.uniqueArray(
  fc.tuple(keyArbitrary, bareItemArbitrary).map(([name, value]) => [name, value] as const),
  { maxLength: 4, selector: ([name]) => name },
)

const itemArbitrary: Arbitrary<StructuredFieldItem> = fc.record({
  type: fc.constant('item'),
  value: bareItemArbitrary,
  parameters: parametersArbitrary,
})

const innerListArbitrary: Arbitrary<StructuredFieldInnerList> = fc.record({
  type: fc.constant('inner-list'),
  value: fc.array(itemArbitrary, { maxLength: 4 }),
  parameters: parametersArbitrary,
})

const memberArbitrary: Arbitrary<StructuredFieldMember> = fc.oneof(
  itemArbitrary,
  innerListArbitrary,
)

const listArbitrary: Arbitrary<StructuredFieldList> = fc.array(memberArbitrary, { maxLength: 5 })

const dictionaryArbitrary: Arbitrary<StructuredFieldDictionary> = fc.uniqueArray(
  fc.tuple(keyArbitrary, memberArbitrary).map(([name, member]) => [name, member] as const),
  { maxLength: 5, selector: ([name]) => name },
)

describe('Structured Fields properties', () => {
  it('keeps Item serialization canonical across a parse round trip', () => {
    fc.assert(
      fc.property(itemArbitrary, (item) => {
        const serialized = serializeStructuredField(item, 'item')
        assert.equal(
          serializeStructuredField(parseStructuredField(serialized, 'item'), 'item'),
          serialized,
        )
      }),
      options,
    )
  })

  it('keeps List serialization canonical across a parse round trip', () => {
    fc.assert(
      fc.property(listArbitrary, (list) => {
        const serialized = serializeStructuredField(list, 'list')
        assert.equal(
          serializeStructuredField(parseStructuredField(serialized, 'list'), 'list'),
          serialized,
        )
      }),
      options,
    )
  })

  it('keeps Dictionary serialization canonical across a parse round trip', () => {
    fc.assert(
      fc.property(dictionaryArbitrary, (dictionary) => {
        const serialized = serializeStructuredField(dictionary, 'dictionary')
        assert.equal(
          serializeStructuredField(parseStructuredField(serialized, 'dictionary'), 'dictionary'),
          serialized,
        )
      }),
      options,
    )
  })
})

const requestPartArbitrary = fc
  .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-._~'), {
    minLength: 1,
    maxLength: 32,
  })
  .map((characters) => characters.join(''))

const rawPathArbitrary = fc.oneof(
  fc.constant(''),
  fc
    .array(
      fc.oneof(
        requestPartArbitrary,
        fc.constantFrom('', '.', '..', '%2e', '%2E%2e', '.%2e', '%2e.', 'a%2Fb', 'a%3Fb', '%25'),
      ),
      { minLength: 1, maxLength: 5 },
    )
    .map((segments) => `/${segments.join('/')}`),
)

const queryTextArbitrary = fc
  .array(fc.constantFrom(...'abcXYZ09 ?%+&=/:!*()~', "'", '\u00e9', '\u2603', '\n', '\0'), {
    maxLength: 16,
  })
  .map((characters) => characters.join(''))

const queryNameArbitrary = fc.oneof(
  queryTextArbitrary,
  queryTextArbitrary.map((name) => `?${name}`),
)

const requestArbitrary = fc.record({
  method: fc.constantFrom('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'),
  path: rawPathArbitrary,
  query: queryTextArbitrary,
  header: requestPartArbitrary,
})

const coveredComponents = [
  '@method',
  '@authority',
  '@path',
  '@query',
  component('@query-param', { name: 'value' }),
  'x-property',
] as const

describe('URL component properties', () => {
  it('preserves raw paths against independently constructed bases', () => {
    fc.assert(
      fc.property(rawPathArbitrary, queryTextArbitrary, (path, value) => {
        const query = `?${new URLSearchParams([['value', value]]).toString()}`
        const message = { method: 'GET', url: `https://example.test${path}${query}`, headers: {} }
        assert.equal(
          createSignatureBase(message, { components: ['@path', '@request-target', '@query'] }),
          [
            `"@path": ${path || '/'}`,
            `"@request-target": ${path || '/'}${query}`,
            `"@query": ${query}`,
            '"@signature-params": ("@path" "@request-target" "@query")',
          ].join('\n'),
        )
      }),
      options,
    )
  })

  it('matches an independent query encoding oracle and rejects missing or repeated names', () => {
    fc.assert(
      fc.property(queryNameArbitrary, queryTextArbitrary, fc.boolean(), (name, value, literal) => {
        const encoded = new URLSearchParams([[name, value]]).toString()
        const canonical = encoded.replaceAll('+', '%20')
        const separator = canonical.indexOf('=')
        const encodedName = canonical.slice(0, separator)
        const encodedValue = canonical.slice(separator + 1)
        const query = literal ? encoded.replaceAll('%3F', '?').replaceAll('+', '%20') : encoded
        const url = `https://example.test/?${query}`
        const components = [component('@query-param', { name: encodedName })]
        const identifier = `"@query-param";name="${encodedName}"`

        for (const message of [new Request(url), { method: 'GET', url, headers: {} }]) {
          assert.equal(
            createSignatureBase(message, { components }),
            `${identifier}: ${encodedValue}\n"@signature-params": (${identifier})`,
          )
          assert.throws(
            () =>
              createSignatureBase(message, {
                components: [component('@query-param', { name: `missing-${encodedName}` })],
              }),
            /is not present/,
          )
        }
        assert.throws(
          () => createSignatureBase(new Request(`${url}&${encoded}`), { components }),
          /occurs more than once/,
        )
      }),
      options,
    )
  })
})

function tamperSignature(request: Request): Request {
  const headers = new Headers(request.headers)
  const signature = headers.get('signature')
  assert.ok(signature)
  headers.set(
    'signature',
    signature.replace(/:([A-Za-z0-9+/])/, (_, first: string) => `:${first === 'A' ? 'B' : 'A'}`),
  )
  return new Request(request, { headers })
}

describe('HTTP Message Signature properties', () => {
  it('round trips arbitrary requests and rejects authenticated tampering', async () => {
    await fc.assert(
      fc.asyncProperty(requestArbitrary, async ({ method, path, query, header }) => {
        const search = new URLSearchParams([['value', query]]).toString().replaceAll('%3F', '?')
        const unsigned = new Request(`https://example.test${path}?${search}`, {
          method,
          headers: { 'x-property': header },
        })
        const signed = await sign(unsigned, {
          signer: webCryptoSigner(),
          components: coveredComponents,
          parameters: { alg: 'hmac-sha256', created: RFC_CREATED, keyid: 'property-key' },
        })
        const verification = {
          verifier: webCryptoVerifier(undefined, 'property-key'),
          policy: verificationPolicy({
            now: RFC_CREATED,
            requiredComponents: coveredComponents,
            requiredParameters: ['created', 'keyid'],
          }),
        }

        const verified = await verify(signed, verification)
        assert.equal(verified.algorithm, 'hmac-sha256')

        const alteredPath = new URL(signed.url)
        alteredPath.pathname += 'changed'
        const alteredQuery = new URL(signed.url)
        alteredQuery.searchParams.set('value', `${query}!`)
        const alteredAuthority = new URL(signed.url)
        alteredAuthority.hostname = 'other.example.test'
        for (const url of [alteredPath, alteredQuery, alteredAuthority]) {
          await assert.rejects(
            verify(new Request(url, { method, headers: signed.headers }), verification),
            { name: 'VerificationError', code: 'signature_mismatch' },
          )
        }
        await assert.rejects(
          verify(new Request(signed, { method: method === 'GET' ? 'POST' : 'GET' }), verification),
          { name: 'VerificationError', code: 'signature_mismatch' },
        )

        const headers = new Headers(signed.headers)
        headers.set('x-property', `${header}!`)
        const tamperedHeader = new Request(signed, { headers })
        await assert.rejects(verify(tamperedHeader, verification), {
          name: 'VerificationError',
          code: 'signature_mismatch',
        })

        await assert.rejects(verify(tamperSignature(signed), verification), {
          name: 'VerificationError',
          code: 'signature_mismatch',
        })
      }),
      { numRuns: 50 },
    )
  })
})
