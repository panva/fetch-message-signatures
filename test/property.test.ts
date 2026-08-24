import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import fc from 'fast-check'
import type { Arbitrary } from 'fast-check'

import {
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

const requestArbitrary = fc.record({
  method: fc.constantFrom('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'),
  path: requestPartArbitrary,
  query: requestPartArbitrary,
  header: requestPartArbitrary,
})

const coveredComponents = ['@method', '@authority', '@path', '@query', 'x-property'] as const

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
        const unsigned = new Request(`https://example.test/${path}?value=${query}`, {
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
