import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendAcceptSignature,
  createAcceptSignature,
  createRequestedSignature,
  date,
  displayString,
  getSignatureRequests,
  parseAcceptSignature,
  signRequested,
  verify,
} from '../index.ts'
import type { SignatureRequest } from '../index.ts'
import { RFC_CREATED, verificationPolicy, webCryptoSigner, webCryptoVerifier } from './support.ts'

describe('Accept-Signature boundary behavior', () => {
  it('returns no requests when Accept-Signature is absent', () => {
    assert.deepEqual(getSignatureRequests(new Request('https://example.com/')), [])
    assert.deepEqual(getSignatureRequests(new Response(null)), [])
  })

  for (const [name, input, pattern] of [
    ['an empty request list', [], /non-empty array/],
    ['a non-array request list', null, /non-empty array/],
    ['a null request', [null], /Signature request.*object/],
    [
      'an invalid label',
      [{ label: 'Uppercase', components: ['@status'] }],
      /Signature request label/,
    ],
    ['non-array components', [{ label: 'sig', components: null }], /"components" must be an array/],
    [
      'created=false',
      [{ label: 'sig', components: ['@status'], parameters: { created: false } }],
      /Requested signature parameter "created" must be a bare Boolean true/,
    ],
    [
      'a Date created request',
      [{ label: 'sig', components: ['@status'], parameters: { created: date(RFC_CREATED) } }],
      /Requested signature parameter "created" must be a bare Boolean true/,
    ],
    [
      'a concrete expires value',
      [{ label: 'sig', components: ['@status'], parameters: { expires: RFC_CREATED } }],
      /Requested signature parameter "expires" must be a bare Boolean true/,
    ],
    [
      'a non-string nonce',
      [{ label: 'sig', components: ['@status'], parameters: { nonce: true } }],
      /Signature parameter "nonce" must be a String/,
    ],
    [
      'a non-string algorithm',
      [{ label: 'sig', components: ['@status'], parameters: { alg: true } }],
      /Signature parameter "alg" must be a String/,
    ],
    [
      'a Display String algorithm',
      [{ label: 'sig', components: ['@status'], parameters: { alg: displayString('ed25519') } }],
      /Signature parameter "alg" must be a String/,
    ],
  ] as const) {
    it(`rejects ${name}`, () => {
      assert.throws(() => createAcceptSignature(input as never), pattern)
    })
  }

  it('preserves an algorithm identifier added to the extensible registry', () => {
    const value = createAcceptSignature([
      { label: 'sig', components: ['@status'], parameters: { alg: 'future-example-alg' } },
    ])

    assert.equal(value, 'sig=("@status");alg="future-example-alg"')
    assert.deepEqual(parseAcceptSignature(value)[0]?.parameters, [['alg', 'future-example-alg']])
  })

  it('requires ordinary request and fulfillment configuration records', async () => {
    class RequestConfiguration {
      readonly label = 'sig'
      readonly components = ['@status']
    }
    assert.throws(
      () => createAcceptSignature([new RequestConfiguration()]),
      /Signature request must be a plain object/,
    )

    const requested = parseAcceptSignature('sig=("@status")')[0]!
    class FulfillmentConfiguration {
      readonly signer = webCryptoSigner()
      readonly now = RFC_CREATED
    }
    await assert.rejects(
      createRequestedSignature(new Response(null), requested, new FulfillmentConfiguration()),
      /"options" must be a plain object/,
    )
  })

  it('rejects a label duplicated across an existing and appended field value', () => {
    const request = new Request('https://example.com/', {
      headers: { 'accept-signature': 'same=("@status")' },
    })
    assert.throws(
      () => appendAcceptSignature(request, [{ label: 'same', components: ['content-type'] }]),
      /Duplicate Structured Field Dictionary key "same"/,
    )
  })

  it('preserves Date and Display String Accept-Signature extension parameters', () => {
    const value = 'sig=("@status");when=@1659578233;title=%"snowman %e2%98%83"'
    assert.deepEqual(parseAcceptSignature(value), [
      {
        label: 'sig',
        components: [{ name: '@status', parameters: [] }],
        parameters: [
          ['when', date(1659578233)],
          ['title', displayString('snowman ☃')],
        ],
      },
    ])
    assert.equal(
      createAcceptSignature([
        {
          label: 'sig',
          components: ['@status'],
          parameters: { when: date(1659578233), title: displayString('snowman ☃') },
        },
      ]),
      value,
    )
  })

  it('compares requested Byte Sequence extensions by value', async () => {
    const requested = parseAcceptSignature('sig=("@status");challenge=:AQID:')[0]!
    const response = new Response(null)

    await assert.rejects(
      createRequestedSignature(response, requested, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { challenge: new Uint8Array([1, 2]) },
      }),
      /conflicts with Accept-Signature/,
    )
    await assert.rejects(
      createRequestedSignature(response, requested, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { challenge: new Uint8Array([1, 2, 4]) },
      }),
      /conflicts with Accept-Signature/,
    )

    const fields = await createRequestedSignature(response, requested, {
      signer: webCryptoSigner(),
      now: RFC_CREATED,
      parameters: { challenge: new Uint8Array([1, 2, 3]) },
    })
    assert.deepEqual(fields.parameters, [
      ['created', RFC_CREATED],
      ['challenge', new Uint8Array([1, 2, 3])],
    ])
  })

  it('fulfills requested Date and Display String extensions by type and value', async () => {
    const requested = parseAcceptSignature(
      'sig=("@status");when=@1659578233;title=%"snowman %e2%98%83"',
    )[0]!
    const response = new Response(null)

    await assert.rejects(
      createRequestedSignature(response, requested, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { when: date(1659578234), title: displayString('snowman ☃') },
      }),
      /conflicts with Accept-Signature/,
    )

    const fields = await createRequestedSignature(response, requested, {
      signer: webCryptoSigner(),
      now: RFC_CREATED,
      parameters: { when: date(1659578233), title: displayString('snowman ☃') },
    })
    assert.deepEqual(fields.parameters, [
      ['created', RFC_CREATED],
      ['when', date(1659578233)],
      ['title', displayString('snowman ☃')],
    ])
  })

  it('supports response-to-next-request negotiation and fulfillment', async () => {
    const negotiation = appendAcceptSignature(new Response(null), [
      {
        label: 'client',
        components: ['@method', '@path', 'content-type'],
        parameters: { created: true, keyid: 'client-key', alg: 'hmac-sha256', nonce: 'challenge' },
      },
    ])
    const requested = getSignatureRequests(negotiation)[0]!
    const request = await signRequested(
      new Request('https://example.com/upload', {
        method: 'PUT',
        headers: { 'content-type': 'application/octet-stream' },
      }),
      requested,
      { signer: webCryptoSigner(), now: RFC_CREATED, parameters: { keyid: 'client-key' } },
    )

    const verified = await verify(request, {
      verifier: webCryptoVerifier(undefined, 'client-key'),
      policy: verificationPolicy({
        requiredComponents: ['@method', '@path', 'content-type'],
        requiredParameters: ['created', 'keyid', 'alg', 'nonce'],
      }),
    })
    assert.equal(verified.label, 'client')
  })

  it('preserves multiple requested members through append and parsing', () => {
    let message = new Request('https://example.com/')
    message = appendAcceptSignature(message, [{ label: 'one', components: ['@status'] }])
    message = appendAcceptSignature(message, [
      { label: 'two', components: ['content-type'] },
      { label: 'three', components: ['content-digest'] },
    ])
    assert.deepEqual(
      getSignatureRequests(message).map(({ label }) => label),
      ['one', 'two', 'three'],
    )
  })

  it('validates externally constructed SignatureRequest objects before fulfillment', async () => {
    const invalid = {
      label: 'sig',
      components: [
        { name: '@method', parameters: [] },
        { name: '@method', parameters: [] },
      ],
      parameters: [],
    } satisfies SignatureRequest

    await assert.rejects(
      createRequestedSignature(new Request('https://example.com/'), invalid, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
      }),
      /Duplicate covered component "@method"/,
    )
  })

  it('rejects a duplicate signature request label', () => {
    assert.throws(
      () =>
        createAcceptSignature([
          { label: 'sig', components: ['@status'] },
          { label: 'sig', components: ['@method'] },
        ]),
      /Duplicate signature request label "sig"/,
    )
  })

  it('requires explicit key selection for a requested keyid', async () => {
    const requested = parseAcceptSignature('sig=("@status");keyid="server-key"')[0]!
    await assert.rejects(
      createRequestedSignature(new Response(null), requested, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
      }),
      /An Accept-Signature "keyid" request requires explicit key selection/,
    )
    await assert.doesNotReject(
      createRequestedSignature(new Response(null), requested, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { keyid: 'server-key' },
      }),
    )
  })

  it('rejects a supplied value that conflicts with the request', async () => {
    const requested = parseAcceptSignature('sig=("@status");keyid="server-key"')[0]!
    await assert.rejects(
      createRequestedSignature(new Response(null), requested, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { keyid: 'other-key' },
      }),
      /Supplied signature parameter "keyid" conflicts with Accept-Signature/,
    )
  })

  it('reports that a filtered response cannot carry Accept-Signature', () => {
    const opaque = {
      status: 0,
      statusText: '',
      headers: new Headers(),
      body: null,
    } as unknown as Response
    assert.throws(
      () => appendAcceptSignature(opaque, [{ label: 'sig', components: ['@method'] }]),
      /Opaque and error responses cannot carry Accept-Signature/,
    )
  })

  it('does not mutate the parsed request while fulfilling it', async () => {
    const requested = parseAcceptSignature('sig=("@status");created;keyid="server-key"')[0]!
    const before = structuredClone(requested)
    await createRequestedSignature(new Response(null), requested, {
      signer: webCryptoSigner(),
      now: RFC_CREATED,
      parameters: { keyid: 'server-key' },
    })
    assert.deepEqual(requested, before)
  })
})
