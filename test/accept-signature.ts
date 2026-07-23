import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendAcceptSignature,
  appendSignature,
  component,
  createAcceptSignature,
  createRequestedSignature,
  getSignatureRequests,
  parseAcceptSignature,
  signRequested,
  token,
  verify,
} from '../index.ts'
import {
  RFC_CREATED,
  rfcRequest,
  verificationPolicy,
  webCryptoSigner,
  webCryptoVerifier,
} from './support.ts'

describe('Accept-Signature creation and parsing', () => {
  it('serializes and parses the RFC 9421 Section 5.1 shape', () => {
    const value = createAcceptSignature([
      {
        label: 'sig1',
        components: ['@method', '@target-uri', '@authority', 'content-digest', 'cache-control'],
        parameters: [
          ['keyid', 'test-key-rsa-pss'],
          ['created', true],
          ['tag', 'app-123'],
        ],
      },
    ])
    assert.equal(
      value,
      'sig1=("@method" "@target-uri" "@authority" "content-digest" "cache-control");keyid="test-key-rsa-pss";created;tag="app-123"',
    )
    assert.deepEqual(parseAcceptSignature(value), [
      {
        label: 'sig1',
        components: [
          { name: '@method', parameters: [] },
          { name: '@target-uri', parameters: [] },
          { name: '@authority', parameters: [] },
          { name: 'content-digest', parameters: [] },
          { name: 'cache-control', parameters: [] },
        ],
        parameters: [
          ['keyid', 'test-key-rsa-pss'],
          ['created', true],
          ['tag', 'app-123'],
        ],
      },
    ])
  })

  it('supports multiple requests and preserves their order', () => {
    const value = createAcceptSignature([
      { label: 'one', components: ['@method'], parameters: { created: true } },
      { label: 'two', components: ['@path'], parameters: { alg: 'hmac-sha256' } },
    ])
    assert.deepEqual(
      parseAcceptSignature(value).map(({ label }) => label),
      ['one', 'two'],
    )
  })

  it('rejects malformed members, duplicate labels, and duplicate components', () => {
    assert.throws(() => parseAcceptSignature('sig1=?1'), /must be an Inner List/)
    assert.throws(
      () => parseAcceptSignature('sig1=("@status"); created'),
      /Invalid Structured Field key/,
    )
    assert.throws(
      () => parseAcceptSignature('sig1=("@method"), sig1=("@path")'),
      /Duplicate Structured Field Dictionary key "sig1"/,
    )
    assert.throws(
      () =>
        createAcceptSignature([
          { label: 'same', components: ['@method'] },
          { label: 'same', components: ['@path'] },
        ]),
      /Duplicate signature request label "same"/,
    )
    assert.throws(
      () => createAcceptSignature([{ label: 'sig1', components: ['@method', '@method'] }]),
      /Duplicate covered component "@method"/,
    )
    assert.throws(
      () =>
        createAcceptSignature([
          {
            label: 'sig1',
            components: [
              component('example', { key: 'a' }),
              component('example', [
                ['key', 'a'],
                ['sf', true],
              ]),
            ],
          },
        ]),
      /Duplicate covered dictionary key "example";key="a"/,
    )
    assert.throws(
      () => parseAcceptSignature('sig1=("example";key="a" "example";sf;key="a")'),
      /Duplicate covered dictionary key "example";key="a"/,
    )
    assert.throws(
      () =>
        createAcceptSignature([
          { label: 'sig1', components: [component('example', { unknown: true })] },
        ]),
      /Unknown HTTP field component parameter "unknown"/,
    )
    assert.throws(
      () =>
        createAcceptSignature([
          {
            label: 'sig1',
            components: [
              component('example', [
                ['bs', true],
                ['sf', true],
              ]),
            ],
          },
        ]),
      /"bs" is incompatible with "sf" and "key"/,
    )
  })
})

describe('Accept-Signature on Fetch messages', () => {
  it('appends response-target requests to a request and parses them', () => {
    const message = appendAcceptSignature(rfcRequest(), [
      {
        label: 'response',
        components: ['@status', 'content-type', component('@method', { req: true })],
        parameters: { created: true, keyid: 'test-shared-secret' },
      },
    ])

    assert.deepEqual(getSignatureRequests(message), [
      {
        label: 'response',
        components: [
          { name: '@status', parameters: [] },
          { name: 'content-type', parameters: [] },
          { name: '@method', parameters: [['req', true]] },
        ],
        parameters: [
          ['created', true],
          ['keyid', 'test-shared-secret'],
        ],
      },
    ])
  })

  it('enforces component applicability for the requested target type', () => {
    assert.throws(
      () => appendAcceptSignature(rfcRequest(), [{ label: 'bad', components: ['@method'] }]),
      /"@method" requires "req" in a response signature/,
    )
    assert.throws(
      () => appendAcceptSignature(new Response(null), [{ label: 'bad', components: ['@status'] }]),
      /"@status" cannot be used with a request/,
    )

    const withInvalidExisting = new Request('https://example.com/', {
      headers: { 'accept-signature': 'bad=("@method")' },
    })
    assert.throws(
      () =>
        appendAcceptSignature(withInvalidExisting, [{ label: 'good', components: ['@status'] }]),
      /"@method" requires "req" in a response signature/,
    )
  })
})

describe('fulfilling Accept-Signature', () => {
  const requestMessage = rfcRequest()
  const requestedValue = createAcceptSignature([
    {
      label: 'requested',
      components: ['@status', 'content-type', component('@method', { req: true })],
      parameters: [
        ['created', true],
        ['expires', true],
        ['nonce', 'server-challenge'],
        ['alg', 'hmac-sha256'],
        ['keyid', 'test-shared-secret'],
        ['tag', 'app-123'],
      ],
    },
  ])
  const request = parseAcceptSignature(requestedValue)[0]!

  it('uses the requested label/components/parameters and permits additions', async () => {
    const response = new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } })
    const fields = await createRequestedSignature(response, request, {
      request: requestMessage,
      signer: webCryptoSigner(),
      now: RFC_CREATED,
      parameters: [
        ['expires', RFC_CREATED + 300],
        ['keyid', 'test-shared-secret'],
        ['custom', 'additional'],
      ],
    })

    assert.equal(fields.label, 'requested')
    assert.deepEqual(fields.components, request.components)
    assert.deepEqual(fields.parameters, [
      ['created', RFC_CREATED],
      ['expires', RFC_CREATED + 300],
      ['nonce', 'server-challenge'],
      ['alg', 'hmac-sha256'],
      ['keyid', 'test-shared-secret'],
      ['tag', 'app-123'],
      ['custom', 'additional'],
    ])

    const signed = appendSignature(response, fields)
    await assert.doesNotReject(
      verify(signed, {
        request: requestMessage,
        verifier: webCryptoVerifier(undefined, 'test-shared-secret'),
        policy: verificationPolicy({
          now: RFC_CREATED,
          requiredComponents: request.components,
          requiredParameters: ['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'],
        }),
      }),
    )
  })

  it('signRequested appends the fulfilled signature', async () => {
    const signed = await signRequested(
      new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }),
      request,
      {
        request: requestMessage,
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { expires: RFC_CREATED + 300, keyid: 'test-shared-secret' },
      },
    )
    assert.deepEqual(
      getSignatureRequests(signed),
      [],
      'fulfillment adds Signature fields, not a new Accept-Signature field',
    )
    assert.match(signed.headers.get('signature-input')!, /^requested=/)
    assert.match(signed.headers.get('signature')!, /^requested=/)
  })

  it('rejects missing expiration and conflicting requested values', async () => {
    const response = new Response('ok', { headers: { 'content-type': 'text/plain' } })
    await assert.rejects(
      createRequestedSignature(response, request, {
        request: requestMessage,
        signer: webCryptoSigner(),
        now: RFC_CREATED,
      }),
      /requires an explicit expiration time/,
    )
    await assert.rejects(
      createRequestedSignature(response, request, {
        request: requestMessage,
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { expires: RFC_CREATED + 300, nonce: 'different-challenge' },
      }),
      /conflicts with Accept-Signature/,
    )
    await assert.rejects(
      createRequestedSignature(response, request, {
        request: requestMessage,
        signer: webCryptoSigner(),
        now: RFC_CREATED,
        parameters: { expires: RFC_CREATED + 300, alg: 'ed25519' },
      }),
      /conflicts with Accept-Signature/,
    )
  })

  it('requires explicit processing of requested extension parameters', async () => {
    const extensionRequest = parseAcceptSignature(
      'extension=("@status");custom=extension-token',
    )[0]!
    const response = new Response(null)

    await assert.rejects(
      createRequestedSignature(response, extensionRequest, {
        signer: webCryptoSigner(),
        now: RFC_CREATED,
      }),
      /Unsupported requested signature parameter "custom"/,
    )

    const fields = await createRequestedSignature(response, extensionRequest, {
      signer: webCryptoSigner(),
      now: RFC_CREATED,
      parameters: { custom: token('extension-token') },
    })
    assert.deepEqual(fields.parameters, [
      ['created', RFC_CREATED],
      ['custom', token('extension-token')],
    ])
  })

  it('preserves an explicit request to omit the default created parameter', async () => {
    const noMetadata = parseAcceptSignature('plain=("@status")')[0]!
    const fields = await createRequestedSignature(new Response(null), noMetadata, {
      signer: webCryptoSigner(),
      parameters: { created: false },
      now: RFC_CREATED,
    })

    assert.deepEqual(fields.parameters, [])
  })
})
