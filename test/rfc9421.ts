import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendSignature,
  component,
  createSignature,
  createSignatureBase,
  getSignatures,
  sign,
  verify,
} from '../index.ts'
import {
  RFC_CREATED,
  RFC_HMAC_SIGNATURE,
  RFC_REQUEST_BASE,
  rfcRequest,
  rfcResponse,
  verificationPolicy,
  webCryptoSigner,
  webCryptoVerifier,
} from './support.ts'

describe('RFC 9421 Appendix B.2.5 HMAC-SHA256 request', () => {
  const components = ['date', '@authority', 'content-type']
  const parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-shared-secret'],
  ] as const

  it('creates the exact Appendix B signature base', () => {
    assert.equal(createSignatureBase(rfcRequest(), { components, parameters }), RFC_REQUEST_BASE)
  })

  it('creates the exact deterministic HMAC signature and fields', async () => {
    const fields = await createSignature(rfcRequest(), {
      signer: webCryptoSigner(),
      components,
      parameters,
      label: 'sig-b25',
    })

    assert.deepEqual(fields.signature, RFC_HMAC_SIGNATURE)
    assert.equal(
      fields.signatureInput,
      'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    )
    assert.equal(fields.signatureField, 'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:')
  })

  it('parses and verifies the RFC-provided signature fields', async () => {
    const request = rfcRequest()
    const signed = new Request(request, {
      headers: {
        ...Object.fromEntries(request.headers),
        signature: 'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:',
        'signature-input':
          'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
      },
    })

    const verified = await verify(signed, {
      verifier: webCryptoVerifier(undefined, 'test-shared-secret'),
      policy: verificationPolicy({
        requiredComponents: components,
        requiredParameters: ['created', 'keyid'],
      }),
    })

    assert.equal(verified.label, 'sig-b25')
    assert.equal(verified.algorithm, 'hmac-sha256')
    assert.deepEqual(verified.signature, RFC_HMAC_SIGNATURE)
  })

  it('round trips createSignature, appendSignature, and getSignatures', async () => {
    const message = rfcRequest()
    const fields = await createSignature(message, {
      signer: webCryptoSigner(),
      components,
      parameters,
      label: 'sig-b25',
    })
    const signed = appendSignature(message, fields)

    assert.deepEqual(getSignatures(signed), [
      {
        label: 'sig-b25',
        components: [
          { name: 'date', parameters: [] },
          { name: '@authority', parameters: [] },
          { name: 'content-type', parameters: [] },
        ],
        parameters: [
          ['created', RFC_CREATED],
          ['keyid', 'test-shared-secret'],
        ],
        signature: RFC_HMAC_SIGNATURE,
      },
    ])
  })

  it('detects covered-message modification', async () => {
    const signed = await sign(rfcRequest(), {
      signer: webCryptoSigner(),
      components,
      parameters,
      label: 'sig-b25',
    })
    const modified = new Request(signed, {
      headers: new Headers([...signed.headers, ['date', 'Tue, 20 Apr 2021 02:07:56 GMT']]),
    })

    await assert.rejects(
      verify(modified, {
        verifier: webCryptoVerifier(undefined, 'test-shared-secret'),
        policy: verificationPolicy(),
      }),
      /HTTP message signature verification failed/,
    )
  })
})

describe('derived components', () => {
  it('derives every request component without decoding path or query octets', () => {
    const request = new Request('https://EXAMPLE.com:443/a%2Fb?param=Value&Pet=dog&empty=', {
      method: 'PATCH',
    })
    const base = createSignatureBase(request, {
      components: [
        '@method',
        '@target-uri',
        '@authority',
        '@scheme',
        '@request-target',
        '@path',
        '@query',
        component('@query-param', { name: 'Pet' }),
        component('@query-param', { name: 'empty' }),
      ],
    })

    assert.equal(
      base,
      [
        '"@method": PATCH',
        '"@target-uri": https://example.com/a%2Fb?param=Value&Pet=dog&empty=',
        '"@authority": example.com',
        '"@scheme": https',
        '"@request-target": /a%2Fb?param=Value&Pet=dog&empty=',
        '"@path": /a%2Fb',
        '"@query": ?param=Value&Pet=dog&empty=',
        '"@query-param";name="Pet": dog',
        '"@query-param";name="empty": ',
        '"@signature-params": ("@method" "@target-uri" "@authority" "@scheme" "@request-target" "@path" "@query" "@query-param";name="Pet" "@query-param";name="empty")',
      ].join('\n'),
    )
  })

  it('normalizes an empty path and represents an absent query as "?"', () => {
    assert.equal(
      createSignatureBase(new Request('https://example.com'), {
        components: ['@path', '@query', '@request-target'],
      }),
      [
        '"@path": /',
        '"@query": ?',
        '"@request-target": /',
        '"@signature-params": ("@path" "@query" "@request-target")',
      ].join('\n'),
    )
  })

  it('derives @status only for responses', () => {
    assert.equal(
      createSignatureBase(rfcResponse(503), { components: ['@status'] }),
      '"@status": 503\n"@signature-params": ("@status")',
    )
    assert.throws(
      () => createSignatureBase(rfcRequest(), { components: ['@status'] }),
      /"@status" cannot be used with a request/,
    )
    assert.throws(
      () => createSignatureBase(rfcResponse(), { components: ['@method'] }),
      /"@method" requires "req" in a response signature/,
    )
  })
})

describe('@query-param form encoding', () => {
  it('percent-encodes parsed names and values, including plus-origin spaces', () => {
    const request = new Request(
      'https://example.com/?na+me=v+a&snow=%E2%98%83&punct=%7E%21%27%28%29',
    )
    assert.equal(
      createSignatureBase(request, {
        components: [
          component('@query-param', { name: 'na%20me' }),
          component('@query-param', { name: 'snow' }),
          component('@query-param', { name: 'punct' }),
        ],
      }),
      [
        '"@query-param";name="na%20me": v%20a',
        '"@query-param";name="snow": %E2%98%83',
        '"@query-param";name="punct": %7E%21%27%28%29',
        '"@signature-params": ("@query-param";name="na%20me" "@query-param";name="snow" "@query-param";name="punct")',
      ].join('\n'),
    )
  })

  it('rejects missing and repeated decoded parameter names', () => {
    const request = new Request('https://example.com/?Pet=dog&%50et=cat&other=value')
    assert.throws(
      () =>
        createSignatureBase(request, { components: [component('@query-param', { name: 'Pet' })] }),
      /Query parameter "Pet" occurs more than once/,
    )
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: [component('@query-param', { name: 'missing' })],
        }),
      /Query parameter "missing" is not present/,
    )
  })

  it('requires exactly one String name parameter', () => {
    assert.throws(
      () => createSignatureBase(rfcRequest(), { components: ['@query-param'] }),
      /requires a String "name" parameter/,
    )
    assert.throws(
      () =>
        createSignatureBase(rfcRequest(), {
          components: [component('@query-param', { name: true })],
        }),
      /requires a String "name" parameter/,
    )
  })
})

describe('response signatures bound to the related request', () => {
  const responseComponents = [
    '@status',
    'content-type',
    component('@method', { req: true }),
    component('@authority', { req: true }),
    component('content-type', { req: true }),
    component('@query-param', [
      ['name', 'Pet'],
      ['req', true],
    ]),
  ]

  it('creates a response base from response and request contexts', () => {
    const response = new Response('busy', {
      status: 503,
      headers: { 'content-type': 'application/problem+json' },
    })
    assert.equal(
      createSignatureBase(response, {
        request: rfcRequest(),
        components: responseComponents,
        parameters: { created: RFC_CREATED },
      }),
      [
        '"@status": 503',
        '"content-type": application/problem+json',
        '"@method";req: POST',
        '"@authority";req: example.com',
        '"content-type";req: application/json',
        '"@query-param";name="Pet";req: dog',
        '"@signature-params": ("@status" "content-type" "@method";req "@authority";req "content-type";req "@query-param";name="Pet";req);created=1618884473',
      ].join('\n'),
    )
  })

  it('requires the exact related request to verify a bound response', async () => {
    const request = rfcRequest()
    const response = new Response('busy', {
      status: 503,
      headers: { 'content-type': 'application/problem+json' },
    })
    const signed = await sign(response, {
      request,
      signer: webCryptoSigner(),
      components: responseComponents,
      parameters: { created: RFC_CREATED, keyid: 'test-shared-secret' },
    })
    const options = {
      verifier: webCryptoVerifier(undefined, 'test-shared-secret'),
      policy: verificationPolicy({
        requiredComponents: ['@status', component('@method', { req: true })],
      }),
    }

    await assert.doesNotReject(verify(signed, { ...options, request }))
    await assert.rejects(
      verify(signed, {
        ...options,
        request: new Request('https://example.com/foo?Pet=cat', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
        }),
      }),
      /HTTP message signature verification failed/,
    )
    await assert.rejects(verify(signed, options), /requires the related request/)

    assert.throws(
      () =>
        createSignatureBase(response, {
          request: new Response(null, {
            headers: { 'content-type': 'not-a-request' },
          }) as unknown as Request,
          components: [component('content-type', { req: true })],
        }),
      /must be the related Request/,
    )
  })
})
