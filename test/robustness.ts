import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendSignature,
  component,
  createSignedFetch,
  createSignature,
  createSignatureBase,
  decimal,
  getSignatures,
  parseSignature,
  parseSignatureInput,
  sign,
  token,
  verify,
} from '../index.ts'
import type {
  MessageSignature,
  SignOptions,
  VerificationPolicy,
  VerifierFactory,
} from '../index.ts'
import {
  RFC_CREATED,
  rfcRequest,
  verificationPolicy,
  webCryptoSigner,
  webCryptoVerifier,
} from './support.ts'

const encoder = new TextEncoder()

function signOptions(overrides: Partial<SignOptions> = {}): SignOptions {
  return {
    signer: webCryptoSigner(),
    components: ['@method', '@authority', 'x-covered'],
    parameters: { created: RFC_CREATED, keyid: 'test-key', alg: 'hmac-sha256' },
    label: 'tested',
    ...overrides,
  }
}

function requestFixture(): Request {
  return new Request('https://example.com:8443/path/to/resource?Pet=dog#fragment', {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', 'x-covered': 'original', 'x-uncovered': 'free' },
  })
}

async function signedFixture(): Promise<Request> {
  return sign(requestFixture(), signOptions())
}

describe('RFC 9651 Structured Field extension values', () => {
  it('rejects RFC 9651-only types in RFC 9421 signature metadata', () => {
    assert.throws(
      () => parseSignatureInput('sig=("@method");when=@1659578233'),
      /not valid RFC 9421 signature parameters/,
    )
    assert.throws(
      () =>
        parseSignatureInput('sig=("@method");title=%"This is intended for display to %c3%bcsers."'),
      /not valid RFC 9421 signature parameters/,
    )
  })

  it('keeps the legacy type shorthand on the RFC 8941 grammar', () => {
    for (const value of ['@1659578233', '%"display %c3%bc"']) {
      const request = new Request('https://example.com/', { headers: { example: value } })
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { sf: true })],
            structuredFields: { example: 'item' },
          }),
        /not part of RFC 8941 Structured Fields/,
      )
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { sf: true })],
            structuredFields: { example: { type: 'item', version: 'rfc8941' } },
          }),
        /not part of RFC 8941 Structured Fields/,
      )
    }
  })

  it('selects RFC 8941 or RFC 9651 for dictionary members under ;key', () => {
    const request = new Request('https://example.com/', {
      headers: { example: 'date=@1659578233, display=%"display %c3%bc"' },
    })

    for (const definition of ['dictionary', { type: 'dictionary', version: 'rfc8941' }] as const) {
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { key: 'date' })],
            structuredFields: { example: definition },
          }),
        /not part of RFC 8941 Structured Fields/,
      )
    }

    assert.equal(
      createSignatureBase(request, {
        components: [
          component('example', { key: 'date' }),
          component('example', { key: 'display' }),
        ],
        structuredFields: { example: { type: 'dictionary', version: 'rfc9651' } },
      }),
      [
        '"example";key="date": @1659578233',
        '"example";key="display": %"display %c3%bc"',
        '"@signature-params": ("example";key="date" "example";key="display")',
      ].join('\n'),
    )
  })

  it('does not allow application configuration to upgrade signature metadata', () => {
    const request = new Request('https://example.com/', {
      headers: { 'signature-input': 'sig=("@method");when=@1659578233' },
    })
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: [component('signature-input', { sf: true })],
          structuredFields: { 'signature-input': { type: 'dictionary', version: 'rfc9651' } },
        }),
      /not valid RFC 9421 signature parameters/,
    )
  })

  it('rejects malformed Structured Field definitions and non-dictionaries under ;key', () => {
    const request = new Request('https://example.com/', { headers: { example: 'value' } })
    for (const [definition, expected] of [
      [null, /Structured Field type for "example" is invalid/],
      [{ type: 'unknown', version: 'rfc9651' }, /Structured Field type for "example" is invalid/],
      [{ type: 'item', version: 'unknown' }, /Structured Field version for "example" is invalid/],
    ] as const) {
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { sf: true })],
            structuredFields: { example: definition as never },
          }),
        expected,
      )
    }

    assert.throws(
      () =>
        createSignatureBase(request, {
          components: [component('example', { key: 'member' })],
          structuredFields: { example: { type: 'item', version: 'rfc9651' } },
        }),
      /must be "dictionary" with the "key" parameter/,
    )
  })

  it('strictly serializes Date and Display String HTTP fields under ;sf', () => {
    const request = new Request('https://example.com/', {
      headers: {
        'example-date': '@1659578233',
        'example-display': '%"This is intended for display to %c3%bcsers."',
      },
    })
    assert.equal(
      createSignatureBase(request, {
        components: [
          component('example-date', { sf: true }),
          component('example-display', { sf: true }),
        ],
        structuredFields: {
          'example-date': { type: 'item', version: 'rfc9651' },
          'example-display': { type: 'item', version: 'rfc9651' },
        },
      }),
      [
        '"example-date";sf: @1659578233',
        '"example-display";sf: %"This is intended for display to %c3%bcsers."',
        '"@signature-params": ("example-date";sf "example-display";sf)',
      ].join('\n'),
    )
  })

  it('strictly serializes escaped, control, and non-BMP Display String bytes under ;sf', () => {
    const request = new Request('https://example.com/', {
      headers: { example: '%"100%25 %22dogs%22 %f0%9f%90%95%0a"' },
    })
    assert.equal(
      createSignatureBase(request, {
        components: [component('example', { sf: true })],
        structuredFields: { example: { type: 'item', version: 'rfc9651' } },
      }),
      [
        '"example";sf: %"100%25 %22dogs%22 %f0%9f%90%95%0a"',
        '"@signature-params": ("example";sf)',
      ].join('\n'),
    )
  })

  it('preserves a leading U+FEFF in a Display String under ;sf', () => {
    const withoutUfeff = createSignatureBase(
      new Request('https://example.com/', { headers: { example: '%"value"' } }),
      {
        components: [component('example', { sf: true })],
        structuredFields: { example: { type: 'item', version: 'rfc9651' } },
      },
    )
    const withUfeff = createSignatureBase(
      new Request('https://example.com/', { headers: { example: '%"%ef%bb%bfvalue"' } }),
      {
        components: [component('example', { sf: true })],
        structuredFields: { example: { type: 'item', version: 'rfc9651' } },
      },
    )

    assert.equal(
      withUfeff,
      ['"example";sf: %"%ef%bb%bfvalue"', '"@signature-params": ("example";sf)'].join('\n'),
    )
    assert.notEqual(withUfeff, withoutUfeff)
  })

  it('strictly serializes negative and boundary SF Dates under ;sf', () => {
    const request = new Request('https://example.com/', {
      headers: { 'negative-date': '@-62135596800', 'future-date': '@253402214400' },
    })
    assert.equal(
      createSignatureBase(request, {
        components: [
          component('negative-date', { sf: true }),
          component('future-date', { sf: true }),
        ],
        structuredFields: {
          'negative-date': { type: 'item', version: 'rfc9651' },
          'future-date': { type: 'item', version: 'rfc9651' },
        },
      }),
      [
        '"negative-date";sf: @-62135596800',
        '"future-date";sf: @253402214400',
        '"@signature-params": ("negative-date";sf "future-date";sf)',
      ].join('\n'),
    )
  })

  for (const [name, value] of [
    ['uppercase percent octets', '%"%C3%BC"'],
    ['truncated percent octet', '%"%c3%"'],
    ['non-hex percent octet', '%"%zz"'],
    ['isolated continuation byte', '%"%80"'],
    ['invalid leading byte', '%"%ff"'],
    ['truncated UTF-8 sequence', '%"%e2%82"'],
    ['overlong UTF-8 sequence', '%"%c0%af"'],
    ['UTF-8 encoded surrogate', '%"%ed%a0%80"'],
    ['code point above U+10FFFF', '%"%f4%90%80%80"'],
  ] as const) {
    it(`rejects ${name} in a Display String`, () => {
      const request = new Request('https://example.com/', { headers: { example: value } })
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { sf: true })],
            structuredFields: { example: { type: 'item', version: 'rfc9651' } },
          }),
        /Structured Field|UTF-8|percent/i,
      )
    })
  }

  it('rejects a fractional or out-of-range SF Date under ;sf', () => {
    for (const value of ['@1.5', '@1000000000000000']) {
      const request = new Request('https://example.com/', { headers: { example: value } })
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { sf: true })],
            structuredFields: { example: { type: 'item', version: 'rfc9651' } },
          }),
        /Date|Integer is out of range/,
      )
    }
  })
})

describe('derived-component and field boundaries', () => {
  it('strips fragments from @target-uri and retains non-default authority ports', () => {
    assert.equal(
      createSignatureBase(requestFixture(), {
        components: ['@target-uri', '@authority', '@scheme', '@request-target'],
      }),
      [
        '"@target-uri": https://example.com:8443/path/to/resource?Pet=dog',
        '"@authority": example.com:8443',
        '"@scheme": https',
        '"@request-target": /path/to/resource?Pet=dog',
        '"@signature-params": ("@target-uri" "@authority" "@scheme" "@request-target")',
      ].join('\n'),
    )
  })

  it('retains an IPv6 literal and port in @authority', () => {
    assert.equal(
      createSignatureBase(new Request('https://[2001:db8::1]:8443/resource'), {
        components: ['@authority'],
      }),
      '"@authority": [2001:db8::1]:8443\n"@signature-params": ("@authority")',
    )
  })

  it('distinguishes a bare query delimiter in the request target', () => {
    assert.equal(
      createSignatureBase(new Request('https://example.com/path?'), {
        components: ['@query', '@request-target'],
      }),
      [
        '"@query": ?',
        '"@request-target": /path?',
        '"@signature-params": ("@query" "@request-target")',
      ].join('\n'),
    )
  })

  it('preserves percent-encoded path and query octets exactly', () => {
    assert.equal(
      createSignatureBase(new Request('https://example.com/%2f%7e?q=%2f%7e'), {
        components: ['@path', '@query', '@target-uri'],
      }),
      [
        '"@path": /%2f%7e',
        '"@query": ?q=%2f%7e',
        '"@target-uri": https://example.com/%2f%7e?q=%2f%7e',
        '"@signature-params": ("@path" "@query" "@target-uri")',
      ].join('\n'),
    )
  })

  it('allows the same field with distinct component parameters', () => {
    const request = new Request('https://example.com/', { headers: { example: 'a=1, b=2' } })
    assert.equal(
      createSignatureBase(request, {
        components: [
          'example',
          component('example', { sf: true }),
          component('example', { key: 'b' }),
        ],
        structuredFields: { example: 'dictionary' },
      }),
      [
        '"example": a=1, b=2',
        '"example";sf: a=1, b=2',
        '"example";key="b": 2',
        '"@signature-params": ("example" "example";sf "example";key="b")',
      ].join('\n'),
    )
  })

  it('strictly serializes List and Item Structured Fields', () => {
    const request = new Request('https://example.com/', {
      headers: { 'example-list': 'a;q=1.0,(b   c)', 'example-item': '"hello";answer=42' },
    })
    assert.equal(
      createSignatureBase(request, {
        components: [
          component('example-list', { sf: true }),
          component('example-item', { sf: true }),
        ],
        structuredFields: { 'example-list': 'list', 'example-item': 'item' },
      }),
      [
        '"example-list";sf: a;q=1.0, (b c)',
        '"example-item";sf: "hello";answer=42',
        '"@signature-params": ("example-list";sf "example-item";sf)',
      ].join('\n'),
    )
  })

  it('normalizes obsolete line folding supplied by a raw-field adapter', () => {
    const request = new Request('https://example.com/')
    assert.equal(
      createSignatureBase(request, {
        components: ['example'],
        fieldValues() {
          return [' first\r\n\tcontinued ', ' second ']
        },
      }),
      ['"example": first continued, second', '"@signature-params": ("example")'].join('\n'),
    )
  })

  it('represents a present empty HTTP field as an empty component value', () => {
    assert.equal(
      createSignatureBase(new Request('https://example.com/', { headers: { 'x-empty': '' } }), {
        components: ['x-empty'],
      }),
      '"x-empty": \n"@signature-params": ("x-empty")',
    )
  })

  it('rejects non-octet raw field values under ;bs', () => {
    assert.throws(
      () =>
        createSignatureBase(requestFixture(), {
          components: [component('example', { bs: true })],
          fieldValues() {
            return ['snowman ☃']
          },
        }),
      /cannot be represented as bytes/,
    )
  })

  it('uses individual Set-Cookie occurrences exposed by Fetch under ;bs', () => {
    const headers = new Headers()
    headers.append('set-cookie', 'a=1')
    headers.append('set-cookie', 'b=2')
    const request = new Request('https://example.com/', { headers })
    assert.equal(
      createSignatureBase(request, { components: [component('set-cookie', { bs: true })] }),
      ['"set-cookie";bs: :YT0x:, :Yj0y:', '"@signature-params": ("set-cookie";bs)'].join('\n'),
    )
  })

  for (const [name, components, pattern] of [
    ['@signature-params', ['@signature-params'], /cannot be listed/],
    ['unknown derived component', ['@Method'], /Unknown derived component/],
    [
      'req on a request signature',
      [component('@method', { req: true })],
      /cannot be used with a request/,
    ],
    ['req on @status', [component('@status', { req: true })], /does not apply to "@status"/],
    ['non-string key', [component('example', { key: true })], /"key" must be a String/],
  ] as const) {
    it(`rejects ${name}`, () => {
      assert.throws(() => createSignatureBase(requestFixture(), { components }), pattern)
    })
  }
})

describe('provider contracts and mutation resistance', () => {
  it('rejects a non-function signer factory', async () => {
    await assert.rejects(
      createSignature(requestFixture(), {
        ...signOptions(),
        signer: null as unknown as SignOptions['signer'],
      }),
      /"signer" must be a factory function/,
    )
  })

  it('wraps a signer factory exception as an invalid provider', async () => {
    await assert.rejects(
      createSignature(requestFixture(), {
        ...signOptions(),
        signer() {
          throw new Error('key store unavailable')
        },
      }),
      (error: unknown) => {
        assert.ok(error instanceof TypeError)
        assert.equal(error.message, 'Invalid "signer"')
        assert.equal((error.cause as Error).message, 'key store unavailable')
        return true
      },
    )
  })

  it('rejects an invalid signer implementation object', async () => {
    await assert.rejects(
      createSignature(requestFixture(), {
        ...signOptions(),
        signer: () => ({ type: 'signer' }) as never,
      }),
      /Invalid "signer"/,
    )
  })

  it('wraps signer operation failures with the original cause', async () => {
    await assert.rejects(
      createSignature(requestFixture(), {
        ...signOptions(),
        signer: () => ({
          type: 'signer',
          alg: 'hmac-sha256',
          async sign() {
            throw new Error('hardware failure')
          },
        }),
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.equal(error.message, 'Failed to create HTTP message signature')
        assert.equal((error.cause as Error).message, 'hardware failure')
        return true
      },
    )
  })

  it('rejects a non-Uint8Array signer result', async () => {
    await assert.rejects(
      createSignature(requestFixture(), {
        ...signOptions(),
        signer: () => ({
          type: 'signer',
          alg: 'hmac-sha256',
          async sign() {
            return 'not bytes' as unknown as Uint8Array
          },
        }),
      }),
      /Signer output must be a Uint8Array/,
    )
  })

  it('detects request-header mutation in the signer factory', async () => {
    const request = requestFixture()
    await assert.rejects(
      createSignature(request, {
        ...signOptions(),
        signer() {
          request.headers.set('x-covered', 'factory mutation')
          return webCryptoSigner()()
        },
      }),
      /headers changed during signature signing/,
    )
  })

  it('detects delayed request-header mutation in the signer operation', async () => {
    const request = requestFixture()
    await assert.rejects(
      createSignature(request, {
        ...signOptions(),
        signer: () => ({
          type: 'signer',
          alg: 'hmac-sha256',
          async sign() {
            await Promise.resolve()
            request.headers.set('x-covered', 'async mutation')
            return new Uint8Array([1])
          },
        }),
      }),
      /headers changed during signature signing/,
    )
  })

  it('detects delayed related-request mutation while signing a response', async () => {
    const request = requestFixture()
    const response = new Response(null, { status: 204, headers: { 'x-response': 'original' } })
    await assert.rejects(
      createSignature(response, {
        request,
        components: ['@status', component('x-covered', { req: true })],
        parameters: { created: RFC_CREATED },
        signer: () => ({
          type: 'signer',
          alg: 'hmac-sha256',
          async sign() {
            await Promise.resolve()
            request.headers.set('x-covered', 'async mutation')
            return new Uint8Array([1])
          },
        }),
      }),
      /headers changed during signature signing/,
    )
  })

  it('rejects a non-function verifier factory', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier: null as unknown as VerifierFactory,
        policy: verificationPolicy(),
      }),
      /"verifier" must be a factory function/,
    )
  })

  it('wraps verifier-factory errors and rejects invalid verifier objects', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier() {
          throw new Error('unknown key')
        },
        policy: verificationPolicy(),
      }),
      (error: unknown) => {
        assert.ok(error instanceof TypeError)
        assert.equal(error.message, 'Invalid "verifier"')
        assert.equal((error.cause as Error).message, 'unknown key')
        return true
      },
    )
    await assert.rejects(
      verify(signed, {
        verifier: (() => ({ type: 'verifier' })) as never,
        policy: verificationPolicy(),
      }),
      /Invalid "verifier"/,
    )
  })

  it('wraps verifier operation failures with the original cause', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier: () => ({
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify() {
            throw new Error('remote HSM failure')
          },
        }),
        policy: verificationPolicy(),
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.equal(error.message, 'Failed to verify HTTP message signature')
        assert.equal((error.cause as Error).message, 'remote HSM failure')
        return true
      },
    )
  })

  it('rejects a non-boolean verifier result', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier: () => ({
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify() {
            return 1 as unknown as boolean
          },
        }),
        policy: verificationPolicy(),
      }),
      /Verifier output must be a boolean/,
    )
  })

  it('detects request mutation in the verifier factory', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier() {
          signed.headers.set('x-covered', 'factory mutation')
          return webCryptoVerifier()(getSignatures(signed)[0]!, { message: signed })
        },
        policy: verificationPolicy(),
      }),
      /headers changed during signature verification/,
    )
  })

  it('detects delayed request mutation in the verifier operation', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier: () => ({
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify() {
            await Promise.resolve()
            signed.headers.set('x-covered', 'async mutation')
            return true
          },
        }),
        policy: verificationPolicy(),
      }),
      /headers changed during signature verification/,
    )
  })

  it('isolates provider mutation of the parsed signature object', async () => {
    const signed = await signedFixture()
    const original = getSignatures(signed)[0]!
    const verified = await verify(signed, {
      verifier(signature) {
        ;(signature as { label: string }).label = 'provider-controlled'
        signature.signature.fill(0)
        ;(signature.components[0] as { name: string }).name = '@path'
        return {
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify() {
            return true
          },
        }
      },
      policy: verificationPolicy(),
    })

    assert.equal(verified.label, 'tested')
    assert.deepEqual(verified.components, original.components)
    assert.deepEqual(verified.signature, original.signature)
  })

  it('detects delayed related-request mutation while verifying a response', async () => {
    const request = requestFixture()
    const response = await sign(
      new Response(null, { status: 204, headers: { 'x-response': 'original' } }),
      {
        request,
        components: ['@status', component('x-covered', { req: true })],
        parameters: { created: RFC_CREATED },
        signer: webCryptoSigner(),
      },
    )

    await assert.rejects(
      verify(response, {
        request,
        verifier: () => ({
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify() {
            await Promise.resolve()
            request.headers.set('x-covered', 'async mutation')
            return true
          },
        }),
        policy: verificationPolicy(),
      }),
      /headers changed during signature verification/,
    )
  })
})

describe('verification policy boundaries', () => {
  const invalidPolicies: ReadonlyArray<readonly [string, unknown, RegExp]> = [
    ['null policy', null, /"policy" must be an object/],
    [
      'missing arrays',
      {},
      /must define requiredComponents, requiredParameters, and algorithms arrays/,
    ],
    [
      'empty algorithm allowlist',
      { requiredComponents: [], requiredParameters: [], algorithms: [] },
      /must not be empty/,
    ],
    [
      'empty algorithm name',
      { requiredComponents: [], requiredParameters: [], algorithms: [''] },
      /non-empty strings/,
    ],
    [
      'negative clock skew',
      {
        requiredComponents: [],
        requiredParameters: [],
        algorithms: ['hmac-sha256'],
        clockSkew: -1,
      },
      /clockSkew.*non-negative/,
    ],
    [
      'infinite clock skew',
      {
        requiredComponents: [],
        requiredParameters: [],
        algorithms: ['hmac-sha256'],
        clockSkew: Number.POSITIVE_INFINITY,
      },
      /clockSkew.*non-negative/,
    ],
    [
      'negative maximum age',
      { requiredComponents: [], requiredParameters: [], algorithms: ['hmac-sha256'], maxAge: -1 },
      /maxAge.*non-negative/,
    ],
    [
      'NaN maximum age',
      {
        requiredComponents: [],
        requiredParameters: [],
        algorithms: ['hmac-sha256'],
        maxAge: Number.NaN,
      },
      /maxAge.*non-negative/,
    ],
    [
      'invalid clock',
      { requiredComponents: [], requiredParameters: [], algorithms: ['hmac-sha256'], now: 1.5 },
      /Clock value must be an integer/,
    ],
    [
      'non-string required parameter',
      { requiredComponents: [], requiredParameters: [1], algorithms: ['hmac-sha256'] },
      /requiredParameters.*strings/,
    ],
  ]

  for (const [name, policy, pattern] of invalidPolicies) {
    it(`rejects ${name}`, async () => {
      const signed = await signedFixture()
      await assert.rejects(
        verify(signed, { verifier: webCryptoVerifier(), policy: policy as VerificationPolicy }),
        pattern,
      )
    })
  }

  it('matches required component parameters independent of their order', async () => {
    const request = new Request('https://example.com/', { headers: { example: 'a=1, b=2' } })
    const covered = component('example', [
      ['sf', true],
      ['key', 'a'],
    ])
    const signed = await sign(request, {
      signer: webCryptoSigner(),
      components: [covered],
      parameters: { created: RFC_CREATED },
    })
    await assert.doesNotReject(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({
          requiredComponents: [
            component('example', [
              ['key', 'a'],
              ['sf', true],
            ]),
          ],
        }),
      }),
    )
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ requiredComponents: [component('example', { key: 'b' })] }),
      }),
      /Required component "example" is not covered/,
    )
  })

  it('detects mutation performed by asynchronous application policy', async () => {
    const signed = await signedFixture()
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({
          async validate() {
            await Promise.resolve()
            signed.headers.set('x-uncovered', 'policy mutation')
          },
        }),
      }),
      /headers changed during signature verification/,
    )
  })

  it('does not allow policy.validate to be swapped during asynchronous verification', async () => {
    const signed = await signedFixture()
    let releaseVerification!: () => void
    const verificationGate = new Promise<void>((resolve) => {
      releaseVerification = resolve
    })
    let verificationStarted!: () => void
    const started = new Promise<void>((resolve) => {
      verificationStarted = resolve
    })
    let originalCalls = 0
    let replacementCalls = 0
    const policy = verificationPolicy({
      validate() {
        originalCalls++
      },
    })
    const pending = verify(signed, {
      verifier: () => ({
        type: 'verifier',
        alg: 'hmac-sha256',
        async verify() {
          verificationStarted()
          await verificationGate
          return true
        },
      }),
      policy,
    })

    await started
    ;(policy as { validate?: VerificationPolicy['validate'] }).validate = () => {
      replacementCalls++
    }
    releaseVerification()
    await pending

    assert.equal(originalCalls, 1)
    assert.equal(replacementCalls, 0)
  })
})

describe('signed-fetch configuration snapshots', () => {
  it('does not allow response verification to be disabled during a delayed fetch', async () => {
    let releaseFetch!: () => void
    const fetchGate = new Promise<void>((resolve) => {
      releaseFetch = resolve
    })
    let fetchStarted!: () => void
    const started = new Promise<void>((resolve) => {
      fetchStarted = resolve
    })
    const options = {
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      verify: { verifier: webCryptoVerifier(), policy: verificationPolicy() },
      fetch: (async () => {
        fetchStarted()
        await fetchGate
        return new Response(null)
      }) as typeof fetch,
    }
    const signedFetch = createSignedFetch(options)
    const pending = signedFetch('https://example.com/')

    await started
    ;(options as { verify?: typeof options.verify }).verify = undefined
    releaseFetch()

    await assert.rejects(pending, /Message does not contain an HTTP message signature/)
  })

  it('copies mutable signing components and metadata at construction time', async () => {
    const components = ['@method']
    const created = new Date(RFC_CREATED * 1000)
    const binary = new Uint8Array([1, 2, 3])
    const parameters: Array<[string, Date | Uint8Array]> = [
      ['created', created],
      ['extension', binary],
    ]
    let observed!: Request
    const signedFetch = createSignedFetch({
      sign: { signer: webCryptoSigner(), components, parameters },
      fetch: (async (input) => {
        observed = input as Request
        return new Response(null)
      }) as typeof fetch,
    })

    components[0] = '@path'
    created.setTime((RFC_CREATED + 1000) * 1000)
    binary.fill(0)
    parameters.push(['later', new Uint8Array([9])])
    await signedFetch('https://example.com/resource')

    const signature = getSignatures(observed)[0]!
    assert.deepEqual(signature.components, [{ name: '@method', parameters: [] }])
    assert.deepEqual(signature.parameters, [
      ['created', RFC_CREATED],
      ['extension', new Uint8Array([1, 2, 3])],
    ])
  })

  it('copies nested Structured Field definitions at construction time', async () => {
    const definition: { type: 'item'; version: 'rfc8941' | 'rfc9651' } = {
      type: 'item',
      version: 'rfc9651',
    }
    let observed!: Request
    const signedFetch = createSignedFetch({
      sign: {
        signer: webCryptoSigner(),
        components: [component('example', { sf: true })],
        structuredFields: { example: definition },
      },
      fetch: (async (input) => {
        observed = input as Request
        return new Response(null)
      }) as typeof fetch,
    })

    definition.version = 'rfc8941'
    await signedFetch('https://example.com/', { headers: { example: '@1659578233' } })

    assert.deepEqual(getSignatures(observed)[0]!.components, [
      { name: 'example', parameters: [['sf', true]] },
    ])
  })
})

describe('signature parsing, metadata, and multiple-signature boundaries', () => {
  it('round trips every supported extension metadata primitive', () => {
    const signatureInput =
      'sig=("@method");string="value";integer=42;decimal=1.5;boolean;binary=:AAEC:;token=token/value'
    assert.deepEqual(parseSignatureInput(signatureInput), [
      {
        label: 'sig',
        components: [{ name: '@method', parameters: [] }],
        parameters: [
          ['string', 'value'],
          ['integer', 42],
          ['decimal', decimal(1.5)],
          ['boolean', true],
          ['binary', new Uint8Array([0, 1, 2])],
          ['token', token('token/value')],
        ],
      },
    ])
  })

  it('supports the full Structured Field Integer range and rejects overflow', () => {
    assert.equal(
      createSignatureBase(requestFixture(), {
        components: [],
        parameters: { minimum: -999_999_999_999_999, maximum: 999_999_999_999_999 },
      }),
      '"@signature-params": ();minimum=-999999999999999;maximum=999999999999999',
    )
    assert.throws(
      () =>
        createSignatureBase(requestFixture(), {
          components: [],
          parameters: { overflow: 1_000_000_000_000_000 },
        }),
      /Integer is out of range/,
    )
  })

  it('rejects invalid token and Decimal helper inputs', () => {
    assert.throws(() => token('not a token'), /Structured Field Token/)
    assert.throws(() => decimal(Number.NaN), /Decimal must be finite/)
    assert.throws(() => decimal(Number.POSITIVE_INFINITY), /Decimal must be finite/)
    assert.throws(() => decimal(1_000_000_000_000), /Decimal is out of range/)
  })

  it('parses unpadded Byte Sequences and rejects invalid Base64 structure', () => {
    assert.deepEqual(parseSignature('sig=:AQI:'), [
      { label: 'sig', signature: new Uint8Array([1, 2]) },
    ])
    for (const value of ['sig=:A:', 'sig=:A===:', 'sig=:AA=A:', 'sig=:AA-_:', 'sig=:AA\n:']) {
      assert.throws(() => parseSignature(value), /Structured Field|Byte Sequence/)
    }
  })

  it('can relabel a signature without invalidating it', async () => {
    const signed = await signedFixture()
    const headers = new Headers(signed.headers)
    headers.set('signature-input', headers.get('signature-input')!.replace(/^tested=/, 'renamed='))
    headers.set('signature', headers.get('signature')!.replace(/^tested=/, 'renamed='))
    const relabeled = new Request(signed, { headers })

    const result = await verify(relabeled, {
      label: 'renamed',
      verifier: webCryptoVerifier(undefined, 'test-key'),
      policy: verificationPolicy(),
    })
    assert.equal(result.label, 'renamed')
  })

  it('verifies a good selected signature next to a corrupted co-signature', async () => {
    const first = await signedFixture()
    const second = await sign(first, {
      signer: webCryptoSigner(),
      components: ['@path'],
      parameters: { created: RFC_CREATED },
      label: 'corrupt',
    })
    const headers = new Headers(second.headers)
    headers.set(
      'signature',
      headers.get('signature')!.replace(/corrupt=:[A-Za-z0-9+/=]+:/, 'corrupt=:AA==:'),
    )
    const mixed = new Request(second, { headers })

    await assert.doesNotReject(
      verify(mixed, {
        label: 'tested',
        verifier: webCryptoVerifier(undefined, 'test-key'),
        policy: verificationPolicy(),
      }),
    )
    await assert.rejects(
      verify(mixed, {
        label: 'corrupt',
        verifier: webCryptoVerifier(),
        policy: verificationPolicy(),
      }),
      /HTTP message signature verification failed/,
    )
  })

  it('appends signature fields to Headers without modifying the source', async () => {
    const fields = await createSignature(requestFixture(), signOptions())
    const source = new Headers({ example: 'value' })
    const output = appendSignature(source, fields)

    assert.equal(source.has('signature'), false)
    assert.equal(source.has('signature-input'), false)
    assert.equal(output.get('example'), 'value')
    assert.equal(output.get('signature'), fields.signatureField)
    assert.equal(output.get('signature-input'), fields.signatureInput)
  })

  it('does not let mutation of returned parsed bytes affect the message', async () => {
    const signed = await signedFixture()
    const parsed = getSignatures(signed)[0]!
    parsed.signature.fill(0)

    await assert.doesNotReject(
      verify(signed, {
        verifier: webCryptoVerifier(undefined, 'test-key'),
        policy: verificationPolicy(),
      }),
    )
  })

  it('copies unknown binary metadata passed to the signer factory', async () => {
    const metadata = new Uint8Array([1, 2, 3])
    let observed!: Readonly<MessageSignature>
    const signed = await sign(requestFixture(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED, extension: metadata },
    })
    metadata.fill(0)

    await verify(signed, {
      verifier(signature) {
        observed = signature
        return {
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify(data, signature) {
            return webCryptoVerifier()(observed, { message: signed }).verify(data, signature)
          },
        }
      },
      policy: verificationPolicy(),
    })
    assert.deepEqual(
      observed.parameters.find(([name]) => name === 'extension')?.[1],
      new Uint8Array([1, 2, 3]),
    )
  })

  it('passes the exact UTF-8 signature base bytes to providers', async () => {
    let signedBytes!: Uint8Array
    const fields = await createSignature(requestFixture(), {
      signer: () => ({
        type: 'signer',
        alg: 'test',
        async sign(data) {
          signedBytes = data
          return new Uint8Array([0])
        },
      }),
      components: ['@method'],
      parameters: { created: false },
    })
    assert.deepEqual(
      signedBytes,
      encoder.encode('"@method": PATCH\n"@signature-params": ("@method")'),
    )
    assert.deepEqual(fields.signature, new Uint8Array([0]))
  })
})
