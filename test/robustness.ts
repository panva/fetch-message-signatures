import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendAcceptSignature,
  appendSignature,
  component,
  createSigningFetch,
  createSignedFetch,
  createSignature,
  createSignatureBase,
  createVerifyingFetch,
  date,
  decimal,
  displayString,
  getSignatureRequests,
  getSignatures,
  parseSignature,
  parseSignatureInput,
  sign,
  token,
  verify,
} from '../index.ts'
import type {
  MessageSignature,
  SignatureParameterInput,
  SignOptions,
  StructuredFieldType,
  VerificationPolicy,
  VerifierFactory,
} from '../index.ts'
import {
  RFC_CREATED,
  rfcRequest,
  verificationPolicy,
  webCryptoSigner,
  webCryptoVerifier,
  withoutUint8ArrayBase64,
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

describe('Structured Field extension values', () => {
  it('parses and serializes Date and Display String signature extension parameters', () => {
    const value =
      'sig=("@method");when=@1659578233;title=%"This is intended for display to %c3%bcsers."'
    assert.deepEqual(parseSignatureInput(value), [
      {
        label: 'sig',
        components: [{ name: '@method', parameters: [] }],
        parameters: [
          ['when', date(1659578233)],
          ['title', displayString('This is intended for display to üsers.')],
        ],
      },
    ])
    assert.equal(
      createSignatureBase(new Request('https://example.com/'), {
        components: ['@method'],
        parameters: [
          ['when', date(1659578233)],
          ['title', displayString('This is intended for display to üsers.')],
        ],
      }),
      [
        '"@method": GET',
        '"@signature-params": ("@method");when=@1659578233;title=%"This is intended for display to %c3%bcsers."',
      ].join('\n'),
    )
  })

  it('keeps RFC 9421 type requirements for known signature parameters', () => {
    assert.throws(
      () => parseSignatureInput('sig=("@method");created=@1659578233'),
      /Signature parameter "created" must be an Integer/,
    )
    assert.throws(
      () => parseSignatureInput('sig=("@method");alg=%"ed25519"'),
      /Signature parameter "alg" must be a String/,
    )
  })

  it('serializes Date and Display String dictionary members under ;key', () => {
    const request = new Request('https://example.com/', {
      headers: { example: 'date=@1659578233, display=%"display %c3%bc"' },
    })

    assert.equal(
      createSignatureBase(request, {
        components: [
          component('example', { key: 'date' }),
          component('example', { key: 'display' }),
        ],
        structuredFields: { example: 'dictionary' },
      }),
      [
        '"example";key="date": @1659578233',
        '"example";key="display": %"display %c3%bc"',
        '"@signature-params": ("example";key="date" "example";key="display")',
      ].join('\n'),
    )
  })

  it('supports Date and Display String values in built-in signature dictionaries', () => {
    const request = new Request('https://example.com/', {
      headers: {
        'signature-input': 'sig=("@method");when=@1659578233;title=%"snowman %e2%98%83"',
        signature: 'sig=:AQI:;when=@1659578233;title=%"snowman %e2%98%83"',
        'accept-signature': 'sig=("@status");when=@1659578233;title=%"snowman %e2%98%83"',
      },
    })

    assert.equal(
      createSignatureBase(request, {
        components: [
          component('signature-input', { sf: true }),
          component('signature', { sf: true }),
          component('accept-signature', { sf: true }),
        ],
      }),
      [
        '"signature-input";sf: sig=("@method");when=@1659578233;title=%"snowman %e2%98%83"',
        '"signature";sf: sig=:AQI=:;when=@1659578233;title=%"snowman %e2%98%83"',
        '"accept-signature";sf: sig=("@status");when=@1659578233;title=%"snowman %e2%98%83"',
        '"@signature-params": ("signature-input";sf "signature";sf "accept-signature";sf)',
      ].join('\n'),
    )
  })

  it('rejects malformed Structured Field types and non-dictionaries under ;key', () => {
    const request = new Request('https://example.com/', { headers: { example: 'value' } })
    for (const definition of [null, 'unknown', { type: 'item' }] as const) {
      assert.throws(
        () =>
          createSignatureBase(request, {
            components: [component('example', { sf: true })],
            structuredFields: { example: definition as never },
          }),
        /Structured Field type for "example" is invalid/,
      )
    }

    assert.throws(
      () =>
        createSignatureBase(request, {
          components: [component('example', { key: 'member' })],
          structuredFields: { example: 'item' },
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
        structuredFields: { 'example-date': 'item', 'example-display': 'item' },
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
        structuredFields: { example: 'item' },
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
      { components: [component('example', { sf: true })], structuredFields: { example: 'item' } },
    )
    const withUfeff = createSignatureBase(
      new Request('https://example.com/', { headers: { example: '%"%ef%bb%bfvalue"' } }),
      { components: [component('example', { sf: true })], structuredFields: { example: 'item' } },
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
        structuredFields: { 'negative-date': 'item', 'future-date': 'item' },
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
            structuredFields: { example: 'item' },
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
            structuredFields: { example: 'item' },
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
    const signed = await sign(
      requestFixture(),
      signOptions({
        parameters: {
          created: RFC_CREATED,
          keyid: 'test-key',
          alg: 'hmac-sha256',
          event: date(RFC_CREATED + 10),
          title: displayString('original title'),
        },
      }),
    )
    const original = getSignatures(signed)[0]!
    const verified = await verify(signed, {
      verifier(signature) {
        ;(signature as { label: string }).label = 'provider-controlled'
        signature.signature.fill(0)
        ;(signature.components[0] as { name: string }).name = '@path'
        ;(signature.parameters.find(([name]) => name === 'event')![1] as { value: number }).value =
          0
        ;(signature.parameters.find(([name]) => name === 'title')![1] as { value: string }).value =
          'provider-controlled'
        return {
          type: 'verifier',
          alg: 'hmac-sha256',
          async verify() {
            return true
          },
        }
      },
      policy: verificationPolicy({
        validate(signature) {
          assert.deepEqual(
            signature.parameters.find(([name]) => name === 'event')![1],
            date(RFC_CREATED + 10),
          )
          assert.deepEqual(
            signature.parameters.find(([name]) => name === 'title')![1],
            displayString('original title'),
          )
          ;(
            signature.parameters.find(([name]) => name === 'event')![1] as { value: number }
          ).value = 1
          ;(
            signature.parameters.find(([name]) => name === 'title')![1] as { value: string }
          ).value = 'policy-controlled'
        },
      }),
    })

    assert.equal(verified.label, 'tested')
    assert.deepEqual(verified.components, original.components)
    assert.deepEqual(verified.parameters, original.parameters)
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

describe('fetch-wrapper configuration snapshots', () => {
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
    const structuredDate = date(RFC_CREATED + 10)
    const structuredDisplayString = displayString('original title')
    const parameters: Array<[string, SignatureParameterInput]> = [
      ['created', created],
      ['extension', binary],
      ['event', structuredDate],
      ['title', structuredDisplayString],
    ]
    let observed!: Request
    const signingFetch = createSigningFetch({
      sign: { signer: webCryptoSigner(), components, parameters },
      fetch: (async (input) => {
        observed = input as Request
        return new Response(null)
      }) as typeof fetch,
    })

    components[0] = '@path'
    created.setTime((RFC_CREATED + 1000) * 1000)
    binary.fill(0)
    ;(structuredDate as { value: number }).value = 0
    ;(structuredDisplayString as { value: string }).value = 'changed title'
    parameters.push(['later', new Uint8Array([9])])
    await signingFetch('https://example.com/resource')

    const signature = getSignatures(observed)[0]!
    assert.deepEqual(signature.components, [{ name: '@method', parameters: [] }])
    assert.deepEqual(signature.parameters, [
      ['created', RFC_CREATED],
      ['extension', new Uint8Array([1, 2, 3])],
      ['event', date(RFC_CREATED + 10)],
      ['title', displayString('original title')],
    ])
  })

  it('copies mutable Structured Field mappings at construction time', async () => {
    const structuredFields: Record<string, StructuredFieldType> = { example: 'item' }
    let observed!: Request
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: [component('example', { sf: true })],
        structuredFields,
      },
      fetch: (async (input) => {
        observed = input as Request
        return new Response(null)
      }) as typeof fetch,
    })

    structuredFields.example = 'dictionary'
    await signingFetch('https://example.com/', { headers: { example: '@1659578233' } })

    assert.deepEqual(getSignatures(observed)[0]!.components, [
      { name: 'example', parameters: [['sf', true]] },
    ])
  })

  it('copies verification policy arrays at construction time', async () => {
    const requiredComponents = ['@status']
    const algorithms = ['hmac-sha256']
    const verifyingFetch = createVerifyingFetch({
      verify: {
        verifier: webCryptoVerifier(),
        policy: { requiredComponents, requiredParameters: [], algorithms, now: RFC_CREATED },
      },
      fetch: (async (input) =>
        sign(new Response(null, { status: 204 }), {
          request: input as Request,
          signer: webCryptoSigner(),
          components: ['@status'],
          parameters: { created: RFC_CREATED },
        })) as typeof fetch,
    })

    requiredComponents[0] = '@method'
    algorithms[0] = 'ed25519'

    await assert.doesNotReject(verifyingFetch('https://example.com/'))
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

  it('creates and validates Structured Field Date and Display String values', () => {
    const instant = new Date(1659578233999)
    assert.deepEqual(date(instant), { type: 'date', value: 1659578233 })
    assert.deepEqual(date(-0), { type: 'date', value: 0 })
    assert.deepEqual(displayString('snowman ☃'), { type: 'display-string', value: 'snowman ☃' })

    assert.equal(
      createSignatureBase(requestFixture(), {
        components: [],
        parameters: [
          ['integer-date', instant],
          ['structured-date', date(instant)],
          ['display', displayString('snowman ☃')],
        ],
      }),
      '"@signature-params": ();integer-date=1659578233;structured-date=@1659578233;display=%"snowman %e2%98%83"',
    )

    for (const value of [
      Number.NaN,
      Number.POSITIVE_INFINITY,
      1.5,
      1_000_000_000_000_000,
      new Date(Number.NaN),
    ]) {
      assert.throws(() => date(value), /Date is out of range/)
    }
    assert.throws(() => displayString(1 as never), /must be a string/)
    assert.throws(() => displayString('\ud800'), /unpaired surrogate/)
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

describe('option and message shape validation', () => {
  it('rejects a malformed Structured Field mapping even when no field component uses it', () => {
    assert.throws(
      () =>
        createSignatureBase(new Request('https://example.com/'), {
          components: ['@method'],
          structuredFields: 'dictionary' as unknown as Record<string, StructuredFieldType>,
        }),
      /"structuredFields" must be an object/,
    )
  })

  it('rejects a non-callable field adapter even when no field component uses it', () => {
    assert.throws(
      () =>
        createSignatureBase(new Request('https://example.com/'), {
          components: ['@method'],
          fieldValues: {} as unknown as SignOptions['fieldValues'],
        }),
      /"fieldValues" must be a function/,
    )
  })

  it('rejects invalid shared options from every entry point', async () => {
    const context = { fieldValues: {} as unknown as SignOptions['fieldValues'] }
    await assert.rejects(
      sign(new Request('https://example.com/'), { ...signOptions(), ...context }),
      /"fieldValues" must be a function/,
    )
    await assert.rejects(
      verify(await signedFixture(), {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy(),
        ...context,
      }),
      /"fieldValues" must be a function/,
    )
    assert.throws(
      () =>
        createSigningFetch({
          sign: { ...signOptions(), ...context },
          fetch: (async () => new Response(null)) as typeof fetch,
        }),
      /"fieldValues" must be a function/,
    )
    assert.throws(
      () =>
        createVerifyingFetch({
          verify: { verifier: webCryptoVerifier(), policy: verificationPolicy(), ...context },
          fetch: (async () => new Response(null)) as typeof fetch,
        }),
      /"fieldValues" must be a function/,
    )
  })

  it('rejects an invalid verification policy when a fetch wrapper is created', () => {
    assert.throws(
      () =>
        createVerifyingFetch({
          verify: {
            verifier: webCryptoVerifier(),
            policy: { requiredComponents: [], requiredParameters: [], algorithms: [] },
          },
          fetch: (async () => new Response(null)) as typeof fetch,
        }),
      /"policy.algorithms" must not be empty/,
    )
  })

  it('rejects a request whose target URI is not a string', () => {
    const message = { method: 'GET', headers: new Headers() } as unknown as Request
    assert.throws(
      () => createSignatureBase(message, { components: ['@method'] }),
      /"message" must be a Request or Response/,
    )
  })
})

describe('response reconstruction boundaries', () => {
  const unreconstructable: ReadonlyArray<readonly [string, number, RegExp]> = [
    ['opaque and network error responses', 0, /Opaque and error responses cannot carry/],
    ['informational responses', 103, /cannot reconstruct a response with status 103/],
  ]

  for (const [name, status, pattern] of unreconstructable) {
    it(`reports that ${name} cannot be signed`, async () => {
      const response = {
        status,
        statusText: '',
        headers: new Headers(),
        body: null,
      } as unknown as Response
      const fields = await createSignature(response, {
        signer: webCryptoSigner(),
        components: [],
        parameters: { created: RFC_CREATED },
      })
      assert.throws(() => appendSignature(response, fields), pattern)
    })
  }

  it('reconstructs a null-body status', async () => {
    const signed = await sign(new Response(null, { status: 204, statusText: 'No Content' }), {
      signer: webCryptoSigner(),
      components: ['@status'],
      parameters: { created: RFC_CREATED },
    })
    assert.equal(signed.status, 204)
    assert.equal(signed.statusText, 'No Content')
    assert.equal(signed.body, null)
  })
})

describe('derived component normalization', () => {
  it('normalizes an empty path in @request-target the same way as @path', () => {
    const request = { method: 'GET', url: 'foo://example.com', headers: new Headers() } as Request
    assert.equal(
      createSignatureBase(request, { components: ['@request-target', '@path'] }),
      [
        '"@request-target": /',
        '"@path": /',
        '"@signature-params": ("@request-target" "@path")',
      ].join('\n'),
    )
  })

  it('lowercases the authority of a scheme the URL parser does not normalize', () => {
    const request = {
      method: 'GET',
      url: 'foo://EXAMPLE.com:8443/path',
      headers: new Headers(),
    } as Request
    assert.equal(
      createSignatureBase(request, { components: ['@authority'] }),
      ['"@authority": example.com:8443', '"@signature-params": ("@authority")'].join('\n'),
    )
  })
})

describe('derived component error paths', () => {
  it('rejects a filtered response status', () => {
    const opaque = { status: 0, statusText: '', headers: new Headers() } as unknown as Response
    assert.throws(
      () => createSignatureBase(opaque, { components: ['@status'] }),
      /"@status" requires an unfiltered HTTP response status/,
    )
  })

  it('rejects a target URI that is not ASCII', () => {
    const request = {
      method: 'GET',
      url: 'https://example.com/é',
      headers: new Headers(),
    } as Request
    assert.throws(
      () => createSignatureBase(request, { components: ['@target-uri'] }),
      /Request target URI must contain only ASCII characters/,
    )
  })

  it('rejects a target URI that cannot be parsed', () => {
    const request = { method: 'GET', url: '/relative', headers: new Headers() } as Request
    assert.throws(
      () => createSignatureBase(request, { components: ['@path'] }),
      /Request does not have a valid target URI/,
    )
  })

  it('leaves query parameter characters the urlencoded set does not escape', () => {
    const request = new Request('https://example.com/?a*b-c.d_e=v*w-x.y_z')
    assert.equal(
      createSignatureBase(request, {
        components: [component('@query-param', { name: 'a*b-c.d_e' })],
      }),
      [
        '"@query-param";name="a*b-c.d_e": v*w-x.y_z',
        '"@signature-params": ("@query-param";name="a*b-c.d_e")',
      ].join('\n'),
    )
  })

  it('rejects an invalid component identifier shape', () => {
    assert.throws(
      () =>
        createSignatureBase(new Request('https://example.com/'), {
          components: [42 as unknown as string],
        }),
      /Invalid HTTP message component identifier/,
    )
  })

  it('rejects an uppercase HTTP field component name', () => {
    assert.throws(
      () => parseSignatureInput('sig1=("Content-Type");created=1618884473'),
      /Invalid or non-lowercase HTTP field component name/,
    )
  })

  it('rejects a Signature-Input member that is not an Inner List', () => {
    assert.throws(
      () => parseSignatureInput('sig1="@method";created=1618884473'),
      /must be an Inner List/,
    )
  })
})

describe('field adapter contract', () => {
  const request = new Request('https://example.com/')

  it('requires an adapter for trailers because Fetch does not expose them', () => {
    assert.throws(
      () => createSignatureBase(request, { components: [component('expires', { tr: true })] }),
      /Trailer field "expires" is not exposed by Fetch/,
    )
  })

  it('rejects an adapter that does not return an array', () => {
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: ['example'],
          fieldValues: () => 'value' as unknown as ReadonlyArray<string>,
        }),
      /"fieldValues" must return an array of strings or undefined/,
    )
  })

  it('rejects an adapter that returns a value that is not a string', () => {
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: ['example'],
          fieldValues: () => [1 as unknown as string],
        }),
      /"fieldValues" must return strings/,
    )
  })

  it('rejects a field value containing a newline', () => {
    assert.throws(
      () =>
        createSignatureBase(request, {
          components: ['example'],
          fieldValues: () => ['first\nsecond'],
        }),
      /HTTP field "example" contains a newline/,
    )
  })

  it('treats an empty array as an absent field', () => {
    assert.throws(
      () => createSignatureBase(request, { components: ['example'], fieldValues: () => [] }),
      /Header field "example" is not present/,
    )
  })
})

describe('signature chaining', () => {
  async function signedWithLabel(label: string, message: Request): Promise<Request> {
    return sign(message, {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
      label,
    })
  }

  it('covers an earlier signature through its Dictionary key', async () => {
    const first = await signedWithLabel('first', new Request('https://example.com/'))
    const second = await sign(first, {
      signer: webCryptoSigner(),
      components: ['@method', component('signature', { key: 'first' })],
      parameters: { created: RFC_CREATED },
      label: 'second',
    })

    assert.deepEqual(
      getSignatures(second).map(({ label }) => label),
      ['first', 'second'],
    )
    await assert.doesNotReject(
      verify(second, {
        verifier: webCryptoVerifier(),
        label: 'second',
        policy: verificationPolicy({
          requiredComponents: [component('signature', { key: 'first' })],
        }),
      }),
    )
    await assert.doesNotReject(
      verify(second, {
        verifier: webCryptoVerifier(),
        label: 'first',
        policy: verificationPolicy(),
      }),
    )
  })

  it('refuses to cover the fields the signature is being appended to', async () => {
    const first = await signedWithLabel('first', new Request('https://example.com/'))
    await assert.rejects(
      sign(first, {
        signer: webCryptoSigner(),
        components: ['signature'],
        parameters: { created: RFC_CREATED },
        label: 'second',
      }),
      /A signature cannot cover fields to which it is being appended/,
    )
  })

  it('refuses to reuse a label already present on the message', async () => {
    const first = await signedWithLabel('first', new Request('https://example.com/'))
    await assert.rejects(
      signedWithLabel('first', first),
      /Signature label "first" is already present/,
    )
  })
})

describe('recipient inspection', () => {
  it('reports no signatures for a message that carries neither field', () => {
    assert.deepEqual(getSignatures(new Request('https://example.com/')), [])
  })

  it('accepts expires without created', async () => {
    const signed = await sign(new Request('https://example.com/'), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: [
        ['created', false],
        ['expires', RFC_CREATED + 60],
      ],
    })
    assert.deepEqual(getSignatures(signed)[0]!.parameters, [['expires', RFC_CREATED + 60]])
    await assert.doesNotReject(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ requiredParameters: ['expires'] }),
      }),
    )
  })

  it('lets application policy match an expected tag', async () => {
    const signed = await sign(new Request('https://example.com/'), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED, tag: 'orders' },
    })
    const policy = (expected: string): VerificationPolicy =>
      verificationPolicy({
        requiredParameters: ['tag'],
        validate(signature) {
          const tag = signature.parameters.find(([name]) => name === 'tag')?.[1]
          assert.equal(typeof tag, 'string')
          if (tag !== expected) {
            throw new Error(`Unexpected signature tag "${String(tag)}"`)
          }
        },
      })

    await assert.doesNotReject(
      verify(signed, { verifier: webCryptoVerifier(), policy: policy('orders') }),
    )
    await assert.rejects(
      verify(signed, { verifier: webCryptoVerifier(), policy: policy('invoices') }),
      /Unexpected signature tag "orders"/,
    )
  })
})

describe('fetch wrapper edge cases', () => {
  it('reports a redirect that carries no signature', async () => {
    const signedFetch = createSignedFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      verify: { verifier: webCryptoVerifier(), policy: verificationPolicy() },
      fetch: (async () =>
        new Response(null, {
          status: 302,
          headers: { location: 'https://elsewhere.example/' },
        })) as typeof fetch,
    })

    await assert.rejects(
      signedFetch('https://example.com/'),
      /Message does not contain an HTTP message signature/,
    )
  })

  it('reports a label that the outgoing request already carries', async () => {
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
        label: 'tested',
      },
      fetch: (async () => new Response(null)) as typeof fetch,
    })

    await assert.rejects(
      signingFetch(await signedFixture()),
      /Signature label "tested" is already present/,
    )
  })

  it('keeps an explicitly configured redirect mode', async () => {
    let observed!: Request
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (input) => {
        observed = input as Request
        return new Response(null)
      }) as typeof fetch,
    })

    // Cloudflare Workers rejects redirect: 'error' outright, so only the modes the runtime can
    // represent are asserted. 'manual' is the one that matters: the wrapper must not touch it.
    for (const mode of ['error', 'manual'] as const) {
      try {
        new Request('https://example.com/', { redirect: mode })
      } catch {
        continue
      }
      await signingFetch('https://example.com/', { redirect: mode })
      assert.equal(observed.redirect, mode)
    }
  })
})

describe('Uint8Array base64 fallback', () => {
  const request = new Request('https://example.com/')

  function serialize(bytes: Uint8Array): string {
    const base = createSignatureBase(request, { components: [], parameters: [['p', bytes]] })
    return base.slice(base.indexOf('()') + '()'.length)
  }

  function parse(encoded: string): Uint8Array {
    return parseSignature(`sig1=:${encoded}:`)[0]!.signature
  }

  it('hides and restores the optional methods around a single call', () => {
    // Recorded rather than assumed, so that this file also runs on a runtime that never had them.
    const before = [
      Object.getOwnPropertyDescriptor(Uint8Array.prototype, 'toBase64'),
      Object.getOwnPropertyDescriptor(Uint8Array, 'fromBase64'),
    ]

    const inside = withoutUint8ArrayBase64(() => [
      typeof Uint8Array.prototype.toBase64,
      typeof Uint8Array.fromBase64,
    ])

    assert.deepEqual(inside, ['undefined', 'undefined'])
    assert.deepEqual(
      [
        Object.getOwnPropertyDescriptor(Uint8Array.prototype, 'toBase64'),
        Object.getOwnPropertyDescriptor(Uint8Array, 'fromBase64'),
      ],
      before,
    )
    assert.ok(!Object.keys(Uint8Array.prototype).includes('toBase64'))
  })

  it('serializes Byte Sequences identically with and without the methods', () => {
    const inputs = [
      new Uint8Array(),
      new Uint8Array([0]),
      new Uint8Array([0xff, 0xfe]),
      new Uint8Array([0x01, 0x02, 0x03]),
      // Exercises every byte value and both the padded and unpadded chunk lengths.
      Uint8Array.from({ length: 256 }, (_value, index) => index),
      // Larger than the chunk the fallback spreads into String.fromCharCode at a time.
      Uint8Array.from({ length: 0x2801 }, (_value, index) => index % 251),
    ]
    for (const bytes of inputs) {
      const expected = serialize(bytes)
      assert.equal(
        withoutUint8ArrayBase64(() => serialize(bytes)),
        expected,
        `${bytes.byteLength}`,
      )
    }
  })

  it('parses Byte Sequences identically with and without the methods', () => {
    // Padded, unpadded, and non-zero padding bits, which RFC 9651 lets a parser accept.
    for (const encoded of ['', 'AQ==', 'AQI=', 'AQID', 'aGVsbG8', 'AQI', 'iZ==', 'AQJ', '/+Ah']) {
      const expected = parse(encoded)
      assert.deepEqual(
        withoutUint8ArrayBase64(() => parse(encoded)),
        expected,
        encoded,
      )
    }
  })

  it('rejects the same malformed Byte Sequences without the methods', () => {
    // The whitespace cases matter most: both decoders skip ASCII whitespace on their own, so this
    // is the guard in front of them rather than the decoder being checked.
    for (const encoded of ['AQ I=', ' AQI=', 'AQI=\t', 'A', '=', 'A===', 'AB=', 'a-b_', 'AQI==']) {
      assert.throws(() => parse(encoded), /Invalid Structured Field Byte Sequence/, encoded)
      assert.throws(
        () => withoutUint8ArrayBase64(() => parse(encoded)),
        /Invalid Structured Field Byte Sequence/,
        encoded,
      )
    }
  })

  it('round trips a signature created and verified without the methods', async () => {
    const signature = await createSignature(request, {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })
    const signed = withoutUint8ArrayBase64(() => appendSignature(request, signature))
    assert.deepEqual(
      withoutUint8ArrayBase64(() => getSignatures(signed)[0]!.signature),
      signature.signature,
    )
    await assert.doesNotReject(
      verify(signed, { verifier: webCryptoVerifier(), policy: verificationPolicy() }),
    )
  })
})

describe('empty Structured Field Dictionary fields', () => {
  const request = () => rfcRequest()

  it('treats present-but-empty signature fields as carrying no signature', async () => {
    for (const empty of ['', ' ', '\t']) {
      const message = new Request(request(), {
        headers: new Headers({ 'signature-input': empty, signature: empty }),
      })
      assert.deepEqual(getSignatures(message), [])

      const signed = await sign(message, {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      })
      assert.equal(signed.headers.get('signature-input'), `sig1=("@method");created=${RFC_CREATED}`)
      await assert.doesNotReject(
        verify(signed, { verifier: webCryptoVerifier(), policy: verificationPolicy() }),
      )
    }
  })

  it('treats a present-but-empty accept-signature as carrying no request', () => {
    const message = new Request(request(), { headers: { 'accept-signature': '' } })
    assert.deepEqual(getSignatureRequests(message), [])

    const withRequest = appendAcceptSignature(message, [
      { label: 'response', components: ['@status'] },
    ])
    assert.equal(withRequest.headers.get('accept-signature'), 'response=("@status")')
  })

  it('still rejects two combined empty field lines, which are not a valid Dictionary', () => {
    const message = new Request(request(), { headers: { 'accept-signature': ', ' } })
    assert.throws(
      () => appendAcceptSignature(message, [{ label: 'response', components: ['@status'] }]),
      /Invalid Structured Field key/,
    )
  })
})

describe('null body status reconstruction', () => {
  // A response that came from the network can expose a body for a null body status: Node.js and
  // Deno report null, browsers and Bun report a stream. The Response constructor rejects a body for
  // those statuses everywhere, so the body has to be dropped rather than passed on.
  for (const status of [204, 205, 304]) {
    it(`drops the body of a status ${status} response that has one`, async () => {
      const withBody = {
        status,
        statusText: '',
        headers: new Headers({ 'content-type': 'application/json' }),
        body: new Response('{"ignored":true}').body,
      } as unknown as Response

      const signed = await sign(withBody, {
        signer: webCryptoSigner(),
        components: ['@status'],
        parameters: { created: RFC_CREATED },
      })
      assert.equal(signed.status, status)
      assert.equal(signed.body, null)
      assert.equal(signed.headers.get('content-type'), 'application/json')

      const negotiated = appendAcceptSignature(withBody, [
        { label: 'client', components: ['@method'] },
      ])
      assert.equal(negotiated.status, status)
      assert.equal(negotiated.body, null)
    })
  }
})

describe('target URI boundaries', () => {
  const message = (url: string) => ({ method: 'GET', url, headers: new Headers() }) as Request

  it('rejects a target URI carrying credentials', () => {
    // Node.js and browsers refuse to construct such a Request; Deno, Bun, and workerd do not, and
    // would otherwise place the password into the signature base.
    for (const url of ['https://user:s3cret@example.com/x', 'https://user@example.com/x']) {
      for (const name of ['@target-uri', '@authority', '@path', '@request-target']) {
        assert.throws(
          () => createSignatureBase(message(url), { components: [name] }),
          /Request target URI must not include credentials/,
          `${name} ${url}`,
        )
      }
    }
  })

  it('accepts an "@" that is not a userinfo delimiter', () => {
    assert.equal(
      createSignatureBase(message('https://example.com/@handle?to=me@example.com'), {
        components: ['@target-uri'],
      }).split('\n')[0],
      '"@target-uri": https://example.com/@handle?to=me@example.com',
    )
  })

  it('rejects the authority-derived components of a URI with no authority', () => {
    for (const url of ['data:text/plain,hi', 'blob:https://example.com/id']) {
      for (const name of ['@authority', '@path', '@request-target']) {
        assert.throws(
          () => createSignatureBase(message(url), { components: [name] }),
          /requires a target URI with an authority/,
          `${name} ${url}`,
        )
      }
    }
  })
})

describe('field value canonicalization', () => {
  const request = () => new Request('https://example.com/')

  it('collapses the whitespace on both sides of an obsolete line fold', () => {
    // RFC 9112 defines obs-fold as OWS CRLF RWS, so the whitespace before the CRLF is part of it.
    const cases: ReadonlyArray<readonly [string, string]> = [
      ['Obsolete\r\n    line folding.', 'Obsolete line folding.'],
      ['Obsolete \r\n    line folding.', 'Obsolete line folding.'],
      ['Obsolete \t \r\n\tline folding.', 'Obsolete line folding.'],
      ['a\r\n b\r\n  c', 'a b c'],
    ]
    for (const [raw, expected] of cases) {
      assert.equal(
        createSignatureBase(request(), { components: ['x-fold'], fieldValues: () => [raw] }).split(
          '\n',
        )[0],
        `"x-fold": ${expected}`,
        raw,
      )
    }
  })

  it('still rejects a CRLF that is not a fold', () => {
    assert.throws(
      () =>
        createSignatureBase(request(), { components: ['x-fold'], fieldValues: () => ['a\r\nb'] }),
      /contains a newline/,
    )
  })

  it('canonicalizes a long whitespace run in linear time', () => {
    // The trim used to be an unanchored regular expression alternation, which restarts at every
    // position: this input cost minutes of CPU before any signature was checked.
    const value = `y${'\t'.repeat(200_000)}x`
    const started = performance.now()
    assert.equal(
      createSignatureBase(request(), { components: ['x-pad'], fieldValues: () => [value] }).split(
        '\n',
      )[0],
      `"x-pad": ${value}`,
    )
    assert.ok(performance.now() - started < 1_000, 'field canonicalization is superlinear')
  })
})

describe('target URI derivation is memoized per signature base', () => {
  it('reads the request URL a fixed number of times regardless of component count', () => {
    // @query-param used to reparse the whole query string once per covered component, which made
    // signature base generation quadratic in the size of an attacker-supplied request.
    function countUrlReads(componentCount: number): number {
      let reads = 0
      const query = Array.from({ length: 64 }, (_, index) => `p${index}=${index}`).join('&')
      const message = {
        method: 'GET',
        headers: new Headers(),
        get url() {
          reads++
          return `https://example.com/x?${query}`
        },
      } as Request
      createSignatureBase(message, {
        components: Array.from({ length: componentCount }, (_, index) =>
          component('@query-param', [['name', `p${index}`]]),
        ),
      })
      return reads
    }

    assert.equal(countUrlReads(64), countUrlReads(1))
  })
})

describe('unspoofable value brands', () => {
  const request = () => new Request('https://example.com/')

  it('rejects a non-Uint8Array that claims the Uint8Array toStringTag', () => {
    // Object.prototype.toString consults Symbol.toStringTag, so a DataView could pose as a
    // Uint8Array and be copied into a silently wrong, empty Byte Sequence.
    const view = new DataView(new ArrayBuffer(8))
    Object.defineProperty(view, Symbol.toStringTag, { value: 'Uint8Array' })
    const floats = new Float64Array([1, 2, 300])
    Object.defineProperty(floats, Symbol.toStringTag, { value: 'Uint8Array' })

    for (const value of [view, floats]) {
      assert.throws(
        () =>
          createSignatureBase(request(), {
            components: [],
            parameters: [['example', value as unknown as Uint8Array]],
          }),
        /has an unsupported value/,
      )
    }

    assert.equal(
      createSignatureBase(request(), {
        components: [],
        parameters: [['example', new Uint8Array([1, 2, 3])]],
      }),
      '"@signature-params": ();example=:AQID:',
    )
  })

  it('rejects a non-Date that claims the Date toStringTag', () => {
    assert.throws(
      () => date({ [Symbol.toStringTag]: 'Date' } as unknown as Date),
      /"value" must be a number of UNIX seconds or a Date/,
    )
    assert.equal(date(new Date(1_659_578_233_000)).value, 1_659_578_233)
    assert.throws(() => date(Number.NaN), /Structured Field Date is out of range/)
  })
})

describe('verification policy snapshot', () => {
  it('validates and stores the same read of every policy member', async () => {
    // Reading a member twice would let an accessor return a different value than the one that
    // passed validation, which is exactly what snapshotting the policy is meant to prevent.
    const signed = await sign(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })

    let maxAgeReads = 0
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: {
          requiredComponents: [],
          requiredParameters: [],
          algorithms: ['hmac-sha256'],
          now: RFC_CREATED + 10_000,
          get maxAge() {
            maxAgeReads++
            return maxAgeReads <= 3 ? 60 : Number.NaN
          },
        },
      }),
      /older than policy permits/,
    )
    assert.equal(maxAgeReads, 1)

    let parametersReads = 0
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: {
          requiredComponents: [],
          algorithms: ['hmac-sha256'],
          now: RFC_CREATED,
          get requiredParameters() {
            parametersReads++
            return parametersReads <= 2 ? ['nonce'] : []
          },
        },
      }),
      /Required signature parameter "nonce" is missing/,
    )
    assert.equal(parametersReads, 1)
  })
})
