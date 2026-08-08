import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendAcceptSignature,
  getSignatureParameter,
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
  includesComponent,
  parseSignature,
  parseSignatureInput,
  sign,
  token,
  verify,
} from '../index.ts'
import type {
  MessageSignature,
  VerifyOptions,
  SignatureParameterInput,
  SignerFactory,
  SignOptions,
  StructuredFieldType,
  SynchronousVerifierFactory,
  VerificationPolicy,
  VerifierFactory,
} from '../index.ts'
import {
  bytesToBase64,
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
    // A browser strips Set-Cookie from a request outright, so the field reads as absent there
    // and coverage needs a fieldValues adapter instead. See guides/fetch.md.
    if (!request.headers.has('set-cookie')) {
      return
    }
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

/**
 * A deterministic synchronous stand-in for a signing primitive.
 *
 * Not cryptography. Web Cryptography has no synchronous interface, so exercising a synchronous
 * provider needs a synchronous primitive, and what these tests cover is the plumbing that accepts
 * one rather than the transform itself.
 */
function syncDigest(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const digest = new Uint8Array(32)
  for (const [index, byte] of data.entries()) {
    const slot = index % digest.length
    digest[slot] = (digest[slot]! + byte * 31 + index) % 251
  }
  return digest
}

const syncSigner: SignerFactory = () => ({
  type: 'signer',
  alg: 'sync-stub',
  sign(data) {
    return syncDigest(data)
  },
})

const syncVerifier: SynchronousVerifierFactory = () => ({
  type: 'verifier',
  alg: 'sync-stub',
  verify(data, signature) {
    return bytesToBase64(syncDigest(data)) === bytesToBase64(signature)
  },
})

const syncSignOptions: SignOptions = {
  signer: syncSigner,
  components: ['@method', '@authority', 'x-covered'],
  parameters: { created: RFC_CREATED, keyid: 'test-key', alg: 'sync-stub' },
  label: 'tested',
}

const syncPolicy = (overrides: Partial<VerificationPolicy> = {}): VerificationPolicy =>
  verificationPolicy({ algorithms: ['sync-stub'], ...overrides })

describe('synchronous providers', () => {
  it('returns the signature and the result without a Promise', () => {
    const data = encoder.encode('HTTP Message Signatures')
    const signature = syncDigest(data)
    assert.deepEqual(syncSigner().sign(data), signature)

    const result = syncVerifier(
      { label: 'tested', components: [], parameters: [], signature },
      { message: requestFixture() },
    ).verify(data, signature)
    // A boolean, not a Promise of one, so the provider never suspended.
    assert.equal(result, true)
  })

  it('round trips a signature through a synchronous signer and verifier', async () => {
    const signed = await sign(requestFixture(), syncSignOptions)
    const verified = await verify(signed, { verifier: syncVerifier, policy: syncPolicy() })

    assert.equal(verified.label, 'tested')
    assert.equal(verified.algorithm, 'sync-stub')
  })

  it('still fails verification when a covered component changed', async () => {
    const signed = await sign(requestFixture(), syncSignOptions)
    const tampered = new Request(signed, { headers: new Headers(signed.headers) })
    tampered.headers.set('x-covered', 'tampered')

    await assert.rejects(
      verify(tampered, { verifier: syncVerifier, policy: syncPolicy() }),
      /HTTP message signature verification failed/,
    )
  })

  it('applies the same output checks to a synchronous provider', async () => {
    await assert.rejects(
      createSignature(requestFixture(), {
        ...syncSignOptions,
        signer: () => ({ type: 'signer', alg: 'sync-stub', sign: () => 'not bytes' as never }),
      }),
      /Signer output must be a Uint8Array/,
    )

    const signed = await sign(requestFixture(), syncSignOptions)
    await assert.rejects(
      verify(signed, {
        verifier: () => ({ type: 'verifier', alg: 'sync-stub', verify: () => 1 as never }),
        policy: syncPolicy(),
      }),
      /Verifier output must be a boolean/,
    )
  })
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
            return (await webCryptoVerifier()(observed, { message: signed })).verify(
              data,
              signature,
            )
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

describe('covered component lookup', () => {
  it('matches a plain identifier and lowercases field names on both sides', () => {
    const covered = ['@method', 'X-Covered']

    assert.equal(includesComponent(covered, '@method'), true)
    assert.equal(includesComponent(covered, 'x-covered'), true)
    assert.equal(includesComponent(covered, 'X-COVERED'), true)
    assert.equal(includesComponent(covered, '@path'), false)
    assert.equal(includesComponent([], '@method'), false)
  })

  it('keeps derived component names case-sensitive', () => {
    // Only field names fold case. A derived name that arrived miscased matches nothing, and one
    // passed in as the identifier to look for is rejected outright.
    assert.equal(includesComponent(['@Method'], '@method'), false)
    assert.throws(() => includesComponent(['@method'], '@Method'), /Unknown derived component/)
  })

  it('requires the complete identifier, not just the name', () => {
    const bound = [component('@authority', { req: true })]

    assert.equal(includesComponent(bound, component('@authority', { req: true })), true)
    // The whole point of the helper: comparing names alone would call this covered.
    assert.equal(includesComponent(bound, '@authority'), false)
    assert.equal(includesComponent(['@authority'], component('@authority', { req: true })), false)
  })

  it('compares component parameters as an unordered set', () => {
    const covered = [
      component('example-dictionary', [
        ['key', 'member'],
        ['req', true],
      ]),
    ]

    assert.equal(
      includesComponent(
        covered,
        component('example-dictionary', [
          ['req', true],
          ['key', 'member'],
        ]),
      ),
      true,
    )
    assert.equal(
      includesComponent(covered, component('example-dictionary', { key: 'member' })),
      false,
    )
    assert.equal(
      includesComponent(covered, component('example-dictionary', { key: 'other', req: true })),
      false,
    )
  })

  it('reads the covered components of a parsed signature', async () => {
    const signed = await signedFixture()
    const { components } = getSignatures(signed)[0]!

    assert.equal(includesComponent(components, '@method'), true)
    assert.equal(includesComponent(components, 'x-covered'), true)
    assert.equal(includesComponent(components, 'x-uncovered'), false)
  })

  it('does not throw for an identifier that arrived on the wire', () => {
    // A peer controls its own Signature-Input, so a lookup against one must report a result rather
    // than reject the list. Neither of these names is one a covered component list may carry.
    const hostile = [{ name: '@signature-params', parameters: [] }, { name: '@bogus' }, 'X-Upper']

    assert.equal(includesComponent(hostile, '@method'), false)
    assert.equal(includesComponent(hostile, 'x-upper'), true)
  })

  it('rejects an invalid identifier to look for, and an invalid list', () => {
    assert.throws(() => includesComponent(['@method'], '@signature-params'), {
      name: 'TypeError',
      message: '"@signature-params" cannot be listed as a covered component',
    })
    assert.throws(() => includesComponent(['@method'], '@bogus'), /@bogus/)
    assert.throws(() => includesComponent(['@method'], 1 as never), {
      name: 'TypeError',
      message: 'Invalid HTTP message component identifier',
    })
    assert.throws(() => includesComponent('@method' as never, '@method'), {
      name: 'TypeError',
      message: '"components" must be an array',
    })
  })

  it('expresses an either-or coverage rule that requiredComponents cannot', async () => {
    const signed = await signedFixture()
    const policy = (allowed: ReadonlyArray<string>): VerificationPolicy =>
      verificationPolicy({
        validate(signature) {
          if (!allowed.some((name) => includesComponent(signature.components, name))) {
            throw new Error(`The signature covers none of ${allowed.join(', ')}`)
          }
        },
      })

    await assert.doesNotReject(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: policy(['@authority', '@target-uri']),
      }),
    )
    await assert.rejects(
      verify(signed, { verifier: webCryptoVerifier(), policy: policy(['@target-uri', '@query']) }),
      /covers none of @target-uri, @query/,
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
    // Node.js and browsers refuse to construct such a Request. Deno, Bun, and workerd do not, and
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

describe('asynchronous key selection', () => {
  it('rejects a message that changed while the key was being fetched', async () => {
    // A verifier factory that returns a Promise is a suspension point. The signature base is
    // rebuilt after it settles, so the guard has to sit after the factory rather than before it.
    // Covers a field a browser also lets script set, so this runs on every runtime.
    const signed = await sign(
      new Request('https://example.com/', { headers: { 'x-covered': 'original' } }),
      {
        signer: webCryptoSigner(),
        components: ['@method', 'x-covered'],
        parameters: { created: RFC_CREATED },
      },
    )
    const headers = new Headers(signed.headers)

    await assert.rejects(
      verify({ method: signed.method, url: signed.url, headers } as Request, {
        verifier: async (signature, context) => {
          await Promise.resolve()
          headers.set('x-covered', 'changed')
          return webCryptoVerifier()(signature, context)
        },
        policy: verificationPolicy(),
      }),
      /headers changed during signature verification/,
    )
  })
})

describe('linear-time boundary before verification', () => {
  // SECURITY.md commits to parsing, canonicalization, and signature base generation staying linear
  // in the size of the message, because a peer chooses that size and reaches this code before any
  // signature has been checked. Each case below was quadratic or worse.
  //
  // Where the repeated work is observable, a case counts it and asserts an exact number. Where it is
  // not, the case falls back to an elapsed-time bound, with an input sized so that the previous
  // behavior ran for tens of seconds against a bound of two or three. That is a blunt instrument, so
  // the bounds are deliberately far above the measured runtime rather than tight.

  it('reads a covered dictionary field once regardless of how many keys are covered', () => {
    function countFieldReads(keyCount: number): number {
      let reads = 0
      const dictionary = Array.from({ length: 64 }, (_, index) => `k${index}=${index}`).join(', ')

      createSignatureBase(new Request('https://example.com/'), {
        components: Array.from({ length: keyCount }, (_, index) =>
          component('x-dict', { key: `k${index}` }),
        ),
        fieldValues(_message, name) {
          if (name === 'x-dict') {
            reads++
            return [dictionary]
          }
          return undefined
        },
      })
      return reads
    }

    assert.equal(countFieldReads(64), countFieldReads(1))
  })

  it('parses a Dictionary with many unique members without a per-member scan', () => {
    // The ordered map preserved insertion order with a findIndex() per member, so a Signature-Input
    // carrying N distinct labels cost O(N^2). This input took about half a minute. It now takes
    // under a tenth of a second.
    const labels = 100_000
    const value = Array.from({ length: labels }, (_, index) => `s${index}=("@method")`).join(',')

    const started = performance.now()
    const parsed = parseSignatureInput(value)
    const elapsed = performance.now() - started

    assert.equal(parsed.length, labels)
    assert.equal(parsed[labels - 1]!.label, `s${labels - 1}`)
    assert.ok(elapsed < 3_000, `Dictionary parsing is superlinear (${elapsed.toFixed(0)}ms)`)
  })

  it('validates a long covered component list without comparing every pair', () => {
    // Every component used to be compared with every preceding one, even with no duplicates
    // present, so this input cost several seconds before verifier selection.
    const components = 60_000
    const inner = Array.from({ length: components }, (_, index) => `"x-h${index}"`).join(' ')

    const started = performance.now()
    const parsed = parseSignatureInput(`sig=(${inner});created=${RFC_CREATED}`)
    const elapsed = performance.now() - started

    assert.equal(parsed[0]!.components.length, components)
    assert.ok(elapsed < 2_000, `component validation is superlinear (${elapsed.toFixed(0)}ms)`)
  })

  it('pairs Signature-Input with Signature without scanning per label', () => {
    // getSignatures() located each label's signature with a find() over the Signature Dictionary, so
    // reversing the two label orders made the join quadratic. Both fields are peer-controlled and
    // are read before any signature has been verified.
    const labels = 40_000
    // Each label carries distinct bytes, so a positional zip pairs s0 with s39999 and fails the
    // assertions below instead of passing on identical values.
    const bytesFor = (index: number) =>
      new Uint8Array([index & 0xff, (index >> 8) & 0xff, (index >> 16) & 0xff])
    const inputs = Array.from({ length: labels }, (_, index) => `s${index}=("@method")`).join(',')
    const values = Array.from({ length: labels }, (_, index) => {
      const label = labels - 1 - index
      return `s${label}=:${bytesToBase64(bytesFor(label))}:`
    })

    const message = new Request('https://example.com/', {
      headers: { 'signature-input': inputs, signature: values.join(',') },
    })

    const started = performance.now()
    const signatures = getSignatures(message)
    const elapsed = performance.now() - started

    assert.equal(signatures.length, labels)
    assert.equal(signatures[0]!.label, 's0')
    // Every input must be paired with its own signature, not a positional neighbour.
    assert.deepEqual(signatures[0]!.signature, bytesFor(0))
    assert.deepEqual(signatures[labels - 1]!.signature, bytesFor(labels - 1))
    assert.ok(elapsed < 3_000, `signature pairing is superlinear (${elapsed.toFixed(0)}ms)`)
  })

  it('resolves many Dictionary keys from one field without reparsing it each time', () => {
    // Each covered key reparsed the whole field and then scanned it linearly, so covering N keys of
    // an N-member Dictionary was effectively cubic: this input took over a minute.
    const keys = 4_000
    const dictionary = Array.from({ length: keys }, (_, index) => `k${index}=${index}`).join(', ')
    const message = new Request('https://example.com/', { headers: { 'x-dict': dictionary } })

    const started = performance.now()
    const base = createSignatureBase(message, {
      components: Array.from({ length: keys }, (_, index) =>
        component('x-dict', { key: `k${index}` }),
      ),
    })
    const elapsed = performance.now() - started

    assert.ok(base.startsWith('"x-dict";key="k0": 0\n'))
    assert.ok(elapsed < 2_000, `Dictionary key resolution is superlinear (${elapsed.toFixed(0)}ms)`)
  })

  it('still rejects the duplicates the pairwise comparison caught', () => {
    assert.throws(
      () => parseSignatureInput('sig=("@method" "@method")'),
      /Duplicate covered component "@method"/,
    )
    // Parameter order must not make an identifier look distinct.
    assert.throws(
      () =>
        createSignatureBase(rfcRequest(), {
          components: [
            component('date', [
              ['sf', true],
              ['key', 'a'],
            ]),
            component('date', [
              ['key', 'a'],
              ['sf', true],
            ]),
          ],
          structuredFields: { date: 'dictionary' },
        }),
      /Duplicate covered component "date"/,
    )
    assert.throws(
      () => parseSignatureInput('sig=("example";key="a" "example";key="a";sf)'),
      /Duplicate covered dictionary key "example";key="a"/,
    )
  })
})

describe('request reconstruction preserves caller protections', () => {
  it('rejects a no-cors request rather than dropping the signature fields', async () => {
    // Fetch gives a no-cors request's headers the request-no-cors guard, and none of the fields this
    // package appends are CORS-safelisted, so a browser silently drops them. Signing would otherwise
    // resolve and hand back an unsigned request.
    const noCors = new Request('https://example.com/', { mode: 'no-cors' })

    // Cloudflare Workers does not expose Request.mode, so the mode a caller asked for cannot be
    // observed there. It also does not apply the guard, so the fields survive and signing is sound.
    if (noCors.mode !== 'no-cors') {
      assert.equal(noCors.mode, undefined)
      return
    }

    await assert.rejects(
      sign(noCors, {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      }),
      /"no-cors" request cannot carry HTTP message signatures/,
    )

    assert.throws(
      () => appendAcceptSignature(noCors, [{ label: 'sig', components: ['@status'] }]),
      /"no-cors" request cannot carry Accept-Signature/,
    )
  })

  it('carries the referrer and referrer policy through signing', async () => {
    // A non-empty RequestInit makes the Fetch constructor reset an inherited referrer to "client"
    // and its policy to the empty string, re-enabling a Referer the caller suppressed.
    const source = new Request('https://example.com/', {
      referrer: '',
      referrerPolicy: 'no-referrer',
    })

    const signed = await sign(source, {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })

    assert.equal(signed.referrer, source.referrer)
    assert.equal(signed.referrerPolicy, source.referrerPolicy)
  })
})

/**
 * Fails with a diagnostic instead of hanging when a promise that should settle does not.
 *
 * Several cases below deliberately use operations that never settle on their own, so that abort
 * handling is what resolves them. Without a bound, a regression would hang the whole run until an
 * outer CI timeout rather than reporting the test that broke.
 */
async function withinBound<T>(operation: Promise<T>, description: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${description} did not settle within 10s`)),
          10_000,
        )
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

describe('fetch wrapper resource and transport handling', () => {
  it('forwards runtime-specific transport options', async () => {
    // Node.js dispatcher, Deno client, Bun proxy/tls/unix. Whether one survives Request
    // reconstruction on its own varies by runtime, so they are forwarded either way. Dropping one
    // can open an ordinary connection where the caller required a proxy or a client certificate.
    let observed: RequestInit | undefined
    let calls = 0
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        calls++
        observed = init as RequestInit
        return new Response(null)
      }) as typeof fetch,
    })

    const proxy = { uri: 'http://proxy.example' }
    await signingFetch('https://example.com/', { proxy } as RequestInit)

    assert.equal(calls, 1)
    assert.equal((observed as unknown as { proxy: unknown }).proxy, proxy)
    // Standard members must not be forwarded: headers would replace the signature fields.
    assert.equal(Object.hasOwn(observed!, 'headers'), false)
    assert.equal(Object.hasOwn(observed!, 'method'), false)
  })

  it('omits the second argument entirely when there is nothing runtime-specific', async () => {
    let argumentCount = 0
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (...args: unknown[]) => {
        argumentCount = args.length
        return new Response(null)
      }) as unknown as typeof fetch,
    })

    await signingFetch('https://example.com/', { method: 'GET' })
    assert.equal(argumentCount, 1)
  })

  it('gives up on an abort while the signer is still pending', async () => {
    const controller = new AbortController()
    let transportCalls = 0

    const signingFetch = createSigningFetch({
      sign: {
        signer: () => ({
          type: 'signer',
          alg: 'test',
          sign() {
            // A stalled HSM or remote signer: never settles on its own.
            return new Promise<Uint8Array>(() => {})
          },
        }),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async () => {
        transportCalls++
        return new Response(null)
      }) as typeof fetch,
    })

    const pending = signingFetch('https://example.com/', { signal: controller.signal })
    controller.abort(new Error('caller gave up'))

    await assert.rejects(withinBound(pending, 'aborted signing'), /caller gave up/)
    assert.equal(transportCalls, 0)
  })

  it('rejects an already-aborted request without invoking the signer at all', async () => {
    // Starting the signer first would still reach a remote signing service or an HSM, even though
    // the transport is skipped and the result is thrown away.
    let factoryCalls = 0
    let signCalls = 0
    const signingFetch = createSigningFetch({
      sign: {
        signer: () => {
          factoryCalls++
          return {
            type: 'signer',
            alg: 'test',
            async sign() {
              signCalls++
              return new Uint8Array([1])
            },
          }
        },
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async () => new Response(null)) as typeof fetch,
    })

    await assert.rejects(
      signingFetch('https://example.com/', { signal: AbortSignal.abort(new Error('already')) }),
      /already/,
    )
    assert.equal(factoryCalls, 0)
    assert.equal(signCalls, 0)
  })

  it('cannot be steered through an own __proto__ member of the initializer', async () => {
    // Copying an own enumerable "__proto__" onto an ordinary object reaches the legacy prototype
    // setter instead of creating a property, installing the attacker's object as the forwarded
    // initializer's prototype. The implementation then reads method, headers, and the rest from it,
    // replacing them on the request that was just signed and dropping the signature fields.
    let observed!: Request
    let forwarded: RequestInit | undefined
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method', '@authority', '@path'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (input: Request, init?: RequestInit) => {
        forwarded = init
        observed = init === undefined ? input : new Request(input, init)
        return new Response(null)
      }) as unknown as typeof fetch,
    })

    const hostile = JSON.parse(
      '{"__proto__":{"headers":{"x-injected":"yes"},"method":"POST","proxy":"http://attacker.invalid"}}',
    ) as RequestInit

    await signingFetch('https://api.example/orders', hostile)

    assert.equal(observed.method, 'GET')
    assert.equal(observed.headers.get('x-injected'), null)
    assert.equal(observed.headers.has('signature'), true)
    assert.equal(observed.headers.has('signature-input'), true)

    // Nothing was forwarded at all here: the hostile member is the only own key, and the options on
    // the object it carries are not reachable by a property lookup on the initializer.
    assert.equal(forwarded, undefined)

    // With a genuine runtime option alongside it, an initializer is forwarded, and the hostile
    // member must be absent from it rather than merely inert. A consumer downstream may copy the
    // forwarded initializer onto an ordinary object, where assignment would reach the prototype
    // setter again.
    const mixed = JSON.parse(
      '{"__proto__":{"method":"POST"},"unix":"/var/run/api.sock"}',
    ) as RequestInit
    await signingFetch('https://api.example/orders', mixed)

    assert.equal(observed.method, 'GET')
    const mixedForwarded = forwarded as Record<string, unknown> | undefined
    assert.notEqual(mixedForwarded, undefined)
    assert.equal(Object.hasOwn(mixedForwarded!, '__proto__'), false)
    assert.equal(mixedForwarded!['unix'], '/var/run/api.sock')

    const copied: Record<string, unknown> = {}
    for (const name of Object.keys(mixedForwarded!)) {
      copied[name] = mixedForwarded![name]
    }
    assert.equal(Object.getPrototypeOf(copied), Object.prototype)
  })

  it('accepts a callable initializer carrying runtime options', async () => {
    // A function is an object and can carry dictionary members, which some runtimes read.
    let observed: Record<string, unknown> | undefined
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        observed = init as Record<string, unknown>
        return new Response(null)
      }) as typeof fetch,
    })

    const callable = Object.assign(() => {}, {
      unix: '/var/run/api.sock',
    }) as unknown as RequestInit
    await signingFetch('https://example.com/', callable)
    assert.equal(observed!['unix'], '/var/run/api.sock')
  })

  it('leaves the signed request exactly as the Fetch constructor built it', async () => {
    // The wrapper must not discover or normalize the initializer itself: whatever `new Request()`
    // makes of it is what gets signed. Inherited and non-enumerable members are the cases that
    // distinguish reading the dictionary the way Fetch does from enumerating the object.
    let observed!: Request
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (input: Request) => {
        observed = input
        return new Response(null)
      }) as unknown as typeof fetch,
    })

    const nonEnumerable = {} as RequestInit
    Object.defineProperty(nonEnumerable, 'method', { value: 'POST', enumerable: false })
    Object.defineProperty(nonEnumerable, 'headers', {
      value: { 'x-carried': 'yes' },
      enumerable: false,
    })
    await signingFetch('https://example.com/', nonEnumerable)
    assert.equal(observed.method, 'POST')
    assert.equal(observed.headers.get('x-carried'), 'yes')
    assert.equal(observed.headers.has('signature'), true)

    const inherited = Object.create({ method: 'PUT' }) as RequestInit
    await signingFetch('https://example.com/', inherited)
    assert.equal(observed.method, 'PUT')

    const controller = new AbortController()
    const inheritedSignal = Object.create({ signal: controller.signal }) as RequestInit
    await signingFetch('https://example.com/', inheritedSignal)
    assert.equal(observed.signal.aborted, false)
    controller.abort(new Error('propagated'))
    assert.equal(observed.signal.aborted, true)
  })

  it('does not enumerate the initializer before the request is built', async () => {
    // Object.keys() runs a Proxy's ownKeys and getOwnPropertyDescriptor traps, which Web IDL
    // dictionary conversion never does. Discovering extension members before construction would let
    // those traps change the message that is about to be signed.
    let observed!: Request
    let method = 'GET'
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (input: Request) => {
        observed = input
        return new Response(null)
      }) as unknown as typeof fetch,
    })

    const target = {} as RequestInit
    Object.defineProperty(target, 'method', { enumerable: false, get: () => method })
    const init = new Proxy(target, {
      ownKeys: (proxied) => {
        method = 'POST'
        return Reflect.ownKeys(proxied)
      },
    })

    await signingFetch('https://example.com/', init)
    assert.equal(observed.method, 'GET')
  })

  it('lets the implementation decide whether a failing transport option stops the request', async () => {
    // Whether a lookup failure matters depends on whether the active implementation asks for the
    // option, which cannot be inferred from its name: Bun reads proxy, tls, and unix, Node.js does
    // not implement any of them. Reading it here instead would either silently downgrade a required
    // proxy to an ordinary connection, or reject a request the implementation would have accepted.
    let reads = 0
    // A class getter lives on the prototype and is non-enumerable, which is the ordinary shape a
    // configuration object takes.
    class TransportOptions {
      get proxy(): never {
        reads++
        throw new Error('proxy unavailable')
      }
    }
    assert.equal(Object.hasOwn(new TransportOptions(), 'proxy'), false)

    // An implementation that consumes the option must see the failure before its transport proceeds.
    let dispatched = 0
    const consuming = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        void (init as Record<string, unknown> | undefined)?.['proxy']
        dispatched++
        return new Response(null)
      }) as typeof fetch,
    })

    await assert.rejects(
      consuming('https://example.com/', new TransportOptions() as RequestInit),
      /proxy unavailable/,
    )
    assert.equal(reads, 1, 'the consuming implementation reads it exactly once')
    assert.equal(dispatched, 0, 'the failure must precede the transport')

    // An implementation that does not know the option never evaluates it, so the request proceeds.
    reads = 0
    let observed!: Request
    const ignoring = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (input: Request) => {
        observed = input
        return new Response(null)
      }) as unknown as typeof fetch,
    })

    await ignoring('https://example.com/', new TransportOptions() as RequestInit)
    assert.equal(reads, 0, 'the wrapper itself must not read it')
    assert.equal(observed.headers.has('signature'), true)
  })

  it('treats an accessor descriptor with no getter as an accessor, not as data', async () => {
    // A data descriptor owns "value", while an accessor descriptor owns "get" and "set" even when both are
    // undefined. Classifying by the accessor values instead would snapshot this one, so redefining
    // the property before dispatch would no longer be visible.
    let seen: unknown
    let release!: () => void
    const blocked = new Promise<void>((resolve) => {
      release = resolve
    })
    const signingFetch = createSigningFetch({
      sign: {
        signer: () => ({
          type: 'signer',
          alg: 'test',
          async sign() {
            await blocked
            return new Uint8Array([1])
          },
        }),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        seen = (init as Record<string, unknown> | undefined)?.['proxy']
        return new Response(null)
      }) as typeof fetch,
    })

    const init = {} as RequestInit
    Object.defineProperty(init, 'proxy', {
      get: undefined,
      set: undefined,
      enumerable: true,
      configurable: true,
    })

    const pending = signingFetch('https://example.com/', init)
    await Promise.resolve()
    Object.defineProperty(init, 'proxy', { value: 'http://proxy.example', enumerable: true })
    release()
    await pending

    assert.equal(seen, 'http://proxy.example')
  })

  it('captures a transport option at invocation, not at dispatch', async () => {
    // fetch() reads its initializer at once. A caller that reuses one initializer and assigns to it
    // again while an earlier signature is still pending must see the earlier request keep the value
    // it was called with. Assigning undefined would otherwise turn a request that had to use a proxy
    // into a direct connection.
    for (const shape of ['own', 'inherited'] as const) {
      let release!: () => void
      const blocked = new Promise<void>((resolve) => {
        release = resolve
      })
      let seen: unknown
      const signingFetch = createSigningFetch({
        sign: {
          signer: () => ({
            type: 'signer',
            alg: 'test',
            async sign() {
              await blocked
              return new Uint8Array([1])
            },
          }),
          components: ['@method'],
          parameters: { created: RFC_CREATED },
        },
        fetch: (async (_input, init) => {
          seen = (init as Record<string, unknown> | undefined)?.['proxy']
          return new Response(null)
        }) as typeof fetch,
      })

      const original = { id: 'first' }
      const carrier = { proxy: original }
      const init = (shape === 'own' ? carrier : Object.create(carrier)) as RequestInit

      const pending = signingFetch('https://example.com/', init)
      await Promise.resolve()
      // Reuse the initializer for a later request while the first signature is still pending.
      carrier.proxy = { id: 'second' }
      release()
      await pending

      assert.equal(seen, original, shape)
    }
  })

  it('forwards an own enumerable option it does not know by name', async () => {
    // The generic scan is what carries an option this package has never heard of, including one a
    // runtime adds later. Every other case here uses a recognized name and would still pass without
    // it.
    let observed: Record<string, unknown> | undefined
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        observed = init as Record<string, unknown>
        return new Response(null)
      }) as typeof fetch,
    })

    const marker = { hops: 2 }
    await signingFetch('https://example.com/', { someFutureTransportOption: marker } as RequestInit)

    assert.equal(observed!['someFutureTransportOption'], marker)
  })

  it('reads an own-enumerable accessor against the caller as receiver', async () => {
    // The value is read with a plain Get on the caller's object, which is the operation Fetch
    // performs. Copying the property descriptor instead would rebind a getter to the forwarded
    // object, where the state it reads does not exist.
    let observed: Record<string, unknown> | undefined
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        observed = init as Record<string, unknown>
        return new Response(null)
      }) as typeof fetch,
    })

    const init = {} as RequestInit
    let receiverWasCaller = false
    Object.defineProperty(init, 'unix', {
      enumerable: true,
      get(this: unknown) {
        // Asserted on identity rather than on borrowed state, because any state held as another
        // own enumerable member would be forwarded too and would mask a rebound receiver.
        receiverWasCaller = this === init
        return receiverWasCaller ? '/var/run/api.sock' : undefined
      },
    })

    await signingFetch('https://example.com/', init)
    assert.equal(observed!['unix'], '/var/run/api.sock')
    assert.equal(receiverWasCaller, true)
  })

  it('forwards a non-enumerable protocol option', async () => {
    let observed: Record<string, unknown> | undefined
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        observed = init as Record<string, unknown>
        return new Response(null)
      }) as typeof fetch,
    })

    const init = {} as RequestInit
    Object.defineProperty(init, 'protocol', { value: 'http2', enumerable: false })

    await signingFetch('https://example.com/', init)
    assert.equal(observed!['protocol'], 'http2')
  })

  it('forwards runtime-only options that are inherited or non-enumerable', async () => {
    // A runtime reads its own fetch options with a plain property lookup, so an initializer can
    // carry them on a prototype or as a non-enumerable property and still work when passed to fetch
    // directly. Object.keys() cannot see either.
    let observed: Record<string, unknown> | undefined
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (_input, init) => {
        observed = init as Record<string, unknown>
        return new Response(null)
      }) as typeof fetch,
    })

    const inherited = Object.create({ unix: '/var/run/api.sock' }) as RequestInit
    await signingFetch('https://example.com/', inherited)
    assert.equal(observed!['unix'], '/var/run/api.sock')

    const hidden = {} as RequestInit
    Object.defineProperty(hidden, 'proxy', { value: 'http://proxy.example', enumerable: false })
    await signingFetch('https://example.com/', hidden)
    assert.equal(observed!['proxy'], 'http://proxy.example')
  })

  it('gives up on an abort raised after verification is already in flight', async () => {
    // The verifier signals that it has started and then never settles, so the abort below happens
    // after the abort listener is registered. Aborting from inside the verifier instead would be
    // observed by the post-startup signal check and would never exercise the listener.
    const signed = await sign(new Response('body'), {
      signer: webCryptoSigner(undefined, 'test'),
      components: ['@status'],
      parameters: { created: RFC_CREATED },
    })

    for (const wrapper of ['verifying', 'signed'] as const) {
      const controller = new AbortController()
      let verifierCalls = 0
      let cancelled = false
      let started!: () => void
      const inFlight = new Promise<void>((resolve) => {
        started = resolve
      })
      const body = new ReadableStream<Uint8Array>({
        cancel() {
          cancelled = true
        },
      })
      const response = new Response(body, { headers: signed.headers })

      const verify: VerifyOptions = {
        verifier: () => ({
          type: 'verifier',
          alg: 'test',
          verify() {
            verifierCalls++
            started()
            return new Promise<boolean>(() => {})
          },
        }),
        policy: verificationPolicy({ algorithms: ['test'] }),
      }
      const transport = (async () => response) as typeof fetch

      const wrapped =
        wrapper === 'verifying'
          ? createVerifyingFetch({ verify, fetch: transport })
          : createSignedFetch({
              sign: {
                signer: webCryptoSigner(),
                components: ['@method'],
                parameters: { created: RFC_CREATED },
              },
              verify,
              fetch: transport,
            })

      const pending = wrapped('https://example.com/', { signal: controller.signal })
      await withinBound(inFlight, `${wrapper} verifier start`)
      controller.abort(new Error('caller gave up'))

      // No custom message: it would replace the "did not settle" diagnostic withinBound raises.
      await assert.rejects(withinBound(pending, `${wrapper} abort`), /caller gave up/)
      assert.equal(verifierCalls, 1, wrapper)
      assert.equal(cancelled, true, wrapper)
    }
  })

  it('cancels a response that was still locked when the abort won', async () => {
    // The verifier holds a reader when abort wins, so the immediate cleanup must skip the locked
    // stream. Once the losing verification settles and releases the lock, the response is still
    // undelivered and has to be released then.
    const signed = await sign(new Response('body'), {
      signer: webCryptoSigner(undefined, 'test'),
      components: ['@status'],
      parameters: { created: RFC_CREATED },
    })

    for (const [wrapper, outcome] of [
      ['verifying', 'fulfils'],
      ['verifying', 'rejects'],
      ['signed', 'fulfils'],
      ['signed', 'rejects'],
    ] as const) {
      const label = `${wrapper}/${outcome}`
      const controller = new AbortController()
      let cancelled!: () => void
      const wasCancelled = new Promise<void>((resolve) => {
        cancelled = resolve
      })
      let started!: () => void
      let release!: () => void
      const inFlight = new Promise<void>((resolve) => {
        started = resolve
      })
      const finish = new Promise<void>((resolve) => {
        release = resolve
      })
      const body = new ReadableStream<Uint8Array>({
        start(streamController) {
          streamController.enqueue(new Uint8Array([1]))
        },
        cancel() {
          cancelled()
        },
      })
      const response = new Response(body, { headers: signed.headers })

      const verify: VerifyOptions = {
        verifier: () => ({
          type: 'verifier',
          alg: 'test',
          async verify() {
            const reader = response.body!.getReader()
            await reader.read()
            started()
            // Still holding the lock when the abort lands.
            await finish
            reader.releaseLock()
            // Both arms must retry the cancellation: the losing verification can settle either way.
            if (outcome === 'rejects') {
              throw new Error('verifier failed after losing')
            }
            return true
          },
        }),
        policy: verificationPolicy({ algorithms: ['test'] }),
      }
      const transport = (async () => response) as typeof fetch

      const wrapped =
        wrapper === 'verifying'
          ? createVerifyingFetch({ verify, fetch: transport })
          : createSignedFetch({
              sign: {
                signer: webCryptoSigner(),
                components: ['@method'],
                parameters: { created: RFC_CREATED },
              },
              verify,
              fetch: transport,
            })

      const pending = wrapped('https://example.com/', { signal: controller.signal })
      await withinBound(inFlight, `${label} reader acquired`)
      controller.abort(new Error('caller gave up'))
      await assert.rejects(withinBound(pending, `${label} abort`), /caller gave up/)

      let cancelledEarly = false
      void wasCancelled.then(() => {
        cancelledEarly = true
      })
      await Promise.resolve()
      assert.equal(cancelledEarly, false, `${label}: a locked body must not be cancelled yet`)

      release()
      // Awaited rather than timed: the retry runs once the losing verification settles.
      await withinBound(wasCancelled, `${label} cancellation after release`)
    }
  })

  it('observes an abort raised synchronously while the signer is being created', async () => {
    // The factory runs while the operation is starting, before any abort listener exists, and an
    // abort event is not replayed to a listener added afterwards.
    const controller = new AbortController()
    let transportCalls = 0

    const signingFetch = createSigningFetch({
      sign: {
        signer: () => {
          controller.abort(new Error('aborted during setup'))
          return { type: 'signer', alg: 'test', sign: () => new Promise<Uint8Array>(() => {}) }
        },
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async () => {
        transportCalls++
        return new Response(null)
      }) as typeof fetch,
    })

    await assert.rejects(
      withinBound(
        signingFetch('https://example.com/', { signal: controller.signal }),
        'signing aborted during setup',
      ),
      /aborted during setup/,
    )
    assert.equal(transportCalls, 0)
  })

  it('cancels a response body that verification already read from', async () => {
    // A disturbed stream is still cancellable while unlocked, and cancelling is what releases the
    // connection, so a verifier that read a chunk must not leave the body dangling.
    let cancelled = false
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1]))
      },
      cancel() {
        cancelled = true
      },
    })

    const signed = await sign(new Response(null), {
      signer: webCryptoSigner(undefined, 'test'),
      components: ['@status'],
      parameters: { created: RFC_CREATED },
    })

    const verifyingFetch = createVerifyingFetch({
      verify: {
        verifier: () => ({
          type: 'verifier',
          alg: 'test',
          async verify(_data, _signature) {
            return false
          },
        }),
        policy: verificationPolicy({ algorithms: ['test'] }),
      },
      fetch: (async () => {
        const response = new Response(body, { headers: signed.headers })
        const reader = response.body!.getReader()
        await reader.read()
        reader.releaseLock()
        return response
      }) as typeof fetch,
    })

    await assert.rejects(verifyingFetch('https://example.com/'), /verification failed/)
    assert.equal(cancelled, true)
  })

  it('does not block the verification error on an unresponsive body cancel', async () => {
    // cancel() is allowed to reject, and nothing requires it to settle. Awaiting it would hold back
    // the error the caller is waiting for indefinitely.
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        return new Promise<void>(() => {})
      },
    })

    const verifyingFetch = createVerifyingFetch({
      verify: { verifier: webCryptoVerifier(), policy: verificationPolicy() },
      fetch: (async () => new Response(body)) as typeof fetch,
    })

    await assert.rejects(
      withinBound(
        verifyingFetch('https://example.com/'),
        'verification with an unresponsive cancel',
      ),
      /does not contain an HTTP message signature/,
    )
  })

  it('cancels an unverified response body so the transport can be released', async () => {
    let cancelled = false
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array([1]))
      },
      cancel() {
        cancelled = true
      },
    })

    const verifyingFetch = createVerifyingFetch({
      verify: { verifier: webCryptoVerifier(), policy: verificationPolicy() },
      fetch: (async () => new Response(body)) as typeof fetch,
    })

    await assert.rejects(
      verifyingFetch('https://example.com/'),
      /does not contain an HTTP message signature/,
    )
    assert.equal(cancelled, true)
  })

  it('leaves the response owned by the caller when verify() is used directly', async () => {
    // verify() is non-owning: its caller still holds the response and decides what to do with it.
    let cancelled = false
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true
      },
    })
    const response = new Response(body)

    await assert.rejects(
      verify(response, { verifier: webCryptoVerifier(), policy: verificationPolicy() }),
      /does not contain an HTTP message signature/,
    )
    assert.equal(cancelled, false)
    assert.equal(response.bodyUsed, false)
  })
})
