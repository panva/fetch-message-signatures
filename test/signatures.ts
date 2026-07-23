import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  appendSignature,
  component,
  createSigningFetch,
  createSignedFetch,
  createSignature,
  createSignatureBase,
  createVerifyingFetch,
  decimal,
  getSignatures,
  parseSignature,
  parseSignatureInput,
  sign,
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

function signedHeaders(signatureInput: string | null, signature: string | null): Request {
  const headers = new Headers()
  if (signatureInput !== null) {
    headers.set('signature-input', signatureInput)
  }
  if (signature !== null) {
    headers.set('signature', signature)
  }
  return new Request('https://example.com/', { headers })
}

describe('signature field parsing and pairing', () => {
  it('parses ordered components, parameters, tokens, and byte sequences', () => {
    assert.deepEqual(
      parseSignatureInput(
        'sig1=("@method" "content-type"; sf "cache-control";   sf); created=1618884473;   alg="hmac-sha256"; custom=thing;   decimal=1.0',
      ),
      [
        {
          label: 'sig1',
          components: [
            { name: '@method', parameters: [] },
            { name: 'content-type', parameters: [['sf', true]] },
            { name: 'cache-control', parameters: [['sf', true]] },
          ],
          parameters: [
            ['created', RFC_CREATED],
            ['alg', 'hmac-sha256'],
            ['custom', token('thing')],
            ['decimal', decimal(1)],
          ],
        },
      ],
    )
    assert.deepEqual(parseSignature('sig1=:AAEC:;when=@1659578233;title=%"snowman %e2%98%83"'), [
      { label: 'sig1', signature: new Uint8Array([0, 1, 2]) },
    ])
  })

  it('rejects malformed Signature-Input and Signature members', () => {
    const invalidInputs = [
      'sig1=?1',
      'sig1=@1659578233',
      'sig1=%"display"',
      'sig1=(token)',
      'sig1=(@1659578233)',
      'sig1=(%"display")',
      'sig1=("@unknown")',
      'sig1=("@method";unknown=1)',
      'sig1=("@method";unknown=@1659578233)',
      'sig1=("@method";unknown=%"display")',
      'sig1=("@method");\tcreated=1618884473',
      'sig1=("@method"',
    ]
    for (const value of invalidInputs) {
      assert.throws(() => parseSignatureInput(value), TypeError, value)
    }

    const invalidSignatures = [
      'sig1="not bytes"',
      'sig1=@1659578233',
      'sig1=%"display"',
      'sig1=:***:',
      'sig1=:AA==',
      'sig1=:AA==:;\textension',
    ]
    for (const value of invalidSignatures) {
      assert.throws(() => parseSignature(value), TypeError, value)
    }
  })

  it('accepts and ignores extension parameters on Signature Byte Sequences', () => {
    assert.deepEqual(parseSignature('sig1=:AAEC:; ext=1;   flag'), [
      { label: 'sig1', signature: new Uint8Array([0, 1, 2]) },
    ])
  })

  it('rejects duplicate dictionary labels and equivalent duplicate components', async () => {
    assert.throws(
      () => parseSignatureInput('sig1=("@method"), sig1=("@path")'),
      /Duplicate Structured Field Dictionary key "sig1"/,
    )
    assert.throws(
      () => parseSignature('sig1=:AA==:, sig1=:AQ==:'),
      /Duplicate Structured Field Dictionary key "sig1"/,
    )
    assert.throws(
      () => parseSignatureInput('sig1=("example";sf;tr "example";tr;sf)'),
      /Duplicate covered component "example"/,
    )
    assert.throws(
      () =>
        createSignatureBase(rfcRequest(), {
          components: [component('date', { sf: true }), component('DATE', { sf: true })],
          structuredFields: { date: 'item' },
        }),
      /Duplicate covered component "date"/,
    )

    const duplicateKeyComponents = [
      component('example', { key: 'a' }),
      component('example', [
        ['key', 'a'],
        ['sf', true],
      ]),
    ]
    assert.throws(
      () =>
        createSignatureBase(new Request('https://example.com/', { headers: { example: 'a=1' } }), {
          components: duplicateKeyComponents,
        }),
      /Duplicate covered dictionary key "example";key="a"/,
    )
    assert.throws(
      () => parseSignatureInput('sig1=("example";key="a" "example";key="a";sf);created=1618884473'),
      /Duplicate covered dictionary key "example";key="a"/,
    )
    await assert.rejects(
      verify(
        signedHeaders(
          'sig1=("example";key="a" "example";key="a";sf);created=1618884473',
          'sig1=:AA==:',
        ),
        { verifier: webCryptoVerifier(), policy: verificationPolicy() },
      ),
      /Duplicate covered dictionary key "example";key="a"/,
    )
  })

  it('allows the same dictionary key from distinct request, header, and trailer contexts', () => {
    const request = new Request('https://example.com/', { headers: { example: 'a=1' } })
    const response = new Response(null, { headers: { example: 'a=2' } })
    assert.equal(
      createSignatureBase(response, {
        request,
        components: [
          component('example', { key: 'a' }),
          component('example', [
            ['key', 'a'],
            ['req', true],
          ]),
        ],
      }),
      [
        '"example";key="a": 2',
        '"example";key="a";req: 1',
        '"@signature-params": ("example";key="a" "example";key="a";req)',
      ].join('\n'),
    )

    assert.equal(
      createSignatureBase(request, {
        components: [
          component('example', { key: 'a' }),
          component('example', [
            ['key', 'a'],
            ['tr', true],
          ]),
        ],
        fieldValues(_message, name, context) {
          if (name === 'example') {
            return [context.trailers ? 'a=3' : 'a=1']
          }
          return undefined
        },
      }),
      [
        '"example";key="a": 1',
        '"example";key="a";tr: 3',
        '"@signature-params": ("example";key="a" "example";key="a";tr)',
      ].join('\n'),
    )
  })

  it('rejects missing or mismatched Signature and Signature-Input fields', () => {
    assert.throws(
      () => getSignatures(signedHeaders('sig1=("@method")', null)),
      /must both be present/,
    )
    assert.throws(() => getSignatures(signedHeaders(null, 'sig1=:AA==:')), /must both be present/)
    assert.throws(
      () => getSignatures(signedHeaders('sig1=("@method")', 'different=:AA==:')),
      /must contain identical labels/,
    )
  })
})

describe('multiple signatures', () => {
  it('appends, parses, and independently verifies distinct labels', async () => {
    const first = await sign(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method', '@authority'],
      parameters: { created: RFC_CREATED, keyid: 'first-key' },
      label: 'first',
    })
    const second = await sign(first, {
      signer: webCryptoSigner(),
      components: ['date', '@path'],
      parameters: { created: RFC_CREATED, keyid: 'second-key' },
      label: 'second',
    })

    assert.deepEqual(
      getSignatures(second).map(({ label }) => label),
      ['first', 'second'],
    )
    await assert.rejects(
      verify(second, { verifier: webCryptoVerifier(), policy: verificationPolicy() }),
      /"label" is required/,
    )
    assert.equal(
      (
        await verify(second, {
          label: 'first',
          verifier: webCryptoVerifier(undefined, 'first-key'),
          policy: verificationPolicy({ requiredComponents: ['@method', '@authority'] }),
        })
      ).label,
      'first',
    )
    assert.equal(
      (
        await verify(second, {
          label: 'second',
          verifier: webCryptoVerifier(undefined, 'second-key'),
          policy: verificationPolicy({ requiredComponents: ['date', '@path'] }),
        })
      ).label,
      'second',
    )
    await assert.rejects(
      verify(second, {
        label: 'missing',
        verifier: webCryptoVerifier(),
        policy: verificationPolicy(),
      }),
      /does not contain signature label "missing"/,
    )
  })

  it('rejects reuse of an existing label', async () => {
    const signed = await sign(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
      label: 'same',
    })
    await assert.rejects(
      createSignature(signed, {
        signer: webCryptoSigner(),
        components: ['@path'],
        parameters: { created: RFC_CREATED },
        label: 'same',
      }),
      /Signature label "same" is already present/,
    )
  })

  it('validates one-member fields passed to appendSignature', async () => {
    const fields = await createSignature(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
      label: 'expected',
    })
    assert.throws(
      () =>
        appendSignature(rfcRequest(), {
          ...fields,
          signatureInput: fields.signatureInput.replace('expected=', 'different='),
        }),
      /exactly one matching signature label/,
    )
  })

  it('preserves a response body in the signed output', async () => {
    const response = new Response('response body')
    const fields = await createSignature(response, {
      signer: webCryptoSigner(),
      components: ['@status'],
      parameters: { created: RFC_CREATED },
    })
    const signed = appendSignature(response, fields)

    assert.equal(await signed.text(), 'response body')
    try {
      assert.equal(await response.text(), 'response body')
    } catch (error) {
      assert.ok(error instanceof TypeError)
    }
  })

  it('preserves a request body in the signed output', async () => {
    const request = new Request('https://example.com/', { method: 'POST', body: 'request body' })
    const signed = await sign(request, {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })

    assert.equal(await signed.text(), 'request body')
    try {
      assert.equal(await request.text(), 'request body')
    } catch (error) {
      assert.ok(error instanceof TypeError)
    }
  })

  it('can cover signature fields from a related request', async () => {
    const request = new Request('https://example.com/', {
      headers: { 'signature-input': 'client=("@method")', signature: 'client=:AA==:' },
    })
    const fields = await createSignature(new Response(null), {
      request,
      signer: webCryptoSigner(),
      components: [component('signature', { req: true })],
      parameters: { created: RFC_CREATED },
    })

    assert.deepEqual(fields.components, [{ name: 'signature', parameters: [['req', true]] }])
  })

  it('verifies a selected signature without interpreting unrelated signatures', async () => {
    const signed = await sign(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
      label: 'good',
    })
    const headers = new Headers(signed.headers)
    headers.set(
      'signature-input',
      `${headers.get('signature-input')}, future=("@future-component")`,
    )
    headers.set('signature', `${headers.get('signature')}, future=:AA==:`)
    const mixed = new Request(signed, { headers })

    await assert.doesNotReject(
      verify(mixed, {
        label: 'good',
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ requiredComponents: ['@method'] }),
      }),
    )
    assert.throws(() => getSignatures(mixed), /Unknown derived component/)
  })
})

describe('verification policy and timestamps', () => {
  async function policyFixture(
    parameters: Record<string, string | number | boolean>,
  ): Promise<Request> {
    return sign(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method', '@authority'],
      parameters,
      label: 'policy',
    })
  }

  it('requires configured components, parameters, and algorithms', async () => {
    const signed = await policyFixture({ created: RFC_CREATED, keyid: 'key', alg: 'hmac-sha256' })

    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ requiredComponents: ['@path'] }),
      }),
      /Required component "@path" is not covered/,
    )
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ requiredParameters: ['nonce'] }),
      }),
      /Required signature parameter "nonce" is missing/,
    )
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ algorithms: ['ed25519'] }),
      }),
      /Algorithm "hmac-sha256" is not allowed/,
    )
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(undefined, undefined, 'different-alg'),
        policy: verificationPolicy({ algorithms: ['different-alg', 'hmac-sha256'] }),
      }),
      /does not match the "alg" signature parameter/,
    )
  })

  it('uses an algorithm identifier added to the extensible registry', async () => {
    const algorithm = 'future-example-alg'
    const message = rfcRequest()
    const fields = await createSignature(message, {
      signer: webCryptoSigner(undefined, algorithm),
      components: ['@method', '@authority'],
      parameters: { created: RFC_CREATED, keyid: 'future-key', alg: algorithm },
      label: 'future',
    })

    assert.deepEqual(parseSignatureInput(fields.signatureInput)[0], {
      label: 'future',
      components: [
        { name: '@method', parameters: [] },
        { name: '@authority', parameters: [] },
      ],
      parameters: [
        ['created', RFC_CREATED],
        ['keyid', 'future-key'],
        ['alg', algorithm],
      ],
    })

    const signed = appendSignature(message, fields)
    assert.equal(
      getSignatures(signed)[0]?.parameters.find(([name]) => name === 'alg')?.[1],
      algorithm,
    )

    const verified = await verify(signed, {
      verifier: webCryptoVerifier(undefined, 'future-key', algorithm),
      policy: verificationPolicy({
        requiredComponents: ['@method', '@authority'],
        requiredParameters: ['created', 'keyid', 'alg'],
        algorithms: [algorithm],
      }),
    })
    assert.equal(verified.algorithm, algorithm)

    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(undefined, 'future-key', 'different-algorithm'),
        policy: verificationPolicy({ algorithms: [algorithm, 'different-algorithm'] }),
      }),
      /does not match the "alg" signature parameter/,
    )
  })

  it('enforces creation, expiration, maximum age, and clock skew', async () => {
    const future = await policyFixture({ created: 1_100 })
    await assert.rejects(
      verify(future, { verifier: webCryptoVerifier(), policy: verificationPolicy({ now: 1_000 }) }),
      /created in the future/,
    )
    await assert.doesNotReject(
      verify(future, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000, clockSkew: 100 }),
      }),
    )

    const expired = await policyFixture({ created: 800, expires: 990 })
    await assert.rejects(
      verify(expired, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000 }),
      }),
      /has expired/,
    )
    await assert.doesNotReject(
      verify(expired, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000, clockSkew: 10 }),
      }),
    )

    const invalidRange = await policyFixture({ created: 1_000, expires: 999 })
    await assert.rejects(
      verify(invalidRange, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000, clockSkew: 10 }),
      }),
      /expires before it was created/,
    )

    const old = await policyFixture({ created: 800 })
    await assert.rejects(
      verify(old, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000, maxAge: 199 }),
      }),
      /older than policy permits/,
    )
    await assert.doesNotReject(
      verify(old, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000, maxAge: 190, clockSkew: 10 }),
      }),
    )
  })

  it('requires created when maxAge is configured', async () => {
    const signed = await policyFixture({ created: false })
    await assert.rejects(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: verificationPolicy({ now: 1_000, maxAge: 10 }),
      }),
      /requires the "created" signature parameter/,
    )
  })

  it('runs additional application policy after cryptographic verification', async () => {
    const signed = await policyFixture({ created: RFC_CREATED, nonce: 'not-seen-before' })
    let verifiedCryptographically = false
    await assert.rejects(
      verify(signed, {
        verifier(_signature, context) {
          assert.equal(context.message, signed)
          assert.equal(context.request, undefined)
          return {
            type: 'verifier',
            alg: 'hmac-sha256',
            async verify() {
              verifiedCryptographically = true
              return true
            },
          }
        },
        policy: verificationPolicy({
          validate(signature, context) {
            assert.equal(
              signature.parameters.find(([name]) => name === 'nonce')?.[1],
              'not-seen-before',
            )
            assert.equal(context.message, signed)
            assert.equal(context.algorithm, 'hmac-sha256')
            throw new Error('replayed nonce')
          },
        }),
      }),
      /replayed nonce/,
    )
    assert.equal(verifiedCryptographically, true)
  })

  it('does not run additional application policy for an invalid signature', async () => {
    const signed = await policyFixture({ created: RFC_CREATED, nonce: 'not-authenticated' })
    let policyCalled = false
    await assert.rejects(
      verify(signed, {
        verifier() {
          return {
            type: 'verifier',
            alg: 'hmac-sha256',
            async verify() {
              return false
            },
          }
        },
        policy: verificationPolicy({
          async validate() {
            policyCalled = true
          },
        }),
      }),
      /HTTP message signature verification failed/,
    )
    assert.equal(policyCalled, false)
  })

  it('adds created by default and permits explicit omission', async () => {
    const withCreated = await createSignature(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      now: 1234,
    })
    assert.deepEqual(withCreated.parameters, [['created', 1234]])

    const withoutCreated = await createSignature(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: false },
      now: 1234,
    })
    assert.deepEqual(withoutCreated.parameters, [])

    const undefinedCreated = await createSignature(rfcRequest(), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: undefined },
      now: 1234,
    })
    assert.deepEqual(undefinedCreated.parameters, [['created', 1234]])

    await assert.rejects(
      createSignature(rfcRequest(), {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: [
          ['created', false],
          ['created', undefined],
        ],
      }),
      /Duplicate signature parameter "created"/,
    )
  })

  it('rejects signer algorithm signaling mismatches', async () => {
    await assert.rejects(
      createSignature(rfcRequest(), {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED, alg: 'ed25519' },
      }),
      /signer algorithm does not match/,
    )
  })

  it('applies cheap policy requirements before resolving a key', async () => {
    const signed = await policyFixture({ created: RFC_CREATED })
    let resolverCalled = false
    await assert.rejects(
      verify(signed, {
        verifier() {
          resolverCalled = true
          return {
            type: 'verifier',
            alg: 'hmac-sha256',
            async verify() {
              return true
            },
          }
        },
        policy: verificationPolicy({ requiredComponents: ['@path'] }),
      }),
      /Required component "@path" is not covered/,
    )
    assert.equal(resolverCalled, false)
  })
})

describe('signer output ownership', () => {
  it('copies the signer output so a later mutation cannot change the fields', async () => {
    let output!: Uint8Array
    const fields = await createSignature(rfcRequest(), {
      signer: () => ({
        type: 'signer',
        alg: 'test',
        async sign() {
          output = new Uint8Array([1, 2, 3])
          return output
        },
      }),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })

    output.fill(0)
    assert.deepEqual(fields.signature, new Uint8Array([1, 2, 3]))
  })
})

describe('fetch wrappers', () => {
  it('validates directional wrapper configuration synchronously', () => {
    assert.throws(() => createSigningFetch(null as never), /"options" must be an object/)
    assert.throws(() => createSigningFetch({} as never), /"options.sign" must be an object/)
    assert.throws(() => createVerifyingFetch(null as never), /"options" must be an object/)
    assert.throws(() => createVerifyingFetch({} as never), /"options.verify" must be an object/)
    assert.throws(
      () =>
        createSigningFetch({
          sign: { signer: webCryptoSigner(), components: [] },
          fetch: 1 as never,
        }),
      /"options.fetch" must be a Fetch implementation/,
    )
  })

  it('signs requests and uses manual redirects without retaining response verification', async () => {
    let observed!: Request
    const signingFetch = createSigningFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async (input) => {
        observed = input as Request
        return new Response(null, { status: 302, headers: { location: '/next' } })
      }) as typeof fetch,
    })

    await signingFetch('https://example.com/')
    assert.equal(observed.redirect, 'manual')
    assert.ok(observed.headers.has('signature'))
  })

  it('verifies responses against unsigned requests and uses manual redirects', async () => {
    const components = ['@status', component('@method', { req: true })]
    let observed!: Request
    let returned!: Response
    const verifier = webCryptoVerifier()
    const verifyingFetch = createVerifyingFetch({
      verify: {
        verifier(signature, context) {
          assert.equal(context.request, observed)
          return verifier(signature, context)
        },
        policy: verificationPolicy({ requiredComponents: components }),
      },
      fetch: (async (input) => {
        observed = input as Request
        returned = await sign(new Response(null, { status: 204 }), {
          request: observed,
          signer: webCryptoSigner(),
          components,
          parameters: { created: RFC_CREATED },
        })
        return returned
      }) as typeof fetch,
    })

    const response = await verifyingFetch('https://example.com/', { method: 'POST' })

    assert.equal(response.status, 204)
    assert.equal(response, returned)
    assert.equal(observed.method, 'POST')
    assert.equal(observed.redirect, 'manual')
    assert.equal(observed.headers.has('signature'), false)
  })

  it('verifies combined responses against the exact signed request', async () => {
    const responseComponents = [component('signature', { req: true })]
    let observed!: Request
    let returned!: Response
    const verifier = webCryptoVerifier()
    const signedFetch = createSignedFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      verify: {
        verifier(signature, context) {
          assert.equal(context.request, observed)
          return verifier(signature, context)
        },
        policy: verificationPolicy({ requiredComponents: responseComponents }),
      },
      fetch: (async (input) => {
        observed = input as Request
        returned = await sign(new Response(null, { status: 204 }), {
          request: observed,
          signer: webCryptoSigner(),
          components: responseComponents,
          parameters: { created: RFC_CREATED },
        })
        return returned
      }) as typeof fetch,
    })

    const response = await signedFetch('https://example.com/')

    assert.equal(response, returned)
    assert.equal(observed.headers.has('signature'), true)
  })

  it('keeps signing-only support through createSignedFetch', async () => {
    const signedFetch = createSignedFetch({
      sign: {
        signer: webCryptoSigner(),
        components: ['@method'],
        parameters: { created: RFC_CREATED },
      },
      fetch: (async () => new Response(null, { status: 204 })) as typeof fetch,
    })

    assert.equal((await signedFetch('https://example.com/')).status, 204)
  })
})
