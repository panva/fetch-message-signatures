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
  createSignatureFields,
  decimal,
  findComponents,
  getSignatureParameter,
  getSignatures,
  includesComponent,
  parseSignature,
  parseSignatureInput,
  sign,
  token,
  verify,
} from '../index.ts'
import type {
  ComponentIdentifier,
  RequestSnapshot,
  VerificationPolicy,
  VerifierFactory,
} from '../index.ts'
import {
  bytesToBase64,
  REQUEST_CARRIES_FORBIDDEN_FIELDS,
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

function assertRequestSnapshot(
  snapshot: RequestSnapshot | undefined,
  request: Request,
): asserts snapshot is RequestSnapshot {
  assert.ok(snapshot)
  assert.notEqual(snapshot, request)
  assert.equal(snapshot.method, request.method)
  assert.equal(snapshot.url, request.url)
  assert.ok(Object.isFrozen(snapshot))
  assert.ok(Object.isFrozen(snapshot.headers))
  assert.ok(Object.isFrozen(snapshot.trailers))
  assert.equal(Object.getPrototypeOf(snapshot.headers), null)
  assert.equal(Object.getPrototypeOf(snapshot.trailers), null)
  for (const [name, value] of request.headers) {
    assert.deepEqual(snapshot.headers[name], [value])
    assert.ok(Object.isFrozen(snapshot.headers[name]))
  }
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
      createSignatureBase(
        {
          method: 'GET',
          url: 'https://example.com/',
          headers: { example: 'a=1' },
          trailers: { example: 'a=3' },
        },
        {
          components: [
            component('example', { key: 'a' }),
            component('example', [
              ['key', 'a'],
              ['tr', true],
            ]),
          ],
        },
      ),
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

describe('verifier factory contract', () => {
  it('awaits a verifier factory that resolves a key', async () => {
    // Key rotation may mean fetching or refreshing a key, so the factory may return a Promise.
    let resolved = 0
    const signed = await sign(new Request('https://example.com/'), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED, keyid: 'rotating-key' },
    })

    const verified = await verify(signed, {
      verifier: async (signature, context) => {
        const keyid = getSignatureParameter(signature, 'keyid')
        assert.equal(keyid, 'rotating-key')
        await Promise.resolve()
        resolved++
        return webCryptoVerifier()(signature, context)
      },
      policy: verificationPolicy({ requiredComponents: ['@method'] }),
    })

    assert.equal(resolved, 1)
    assert.equal(verified.label, 'sig1')
  })

  it('reports a rejected factory as the cause, like a thrown one', async () => {
    const signed = await sign(new Request('https://example.com/'), {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })

    for (const verifier of [
      () => Promise.reject(new Error('key service unavailable')),
      () => {
        throw new Error('key service unavailable')
      },
    ] as VerifierFactory[]) {
      await assert.rejects(
        verify(signed, { verifier, policy: verificationPolicy() }),
        (error: unknown) => {
          assert.ok(error instanceof TypeError)
          assert.equal(error.message, 'Invalid "verifier"')
          assert.equal((error.cause as Error).message, 'key service unavailable')
          return true
        },
      )
    }
  })

  it('reads a metadata parameter without reproducing the ordered-list shape', () => {
    const [parsed] = parseSignatureInput(
      'sig1=("@method");created=1618884473;keyid="client-key";alg="ed25519"',
    )
    const signature = { ...parsed!, signature: new Uint8Array() }

    assert.equal(getSignatureParameter(signature, 'keyid'), 'client-key')
    assert.equal(getSignatureParameter(signature, 'alg'), 'ed25519')
    assert.equal(getSignatureParameter(signature, 'created'), RFC_CREATED)
    assert.equal(getSignatureParameter(signature, 'nonce'), undefined)
    assert.throws(() => getSignatureParameter(null as never, 'keyid'), /must be a MessageSignature/)
    assert.throws(() => getSignatureParameter(signature, 1 as never), /"name" must be a string/)
  })
})

describe('synchronous signature field serialization', () => {
  const components = ['@method', '@authority', '@path', 'x-covered']
  const parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'client-key'],
    ['alg', 'test'],
  ] as const
  const bytes = new Uint8Array(64).map((_, index) => (index * 7) % 251)

  function message(): Request {
    return new Request('https://api.example/orders?page=1', {
      method: 'POST',
      headers: { 'x-covered': 'value' },
    })
  }

  it('produces exactly what createSignature produces for the same inputs', async () => {
    const oneStep = await createSignature(message(), {
      signer: () => ({ alg: 'test', sign: () => bytes }),
      components,
      parameters,
      label: 'sig9',
    })
    const composed = createSignatureFields({
      signature: bytes,
      components,
      parameters,
      label: 'sig9',
    })

    assert.equal(composed.signatureInput, oneStep.signatureInput)
    assert.equal(composed.signatureField, oneStep.signatureField)
    assert.deepEqual(composed.components, oneStep.components)
    assert.deepEqual(composed.parameters, oneStep.parameters)
    assert.deepEqual(composed.signature, oneStep.signature)
    assert.equal(composed.label, 'sig9')
  })

  it('round trips a synchronously signed message through verify', async () => {
    // The whole point: no await between building the base and holding the fields.
    const digest = (data: Uint8Array): Uint8Array<ArrayBuffer> => {
      const out = new Uint8Array(32)
      for (const [index, byte] of data.entries()) {
        out[index % 32] = (out[index % 32]! + byte * 31 + index) % 251
      }
      return out
    }
    const request = message()
    const base = createSignatureBase(request, { components, parameters })
    const fields = createSignatureFields({
      signature: digest(new TextEncoder().encode(base)),
      components,
      parameters,
    })
    const signed = appendSignature(request, fields)

    const verified = await verify(signed, {
      verifier: () => ({
        alg: 'test',
        verify: (data, signature) => bytesToBase64(digest(data)) === bytesToBase64(signature),
      }),
      policy: verificationPolicy({ algorithms: ['test'], requiredComponents: [...components] }),
    })

    assert.equal(verified.label, 'sig1')
    assert.equal(verified.algorithm, 'test')
  })

  it('copies the signature so a later mutation cannot change the fields', () => {
    const owned = new Uint8Array([1, 2, 3])
    const fields = createSignatureFields({ signature: owned, components, parameters })
    const before = fields.signatureField

    owned.fill(0)
    assert.deepEqual(fields.signature, new Uint8Array([1, 2, 3]))
    assert.equal(fields.signatureField, before)
  })

  it('adds no default created, unlike createSignature', async () => {
    const composed = createSignatureFields({ signature: bytes, components: ['@method'] })
    const oneStep = await createSignature(message(), {
      signer: () => ({ alg: 'test', sign: () => bytes }),
      components: ['@method'],
    })

    assert.equal(composed.signatureInput, 'sig1=("@method")')
    assert.match(oneStep.signatureInput, /^sig1=\("@method"\);created=\d+$/)
  })

  it('validates its options', () => {
    assert.throws(() => createSignatureFields(null as never), /"options" must be an object/)
    assert.throws(
      () => createSignatureFields({ signature: 'nope' as never, components }),
      /"signature" must be a Uint8Array/,
    )
    assert.throws(
      () => createSignatureFields({ signature: bytes, components, label: 'Bad Label' }),
      /Signature label/,
    )
    assert.throws(
      () => createSignatureFields({ signature: bytes, components: ['@method', '@method'] }),
      /Duplicate covered component/,
    )
    assert.throws(
      () => createSignatureFields({ signature: bytes, components: ['@bogus'] }),
      /@bogus/,
    )
  })

  it('refuses component identifiers its own parser would reject', () => {
    // Serializing without building a base skipped parameter validation, so these produced a
    // Signature-Input that parseSignatureInput() and appendSignature() both threw on.
    const invalid: ReadonlyArray<readonly [ComponentIdentifier, RegExp]> = [
      [component('@method', { sf: true }), /Parameter "sf" does not apply to "@method"/],
      [component('@query-param'), /"@query-param" requires a String "name" parameter/],
      [component('@status', { req: true }), /Parameter "req" does not apply to "@status"/],
      [component('x-covered', { wat: true }), /Unknown HTTP field component parameter "wat"/],
      [component('x-covered', { bs: true, sf: true }), /"bs" is incompatible with "sf" and "key"/],
      [component('x-covered', { sf: 'yes' as never }), /must be a bare Boolean true/],
    ]

    for (const [identifier, message] of invalid) {
      assert.throws(
        () => createSignatureFields({ signature: bytes, components: [identifier] }),
        message,
      )
    }
  })

  it('refuses to cover a field the signature is about to change', async () => {
    // Appending the new signature rewrites signature-input, so a signature over the whole field
    // could never verify against the message it was added to.
    for (const name of ['signature', 'signature-input']) {
      assert.throws(
        () => createSignatureFields({ signature: bytes, components: [name] }),
        /cannot cover fields to which it is being appended/,
      )
      await assert.rejects(
        createSignature(rfcRequest(), {
          signer: webCryptoSigner(),
          components: [name],
          parameters: { created: RFC_CREATED },
        }),
        /cannot cover fields to which it is being appended/,
      )
    }

    // Coverage unaffected by the append stays allowed in both constructors. The keyed case names
    // another label, because this signature's own member is covered separately below.
    for (const identifier of [
      component('signature-input', { req: true }),
      component('signature', { tr: true }),
      component('signature', { key: 'sig0' }),
    ]) {
      assert.ok(
        createSignatureFields({ signature: bytes, components: [identifier], label: 'sig1' })
          .signatureInput,
      )
    }
  })

  it('refuses to cover the signature member it is itself producing', async () => {
    // ";key" pins one member, but when the key is this signature's own label the member is the
    // signature bytes: absent while the base is built, and the signature itself afterwards.
    const own = [component('signature', { key: 'sig1' })]
    assert.throws(
      () => createSignatureFields({ signature: bytes, components: own, label: 'sig1' }),
      /cannot cover its own "signature" Dictionary member "sig1"/,
    )
    await assert.rejects(
      createSignature(rfcRequest(), {
        signer: webCryptoSigner(),
        components: own,
        parameters: { created: RFC_CREATED },
        label: 'sig1',
      }),
      /cannot cover its own "signature" Dictionary member "sig1"/,
    )

    // Another label's member, this signature's own signature-input member, and the related request
    // or trailer section are all unaffected.
    for (const identifier of [
      component('signature', { key: 'sig0' }),
      component('signature-input', { key: 'sig1' }),
      component('signature', { key: 'sig1', req: true }),
      component('signature', { key: 'sig1', tr: true }),
    ]) {
      assert.ok(
        createSignatureFields({ signature: bytes, components: [identifier], label: 'sig1' })
          .signatureInput,
      )
    }
  })

  it('round trips a signature that covers its own signature-input member', async () => {
    // Self-referential but knowable ahead of signing: the member value is exactly the
    // @signature-params line of the base, so the field can be set before the base is built. That is
    // why the guard singles out "signature" rather than both fields.
    const components = [component('signature-input', { key: 'sig1' })]
    const parameters = [['created', RFC_CREATED]] as const
    const probe = createSignatureFields({ signature: bytes, components, parameters, label: 'sig1' })

    const request = new Request('https://example.com/', {
      headers: { 'signature-input': probe.signatureInput },
    })
    const base = createSignatureBase(request, { components, parameters })
    const fields = createSignatureFields({
      signature: await webCryptoSigner()().sign(new TextEncoder().encode(base)),
      components,
      parameters,
      label: 'sig1',
    })
    // appendSignature() requires both fields together, and this workflow sets Signature-Input
    // before the bytes exist, so the final message carries the pair. Signature-Input is
    // unchanged between the two calls, because it does not depend on the signature.
    assert.equal(fields.signatureInput, probe.signatureInput)
    const signed = new Request(request, {
      headers: { 'signature-input': fields.signatureInput, signature: fields.signatureField },
    })

    const verified = await verify(signed, {
      verifier: webCryptoVerifier(),
      policy: verificationPolicy(),
    })
    assert.equal(verified.label, 'sig1')
  })

  it('round trips a composed signature that covers one existing dictionary member', async () => {
    const first = await sign(
      new Request('https://example.com/orders', { headers: { 'x-covered': 'value' } }),
      {
        signer: webCryptoSigner(),
        components: ['@method', 'x-covered'],
        parameters: { created: RFC_CREATED },
        label: 'sig1',
      },
    )

    // ";key" pins one member, which appending sig2 does not disturb.
    const covered = [component('signature-input', { key: 'sig1' })]
    const secondParameters = [['created', RFC_CREATED]] as const
    const base = createSignatureBase(first, { components: covered, parameters: secondParameters })
    const fields = createSignatureFields({
      signature: new Uint8Array(await webCryptoSigner()().sign(new TextEncoder().encode(base))),
      components: covered,
      parameters: secondParameters,
      label: 'sig2',
    })
    const appended = appendSignature(first, fields)

    const verified = await verify(appended, {
      verifier: webCryptoVerifier(),
      policy: verificationPolicy(),
      label: 'sig2',
    })
    assert.equal(verified.label, 'sig2')
  })
})

describe('covered component inspection', () => {
  // Plain fields only, and no body: a browser cannot carry a forbidden field through the
  // reconstruction that sign() performs, so a fixture that used one would not verify there.
  async function signedRequest(
    components: ReadonlyArray<Parameters<typeof createSignature>[1]['components'][number]>,
  ): Promise<Request> {
    return sign(
      new Request('https://example.com/orders?page=1', { headers: { 'x-covered': 'value' } }),
      { signer: webCryptoSigner(), components, parameters: { created: RFC_CREATED } },
    )
  }

  it('matches a plain identifier and lowercases field names on both sides', () => {
    const covered = ['@method', 'Content-Type']

    assert.equal(includesComponent(covered, '@method'), true)
    assert.equal(includesComponent(covered, 'content-type'), true)
    assert.equal(includesComponent(covered, 'CONTENT-TYPE'), true)
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
    // Comparing names alone would call this covered.
    assert.equal(includesComponent(bound, '@authority'), false)
    assert.equal(includesComponent(['@authority'], component('@authority', { req: true })), false)
  })

  it('compares component parameters as an unordered set', () => {
    const covered = [
      component('content-type', [
        ['key', 'member'],
        ['req', true],
      ]),
    ]

    assert.equal(
      includesComponent(
        covered,
        component('content-type', [
          ['req', true],
          ['key', 'member'],
        ]),
      ),
      true,
    )
    assert.equal(includesComponent(covered, component('content-type', { key: 'member' })), false)
  })

  it('reads the covered components of a parsed signature', async () => {
    const signed = await signedRequest(['@method', 'x-covered'])
    const { components } = getSignatures(signed)[0]!

    assert.equal(includesComponent(components, '@method'), true)
    assert.equal(includesComponent(components, 'x-covered'), true)
    assert.equal(includesComponent(components, 'x-uncovered'), false)
  })

  it('finds every parameterization of one field name', () => {
    const covered = [
      '@method',
      component('example-dict', { key: 'a' }),
      component('example-dict', { key: 'b' }),
      'content-type',
    ]

    assert.deepEqual(
      findComponents(covered, 'example-dict').map(({ parameters }) => parameters),
      [[['key', 'a']], [['key', 'b']]],
    )
    assert.deepEqual(findComponents(covered, '@method'), [{ name: '@method', parameters: [] }])
    assert.deepEqual(findComponents(covered, 'date'), [])
    assert.deepEqual(findComponents([], '@method'), [])
  })

  it('finds a keyed identifier that includesComponent does not', () => {
    const covered = [component('content-type', { key: 'sig1' })]

    // The pair that motivates both helpers: one list, two different questions.
    assert.equal(includesComponent(covered, 'content-type'), false)
    assert.equal(findComponents(covered, 'content-type').length, 1)
  })

  it('reports how a field was covered, not only that it was', async () => {
    const signed = await sign(
      new Request('https://example.com/', { headers: { 'x-dict': 'a=1, b=2' } }),
      {
        signer: webCryptoSigner(),
        components: [component('x-dict', { key: 'a' }), '@authority'],
        parameters: { created: RFC_CREATED },
        structuredFields: { 'x-dict': 'dictionary' },
      },
    )
    const [covered] = findComponents(getSignatures(signed)[0]!.components, 'x-dict')

    assert.ok(covered)
    // The parameter is what tells a caller only one dictionary member is bound.
    assert.deepEqual(covered.parameters, [['key', 'a']])
    assert.equal(includesComponent([covered], component('x-dict', { key: 'a' })), true)
    assert.equal(includesComponent([covered], 'x-dict'), false)
  })

  it('reports a result for an identifier that arrived on the wire rather than throwing', () => {
    // A peer controls its own Signature-Input, so a lookup against one must not reject the list.
    // Neither of these names is one a covered component list may carry.
    const hostile = [{ name: '@signature-params', parameters: [] }, { name: '@bogus' }, 'X-Upper']

    assert.equal(includesComponent(hostile, '@method'), false)
    assert.equal(includesComponent(hostile, 'x-upper'), true)
    assert.deepEqual(findComponents(hostile, '@method'), [])
  })

  it('rejects an identifier that is not a legal covered component', () => {
    // The list being searched is not validated, but the identifier being looked for comes from the
    // application and has to be one a signature could actually carry.
    const invalid: ReadonlyArray<ComponentIdentifier> = [
      component('@method', { sf: true }),
      component('@query-param'),
      component('x-covered', { wat: true }),
      component('x-covered', { bs: true, key: 'a' }),
    ]

    for (const identifier of invalid) {
      assert.throws(() => includesComponent([identifier], identifier), { name: 'TypeError' })
    }
  })

  it('rejects an invalid identifier to look for, and an invalid list', () => {
    for (const lookup of [includesComponent, findComponents] as Array<
      (components: ReadonlyArray<string>, name: never) => unknown
    >) {
      assert.throws(() => lookup(['@method'], '@signature-params' as never), {
        name: 'TypeError',
        message: '"@signature-params" cannot be listed as a covered component',
      })
      assert.throws(() => lookup(['@method'], '@bogus' as never), /@bogus/)
      assert.throws(() => lookup('@method' as never, '@method' as never), {
        name: 'TypeError',
        message: '"components" must be an array',
      })
    }

    assert.throws(() => includesComponent(['@method'], 1 as never), {
      name: 'TypeError',
      message: 'Invalid HTTP message component identifier',
    })
    assert.throws(() => findComponents(['@method'], 1 as never), {
      name: 'TypeError',
      message: '"name" must be a string',
    })
  })

  it('expresses coverage rules that requiredComponents cannot', async () => {
    const signed = await signedRequest(['@method', '@authority', 'x-covered'])
    const policy = (validate: VerificationPolicy['validate']): VerificationPolicy =>
      verificationPolicy({ validate })

    // Either-or: requiredComponents is a conjunction, so this has to live in validate.
    const eitherOr = policy((signature) => {
      if (
        !includesComponent(signature.components, '@authority') &&
        !includesComponent(signature.components, '@target-uri')
      ) {
        throw new Error('The signature must cover @authority or @target-uri')
      }
    })
    await assert.doesNotReject(verify(signed, { verifier: webCryptoVerifier(), policy: eitherOr }))

    // Conditional on the message, and name-level rather than identifier-level.
    const requireCoverageWhenPresent = (field: string): VerificationPolicy =>
      policy((signature, context) => {
        if (
          Object.hasOwn(context.message.headers, field) &&
          findComponents(signature.components, field).length === 0
        ) {
          throw new Error(`A present ${field} field must be covered`)
        }
      })

    await assert.doesNotReject(
      verify(signed, {
        verifier: webCryptoVerifier(),
        policy: requireCoverageWhenPresent('x-covered'),
      }),
    )
    const withUncovered = new Request(signed, {
      headers: new Headers([...signed.headers, ['x-extra', 'added']]),
    })
    await assert.rejects(
      verify(withUncovered, {
        verifier: webCryptoVerifier(),
        policy: requireCoverageWhenPresent('x-extra'),
      }),
      /A present x-extra field must be covered/,
    )
  })
})

describe('multiple signatures', () => {
  it('appends, parses, and independently verifies distinct labels', async () => {
    // Covers a forbidden request field and rebuilds the message, which a browser cannot do.
    if (!REQUEST_CARRIES_FORBIDDEN_FIELDS) {
      return
    }
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
    // Covers a forbidden request field and rebuilds the message, which a browser cannot do.
    if (!REQUEST_CARRIES_FORBIDDEN_FIELDS) {
      return
    }
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
    // Covers a forbidden request field and rebuilds the message, which a browser cannot do.
    if (!REQUEST_CARRIES_FORBIDDEN_FIELDS) {
      return
    }
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
    // Covers a forbidden request field and rebuilds the message, which a browser cannot do.
    if (!REQUEST_CARRIES_FORBIDDEN_FIELDS) {
      return
    }
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
    let verifiedMessage: object | undefined
    await assert.rejects(
      verify(signed, {
        verifier(_signature, context) {
          assert.notEqual(context.message, signed)
          assert.ok('method' in context.message)
          assert.equal(context.message.method, signed.method)
          assert.equal(context.message.url, signed.url)
          assert.ok(Object.isFrozen(context.message))
          assert.ok(Object.isFrozen(context.message.headers))
          assert.ok(Object.isFrozen(context.message.trailers))
          verifiedMessage = context.message
          assert.equal(context.request, undefined)
          return {
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
            assert.equal(context.message, verifiedMessage)
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
          assertRequestSnapshot(context.request, observed)
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
          assertRequestSnapshot(context.request, observed)
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
