import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { component, createSignature, createSignatureBase, getSignatures, verify } from '../index.ts'
import type { SignableRequest, SignableResponse } from '../index.ts'
import { RFC_CREATED, verificationPolicy, webCryptoSigner, webCryptoVerifier } from './support.ts'

const URL_ = 'https://api.example/orders/123?page=2'
const FIELDS = { 'content-type': 'application/json', 'x-covered': 'value' }
const COMPONENTS = ['@method', '@authority', '@path', '@query', 'content-type', 'x-covered']
const PARAMETERS = [
  ['created', RFC_CREATED],
  ['keyid', 'client-key'],
] as const

describe('plain message descriptors', () => {
  it('derives the same base as the equivalent Request', () => {
    const fetchMessage = new Request(URL_, { method: 'POST', headers: FIELDS })
    const expected = createSignatureBase(fetchMessage, {
      components: COMPONENTS,
      parameters: PARAMETERS,
    })

    // Both accepted header shapes have to agree with Fetch byte for byte.
    for (const headers of [new Headers(FIELDS), FIELDS]) {
      const descriptor: SignableRequest = { method: 'POST', url: URL_, headers }
      assert.equal(
        createSignatureBase(descriptor, { components: COMPONENTS, parameters: PARAMETERS }),
        expected,
      )
    }
  })

  it('derives the same base as the equivalent Response', () => {
    const request = new Request(URL_, { method: 'POST' })
    const covered = ['@status', component('@authority', { req: true }), 'content-type']
    const expected = createSignatureBase(new Response('', { status: 201, headers: FIELDS }), {
      components: covered,
      parameters: PARAMETERS,
      request,
    })

    const descriptor: SignableResponse = { status: 201, headers: FIELDS }
    assert.equal(
      createSignatureBase(descriptor, { components: covered, parameters: PARAMETERS, request }),
      expected,
    )
  })

  it('binds a response descriptor to a request descriptor with ;req', () => {
    const request: SignableRequest = { method: 'POST', url: URL_, headers: FIELDS }
    const response: SignableResponse = { status: 200, headers: { 'content-type': 'text/plain' } }

    const base = createSignatureBase(response, {
      components: ['@status', component('@authority', { req: true })],
      parameters: PARAMETERS,
      request,
    })

    assert.match(base, /^"@status": 200$/m)
    assert.match(base, /^"@authority";req: api\.example$/m)
  })

  it('round trips the way a server without Request and Response would', async () => {
    // Sign an outgoing response, attach the two field values by hand, then verify what a peer
    // would receive. No Fetch message is constructed at any point.
    const request: SignableRequest = { method: 'POST', url: URL_, headers: FIELDS }
    const outgoing = { status: 200, headers: { 'content-type': 'application/json' } }

    const fields = await createSignature(outgoing, {
      signer: webCryptoSigner(),
      request,
      components: ['@status', component('@authority', { req: true })],
      parameters: { created: RFC_CREATED },
    })

    const received: SignableResponse = {
      status: outgoing.status,
      headers: {
        ...outgoing.headers,
        'signature-input': fields.signatureInput,
        signature: fields.signatureField,
      },
    }

    assert.equal(getSignatures(received).length, 1)
    const verified = await verify(received, {
      verifier(signature, context) {
        assert.ok(context.message.headers instanceof Headers)
        assert.ok(context.request?.headers instanceof Headers)
        context.message.headers.set('x-verifier-only', 'changed')
        context.request?.headers.set('x-verifier-only', 'changed')
        return webCryptoVerifier()(signature, context)
      },
      request,
      policy: {
        ...verificationPolicy({
          requiredComponents: ['@status', component('@authority', { req: true })],
        }),
        validate(_signature, context) {
          assert.ok(context.message.headers instanceof Headers)
          assert.ok(context.request?.headers instanceof Headers)
          assert.equal(context.message.headers.has('x-verifier-only'), false)
          assert.equal(context.request?.headers.has('x-verifier-only'), false)
        },
      },
    })
    assert.equal(verified.label, 'sig1')
  })

  it('keeps repeated field occurrences that the Headers constructor would lose', () => {
    const headers = { 'x-multi': ['one', 'two'] }
    const descriptor: SignableRequest = { method: 'GET', url: URL_, headers }

    // RFC 9421 Section 2.1 combines occurrences with ", ". The Headers record constructor joins an
    // array with a bare comma, so building one from the record would change the signed value.
    assert.equal(new Headers(headers as never).get('x-multi'), 'one,two')
    assert.match(
      createSignatureBase(descriptor, { components: ['x-multi'], parameters: PARAMETERS }),
      /^"x-multi": one, two$/m,
    )
    assert.match(
      createSignatureBase(descriptor, {
        components: [component('x-multi', { bs: true })],
        parameters: PARAMETERS,
      }),
      /^"x-multi";bs: :b25l:, :dHdv:$/m,
    )
  })

  it('combines repeated Cookie occurrences independently of Fetch runtime behavior', () => {
    const descriptor: SignableRequest = {
      method: 'GET',
      url: URL_,
      headers: { cookie: ['a=1', 'b=2'] },
    }

    assert.match(
      createSignatureBase(descriptor, { components: ['cookie'], parameters: PARAMETERS }),
      /^"cookie": a=1, b=2$/m,
    )
  })

  it('keeps Set-Cookie occurrences separate, which must never be combined', () => {
    const cookies = ['a=1', 'b=2']
    const descriptor: SignableResponse = { status: 200, headers: { 'set-cookie': cookies } }

    // The record constructor collapses these into one folded value.
    assert.deepEqual(new Headers({ 'set-cookie': cookies } as never).getSetCookie(), ['a=1,b=2'])

    const expected = createSignatureBase(new Response('', { status: 200 }), {
      components: ['set-cookie'],
      parameters: PARAMETERS,
      fieldValues: () => cookies,
    })
    assert.equal(
      createSignatureBase(descriptor, { components: ['set-cookie'], parameters: PARAMETERS }),
      expected,
    )
  })

  it('ignores an absent field supplied as undefined', () => {
    const descriptor: SignableRequest = {
      method: 'GET',
      url: URL_,
      headers: { 'x-covered': 'value', 'x-absent': undefined },
    }

    assert.throws(
      () => createSignatureBase(descriptor, { components: ['x-absent'], parameters: PARAMETERS }),
      /Header field "x-absent" is not present/,
    )
    assert.match(
      createSignatureBase(descriptor, { components: ['x-covered'], parameters: PARAMETERS }),
      /^"x-covered": value$/m,
    )
  })

  it('passes the caller descriptor itself to a field adapter', () => {
    const descriptor: SignableRequest = { method: 'GET', url: URL_, headers: FIELDS }

    assert.match(
      createSignatureBase(descriptor, {
        components: ['x-covered'],
        fieldValues(message) {
          assert.equal(message, descriptor)
          return ['value']
        },
      }),
      /^"x-covered": value$/m,
    )
  })

  it('indexes a related descriptor field record once per base', () => {
    let reads = 0
    const headers: Record<string, string> = {}
    const components = Array.from({ length: 16 }, (_, index) => {
      const name = `x-${index}`
      Object.defineProperty(headers, name, {
        enumerable: true,
        get() {
          reads++
          return String(index)
        },
      })
      return component(name, { req: true })
    })
    const request: SignableRequest = { method: 'GET', url: URL_, headers }

    createSignatureBase({ status: 200, headers: {} }, { components, request })
    assert.equal(reads, components.length)
  })

  it('rejects mutation of a descriptor header while signing', async () => {
    const descriptor = { method: 'GET', url: URL_, headers: { 'x-covered': 'original' } }

    await assert.rejects(
      createSignature(descriptor, {
        components: ['@method', '@path', 'x-covered'],
        signer: () => ({
          type: 'signer',
          alg: 'hmac-sha256',
          async sign() {
            descriptor.headers['x-covered'] = 'changed'
            return new Uint8Array([1])
          },
        }),
      }),
      /changed during signature signing/,
    )
  })

  it('distinguishes record occurrence boundaries while guarding a signature', async () => {
    const occurrences = ['one', 'two']
    const descriptor = { method: 'GET', url: URL_, headers: { 'x-covered': occurrences } }

    await assert.rejects(
      createSignature(descriptor, {
        components: ['x-covered'],
        signer: () => ({
          type: 'signer',
          alg: 'hmac-sha256',
          async sign() {
            occurrences.splice(0, occurrences.length, 'one, two')
            return new Uint8Array([1])
          },
        }),
      }),
      /headers changed during signature signing/,
    )
  })

  it('rejects mutation of an uncovered related descriptor while signing', async () => {
    const request = { method: 'GET', url: URL_, headers: { 'x-uncovered': 'original' } }

    await assert.rejects(
      createSignature(
        { status: 200, headers: { 'x-covered': 'stable' } },
        {
          request,
          components: ['x-covered'],
          signer: () => ({
            type: 'signer',
            alg: 'hmac-sha256',
            async sign() {
              request.headers['x-uncovered'] = 'changed'
              return new Uint8Array([1])
            },
          }),
        },
      ),
      /headers changed during signature signing/,
    )
  })

  it('rejects mutation of an uncovered related descriptor URL while signing', async () => {
    const request = { method: 'GET', url: URL_, headers: {} }

    await assert.rejects(
      createSignature(
        { status: 200, headers: { 'x-covered': 'stable' } },
        {
          request,
          components: ['x-covered'],
          signer: () => ({
            type: 'signer',
            alg: 'hmac-sha256',
            async sign() {
              request.url = 'https://other.example/changed'
              return new Uint8Array([1])
            },
          }),
        },
      ),
      /context changed during signature signing/,
    )
  })

  it('rejects mutation of an uncovered descriptor property while signing', async () => {
    const method = { method: 'GET', url: URL_, headers: { 'x-covered': 'stable' } }
    const url = { method: 'GET', url: URL_, headers: { 'x-covered': 'stable' } }
    const status = { status: 200, headers: { 'x-covered': 'stable' } }
    const cases = [
      {
        message: method,
        name: 'method',
        mutate() {
          method.method = 'POST'
        },
      },
      {
        message: url,
        name: 'url',
        mutate() {
          url.url = 'https://api.example/changed'
        },
      },
      {
        message: status,
        name: 'status',
        mutate() {
          status.status = 201
        },
      },
    ] as const

    for (const test of cases) {
      await assert.rejects(
        createSignature(test.message, {
          components: ['x-covered'],
          signer: () => ({
            type: 'signer',
            alg: 'hmac-sha256',
            async sign() {
              test.mutate()
              return new Uint8Array([1])
            },
          }),
        }),
        /context changed during signature signing/,
        test.name,
      )
    }
  })

  it('rejects mutation of a descriptor while verifying', async () => {
    const unsigned = { method: 'GET', url: URL_, headers: { 'x-covered': 'original' } }
    const fields = await createSignature(unsigned, {
      signer: webCryptoSigner(),
      components: ['x-covered'],
      parameters: { created: RFC_CREATED },
    })
    const signed = {
      ...unsigned,
      headers: {
        ...unsigned.headers,
        'signature-input': fields.signatureInput,
        signature: fields.signatureField,
      },
    }

    await assert.rejects(
      verify(signed, {
        verifier(signature, context) {
          signed.headers['x-covered'] = 'changed'
          return webCryptoVerifier()(signature, context)
        },
        policy: verificationPolicy({ requiredComponents: ['x-covered'] }),
      }),
      /changed during signature verification/,
    )
  })

  it('rejects an uncovered URL change while key selection is pending', async () => {
    const unsigned = { method: 'GET', url: URL_, headers: { 'x-covered': 'original' } }
    const fields = await createSignature(unsigned, {
      signer: webCryptoSigner(),
      components: ['x-covered'],
      parameters: { created: RFC_CREATED },
    })
    const signed = {
      ...unsigned,
      headers: {
        ...unsigned.headers,
        'signature-input': fields.signatureInput,
        signature: fields.signatureField,
      },
    }
    let started!: () => void
    const keySelectionStarted = new Promise<void>((resolve) => {
      started = resolve
    })
    let release!: () => void
    const keySelected = new Promise<void>((resolve) => {
      release = resolve
    })
    let policyCalled = false

    const pending = verify(signed, {
      async verifier(signature, context) {
        assert.ok('method' in context.message)
        assert.equal(context.message.url, URL_)
        started()
        await keySelected
        return webCryptoVerifier()(signature, context)
      },
      policy: {
        ...verificationPolicy({ requiredComponents: ['x-covered'] }),
        validate() {
          policyCalled = true
        },
      },
    })
    await keySelectionStarted
    signed.url = 'https://other.example/changed'
    release()

    await assert.rejects(pending, /context changed during signature verification/)
    assert.equal(policyCalled, false)
  })

  it('rejects a descriptor that names neither a method with a url nor a status', () => {
    for (const invalid of [{ headers: {} }, { method: 'GET', headers: {} }, { url: URL_ }, null]) {
      assert.throws(
        () => createSignatureBase(invalid as never, { components: ['@method'] }),
        /"message" must be a Request, Response, or plain message descriptor/,
      )
    }
  })

  it('leaves appending to the caller, which is what createSignature is for', async () => {
    // sign() and appendSignature() take a Fetch message, because they rebuild one. The types say so.
    // A caller holding a descriptor uses createSignature() and attaches the two field values, which
    // is the flow the round trip above exercises.
    const descriptor: SignableRequest = { method: 'POST', url: URL_, headers: FIELDS }
    const fields = await createSignature(descriptor, {
      signer: webCryptoSigner(),
      components: ['@method'],
      parameters: { created: RFC_CREATED },
    })

    assert.match(fields.signatureInput, /^sig1=\("@method"\);created=/)
    assert.match(fields.signatureField, /^sig1=:[A-Za-z0-9+/]+=*:$/)
  })
})
