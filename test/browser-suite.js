import {
  appendAcceptSignature,
  component,
  createSignedFetch,
  date,
  displayString,
  ecdsaP256Sha256Signer,
  ecdsaP256Sha256Verifier,
  ecdsaP384Sha384Signer,
  ecdsaP384Sha384Verifier,
  ed25519Signer,
  ed25519Verifier,
  generateEcdsaP256Sha256KeyPair,
  generateEcdsaP384Sha384KeyPair,
  generateEd25519KeyPair,
  getSignatureRequests,
  getSignatures,
  sign,
  signRequested,
  verify,
} from '../index.js'

const CREATED = 1_618_884_473
const REQUEST_BODY = JSON.stringify({ hello: 'browser' })
const REQUEST_COMPONENTS = [
  '@method',
  '@authority',
  '@path',
  '@query',
  'content-type',
  'x-request-id',
]
const RESPONSE_COMPONENTS = [
  '@status',
  'content-type',
  component('@method', { req: true }),
  component('@authority', { req: true }),
  component('@path', { req: true }),
  component('x-request-id', { req: true }),
]

const tests = []
const results = globalThis.fetchMessageSignaturesTestResults

function test(name, run) {
  tests.push({ name, run })
}

function assertion(condition, message) {
  if (!condition) {
    throw new Error(message)
  }
}

function equal(actual, expected, message) {
  if (!Object.is(actual, expected)) {
    throw new Error(`${message}: expected ${String(expected)}, received ${String(actual)}`)
  }
}

async function rejects(operation, pattern) {
  try {
    await operation
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    assertion(pattern.test(message), `unexpected rejection: ${message}`)
    return
  }
  throw new Error('expected operation to reject')
}

function request(path = '/messages/1?mode=browser') {
  return new Request(`https://browser.example${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-request-id': 'request-123' },
    body: REQUEST_BODY,
  })
}

function policy(algorithm, requiredComponents) {
  return {
    requiredComponents,
    requiredParameters: ['created', 'alg', 'keyid'],
    algorithms: [algorithm],
    now: CREATED,
  }
}

const algorithms = [
  {
    name: 'ECDSA P-256',
    identifier: 'ecdsa-p256-sha256',
    signatureLength: 64,
    keyAlgorithm: 'ECDSA',
    namedCurve: 'P-256',
    generate: generateEcdsaP256Sha256KeyPair,
    signer: ecdsaP256Sha256Signer,
    verifier: ecdsaP256Sha256Verifier,
  },
  {
    name: 'ECDSA P-384',
    identifier: 'ecdsa-p384-sha384',
    signatureLength: 96,
    keyAlgorithm: 'ECDSA',
    namedCurve: 'P-384',
    generate: generateEcdsaP384Sha384KeyPair,
    signer: ecdsaP384Sha384Signer,
    verifier: ecdsaP384Sha384Verifier,
  },
  {
    name: 'Ed25519',
    identifier: 'ed25519',
    signatureLength: 64,
    keyAlgorithm: 'Ed25519',
    generate: generateEd25519KeyPair,
    signer: ed25519Signer,
    verifier: ed25519Verifier,
  },
]

for (const algorithm of algorithms) {
  test(`${algorithm.name} keys sign and verify a Request`, async () => {
    const protectedKeys = await algorithm.generate()
    equal(
      protectedKeys.privateKey.extractable,
      false,
      'private key must default to non-extractable',
    )
    equal(protectedKeys.publicKey.extractable, true, 'public key must remain extractable')
    equal(protectedKeys.privateKey.type, 'private', 'signing key has the wrong type')
    equal(protectedKeys.publicKey.type, 'public', 'verification key has the wrong type')
    equal(protectedKeys.privateKey.algorithm.name, algorithm.keyAlgorithm, 'wrong key algorithm')
    if (algorithm.namedCurve !== undefined) {
      equal(
        protectedKeys.privateKey.algorithm.namedCurve,
        algorithm.namedCurve,
        'wrong named curve',
      )
    }

    const extractableKeys = await algorithm.generate(true)
    equal(extractableKeys.privateKey.extractable, true, 'extractable option was not applied')

    const signed = await sign(request(), {
      signer: algorithm.signer(protectedKeys.privateKey),
      components: REQUEST_COMPONENTS,
      parameters: {
        created: CREATED,
        alg: algorithm.identifier,
        keyid: `${algorithm.identifier}-key`,
      },
    })

    const parsed = getSignatures(signed)
    equal(parsed.length, 1, 'signed request must contain one signature')
    equal(parsed[0].signature.byteLength, algorithm.signatureLength, 'wrong signature length')

    const verified = await verify(signed, {
      verifier: algorithm.verifier(protectedKeys.publicKey),
      policy: policy(algorithm.identifier, REQUEST_COMPONENTS),
    })
    equal(verified.algorithm, algorithm.identifier, 'wrong verified algorithm')
    equal(await signed.clone().text(), REQUEST_BODY, 'signed request body changed')
  })
}

test('a related Response verifies and a changed signature is rejected', async () => {
  const keys = await generateEcdsaP256Sha256KeyPair()
  const relatedRequest = request('/orders/123?mode=response')
  const responseBody = JSON.stringify({ accepted: true })
  const signed = await sign(
    new Response(responseBody, { status: 202, headers: { 'content-type': 'application/json' } }),
    {
      request: relatedRequest,
      signer: ecdsaP256Sha256Signer(keys.privateKey),
      components: RESPONSE_COMPONENTS,
      parameters: { created: CREATED, alg: 'ecdsa-p256-sha256', keyid: 'response-key' },
    },
  )

  const verified = await verify(signed, {
    request: relatedRequest,
    verifier: ecdsaP256Sha256Verifier(keys.publicKey),
    policy: policy('ecdsa-p256-sha256', RESPONSE_COMPONENTS),
  })
  equal(verified.algorithm, 'ecdsa-p256-sha256', 'wrong response algorithm')
  equal(await signed.clone().text(), responseBody, 'signed response body changed')

  const headers = new Headers(signed.headers)
  const signature = headers.get('signature')
  assertion(signature !== null, 'signed response is missing Signature')
  headers.set(
    'signature',
    signature.replace(/=:([A-Za-z0-9+/])/, (_, character) => (character === 'A' ? '=:B' : '=:A')),
  )
  const tampered = new Response(await signed.clone().text(), {
    status: signed.status,
    statusText: signed.statusText,
    headers,
  })
  await rejects(
    verify(tampered, {
      request: relatedRequest,
      verifier: ecdsaP256Sha256Verifier(keys.publicKey),
      policy: policy('ecdsa-p256-sha256', RESPONSE_COMPONENTS),
    }),
    /signature verification failed/i,
  )
})

test('Accept-Signature is parsed and fulfilled', async () => {
  const keys = await generateEcdsaP256Sha256KeyPair()
  const relatedRequest = appendAcceptSignature(request('/orders/456?mode=negotiation'), [
    {
      label: 'server',
      components: RESPONSE_COMPONENTS,
      parameters: {
        created: true,
        alg: 'ecdsa-p256-sha256',
        keyid: 'server-key',
        nonce: 'browser-challenge',
      },
    },
  ])
  const signatureRequest = getSignatureRequests(relatedRequest)[0]
  assertion(signatureRequest !== undefined, 'Accept-Signature was not parsed')
  equal(signatureRequest.label, 'server', 'signature request label changed')

  const signed = await signRequested(
    new Response('accepted', { status: 201, headers: { 'content-type': 'text/plain' } }),
    signatureRequest,
    {
      request: relatedRequest,
      signer: ecdsaP256Sha256Signer(keys.privateKey),
      parameters: { keyid: 'server-key' },
      now: CREATED,
    },
  )
  const parsed = getSignatures(signed)[0]
  assertion(parsed !== undefined, 'requested signature was not appended')
  equal(parsed.label, 'server', 'requested signature label changed')

  await verify(signed, {
    request: relatedRequest,
    verifier: ecdsaP256Sha256Verifier(keys.publicKey),
    policy: {
      ...policy('ecdsa-p256-sha256', RESPONSE_COMPONENTS),
      requiredParameters: ['created', 'alg', 'keyid', 'nonce'],
    },
  })
})

test('createSignedFetch signs requests and verifies related responses', async () => {
  const [clientKeys, serverKeys] = await Promise.all([
    generateEcdsaP256Sha256KeyPair(),
    generateEcdsaP256Sha256KeyPair(),
  ])

  const implementation = async (input) => {
    const signedRequest = input instanceof Request ? input : new Request(input)
    equal(signedRequest.redirect, 'manual', 'signed Fetch request must use manual redirects')
    equal(await signedRequest.clone().text(), REQUEST_BODY, 'Fetch request body changed')

    await verify(signedRequest, {
      verifier: ecdsaP256Sha256Verifier(clientKeys.publicKey),
      policy: policy('ecdsa-p256-sha256', REQUEST_COMPONENTS),
    })

    return sign(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      {
        request: signedRequest,
        signer: ecdsaP256Sha256Signer(serverKeys.privateKey),
        components: RESPONSE_COMPONENTS,
        parameters: { created: CREATED, alg: 'ecdsa-p256-sha256', keyid: 'server-key' },
      },
    )
  }

  const signedFetch = createSignedFetch({
    sign: {
      signer: ecdsaP256Sha256Signer(clientKeys.privateKey),
      components: REQUEST_COMPONENTS,
      parameters: { created: CREATED, alg: 'ecdsa-p256-sha256', keyid: 'client-key' },
    },
    verify: {
      verifier: ecdsaP256Sha256Verifier(serverKeys.publicKey),
      policy: policy('ecdsa-p256-sha256', RESPONSE_COMPONENTS),
    },
    fetch: implementation,
  })

  const response = await signedFetch(request('/fetch/1?mode=wrapper'))
  equal(response.status, 200, 'signed Fetch returned the wrong status')
  equal(await response.text(), JSON.stringify({ ok: true }), 'signed Fetch response body changed')
})

test('Structured Field extension values survive signature parsing', async () => {
  const keys = await generateEcdsaP256Sha256KeyPair()
  const signed = await sign(request('/extensions/1'), {
    signer: ecdsaP256Sha256Signer(keys.privateKey),
    components: REQUEST_COMPONENTS,
    parameters: {
      created: CREATED,
      alg: 'ecdsa-p256-sha256',
      keyid: 'extension-key',
      'extension-date': date(CREATED),
      'extension-display': displayString('Vienna €'),
    },
  })
  const parsed = getSignatures(signed)[0]
  assertion(parsed !== undefined, 'signature was not parsed')
  const values = Object.fromEntries(parsed.parameters)
  equal(values['extension-date'].type, 'date', 'Structured Field Date type changed')
  equal(values['extension-date'].value, CREATED, 'Structured Field Date value changed')
  equal(
    values['extension-display'].type,
    'display-string',
    'Structured Field Display String type changed',
  )
  equal(
    values['extension-display'].value,
    'Vienna €',
    'Structured Field Display String value changed',
  )

  await verify(signed, {
    verifier: ecdsaP256Sha256Verifier(keys.publicKey),
    policy: policy('ecdsa-p256-sha256', REQUEST_COMPONENTS),
  })
})

async function run() {
  results.total = tests.length
  for (const current of tests) {
    try {
      await current.run()
      results.passed += 1
      results.tests.push({ name: current.name, status: 'passed' })
    } catch (error) {
      results.failed += 1
      results.tests.push({
        name: current.name,
        status: 'failed',
        error:
          error instanceof Error
            ? `${error.name}: ${error.message}${error.stack ? `\n${error.stack}` : ''}`
            : String(error),
      })
    }
  }
  results.completed = true
}

run().catch((error) => {
  results.total += 1
  results.failed += 1
  results.tests.push({
    name: 'run browser test suite',
    status: 'failed',
    error: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
  })
  results.completed = true
})
