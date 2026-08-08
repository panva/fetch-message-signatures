import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  component,
  createSignature,
  createSignatureBase,
  ecdsaP256Sha256Verifier,
  ed25519Signer as createEd25519Signer,
  ed25519Verifier as createEd25519Verifier,
  rsaPssSha512Verifier,
  verify,
  type SignerFactory,
  type VerifierFactory,
} from '../index.ts'
import {
  base64ToBytes,
  bytesToBase64,
  fixtureRequest,
  withRequestFields,
  pemToDer,
  RFC_CREATED,
  rfcRequest,
  rfcResponse,
  verificationPolicy,
} from './support.ts'

const rsaPssPublicKey = pemToDer(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----`)

const p256PublicKey = pemToDer(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`)

const ed25519PublicKey = pemToDer(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`)

const ed25519PrivateKey = pemToDer(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`)

const hmacSecret = base64ToBytes(
  'uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==',
)

const b21Signature = [
  'd2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem',
  'LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG',
  '52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx',
  '2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6',
  'UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3',
  '+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==',
].join('')

const b22Signature = [
  'LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ',
  'EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT',
  '8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA',
  'RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd',
  '4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK',
  'UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==',
].join('')

const b23Signature = [
  'bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB',
  'iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU',
  'xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1',
  'pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9',
  'bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z',
  'JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==',
].join('')

const b24Signature =
  'wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw=='

const b25Signature = 'pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8='

const b26Signature =
  'wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=='

const b3Signature =
  'xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw=='

const b4Signature =
  'ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA=='

const clientCert = [
  ':MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQ',
  'KDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBD',
  'QTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDM',
  'FkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXm',
  'ckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQY',
  'DVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8B',
  'Af8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQ',
  'GV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0',
  'Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:',
].join('')

const rsaPssVerifier = rsaPssSha512Verifier(
  await crypto.subtle.importKey(
    'spki',
    rsaPssPublicKey,
    { name: 'RSA-PSS', hash: 'SHA-512' },
    false,
    ['verify'],
  ),
)

const p256Verifier = ecdsaP256Sha256Verifier(
  await crypto.subtle.importKey(
    'spki',
    p256PublicKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  ),
)

const hmacKey = await crypto.subtle.importKey(
  'raw',
  hmacSecret,
  { name: 'HMAC', hash: 'SHA-256' },
  false,
  ['sign', 'verify'],
)
const hmacVerifier: VerifierFactory = () => ({
  type: 'verifier',
  alg: 'hmac-sha256',
  async verify(data, signature) {
    return crypto.subtle.verify('HMAC', hmacKey, signature, data)
  },
})
const hmacSigner: SignerFactory = () => ({
  type: 'signer',
  alg: 'hmac-sha256',
  async sign(data) {
    return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data))
  },
})

const ed25519Verifier = createEd25519Verifier(
  await crypto.subtle.importKey('spki', ed25519PublicKey, 'Ed25519', false, ['verify']),
)

const ed25519Signer = createEd25519Signer(
  await crypto.subtle.importKey('pkcs8', ed25519PrivateKey, 'Ed25519', false, ['sign']),
)

/** Reports whether this host's Ed25519 reproduces the deterministic RFC 8032 signature. */
async function ed25519IsDeterministic(): Promise<boolean> {
  const signer = ed25519Signer()
  const first = await signer.sign(new Uint8Array([1, 2, 3]))
  const second = await signer.sign(new Uint8Array([1, 2, 3]))
  return bytesToBase64(first) === bytesToBase64(second)
}

function signedRequest(signatureInput: string, signature: string, request = rfcRequest()): Request {
  return withRequestFields(request, { 'signature-input': signatureInput, signature })
}

function signedResponse(signatureInput: string, signature: string): Response {
  const response = rfcResponse()
  const headers = new Headers(response.headers)
  headers.set('signature-input', signatureInput)
  headers.set('signature', signature)
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  })
}

describe('RFC 9421 Appendix B complete examples', () => {
  const b21Parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-key-rsa-pss'],
    ['nonce', 'b3k2pp5k7z-50gnwp.yemd'],
  ] as const
  const b22Components = ['@authority', 'content-digest', component('@query-param', { name: 'Pet' })]
  const b22Parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-key-rsa-pss'],
    ['tag', 'header-example'],
  ] as const
  const b23Components = [
    'date',
    '@method',
    '@path',
    '@query',
    '@authority',
    'content-type',
    'content-digest',
    'content-length',
  ]
  const b23Parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-key-rsa-pss'],
  ] as const
  const b24Components = ['@status', 'content-type', 'content-digest', 'content-length']
  const b24Parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-key-ecc-p256'],
  ] as const
  const b25Components = ['date', '@authority', 'content-type']
  const b25Parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-shared-secret'],
  ] as const
  const b26Components = ['date', '@method', '@path', '@authority', 'content-type', 'content-length']
  const b26Parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-key-ed25519'],
  ] as const

  it('recreates B.2.1 minimal signature base', () => {
    assert.equal(
      createSignatureBase(rfcRequest(), { components: [], parameters: b21Parameters }),
      '"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    )
  })

  it('verifies the published B.2.1 RSA-PSS signature', async () => {
    const message = signedRequest(
      'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
      `sig-b21=:${b21Signature}:`,
    )
    const signature = await verify(message, {
      verifier: rsaPssVerifier,
      policy: verificationPolicy({
        algorithms: ['rsa-pss-sha512'],
        requiredParameters: ['created', 'keyid', 'nonce'],
      }),
    })
    assert.equal(signature.label, 'sig-b21')
  })

  it('recreates B.2.2 selective-coverage signature base', () => {
    assert.equal(
      createSignatureBase(rfcRequest(), { components: b22Components, parameters: b22Parameters }),
      [
        '"@authority": example.com',
        '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
        '"@query-param";name="Pet": dog',
        '"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
      ].join('\n'),
    )
  })

  it('verifies the published B.2.2 RSA-PSS signature', async () => {
    const message = signedRequest(
      'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
      `sig-b22=:${b22Signature}:`,
    )
    const signature = await verify(message, {
      verifier: rsaPssVerifier,
      policy: verificationPolicy({
        algorithms: ['rsa-pss-sha512'],
        requiredComponents: b22Components,
        requiredParameters: ['created', 'keyid', 'tag'],
      }),
    })
    assert.equal(signature.label, 'sig-b22')
  })

  it('recreates B.2.3 full-coverage signature base', () => {
    assert.equal(
      createSignatureBase(rfcRequest(), { components: b23Components, parameters: b23Parameters }),
      [
        '"date": Tue, 20 Apr 2021 02:07:55 GMT',
        '"@method": POST',
        '"@path": /foo',
        '"@query": ?param=Value&Pet=dog',
        '"@authority": example.com',
        '"content-type": application/json',
        '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
        '"content-length": 18',
        '"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
      ].join('\n'),
    )
  })

  it('verifies the published B.2.3 RSA-PSS signature', async () => {
    const message = signedRequest(
      'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
      `sig-b23=:${b23Signature}:`,
    )
    const signature = await verify(message, {
      verifier: rsaPssVerifier,
      policy: verificationPolicy({
        algorithms: ['rsa-pss-sha512'],
        requiredComponents: b23Components,
        requiredParameters: ['created', 'keyid'],
      }),
    })
    assert.equal(signature.label, 'sig-b23')
  })

  it('recreates B.2.4 response signature base', () => {
    assert.equal(
      createSignatureBase(rfcResponse(), { components: b24Components, parameters: b24Parameters }),
      [
        '"@status": 200',
        '"content-type": application/json',
        '"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:',
        '"content-length": 23',
        '"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
      ].join('\n'),
    )
  })

  it('verifies the published B.2.4 ECDSA P-256 signature', async () => {
    const message = signedResponse(
      'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
      `sig-b24=:${b24Signature}:`,
    )
    const signature = await verify(message, {
      verifier: p256Verifier,
      policy: verificationPolicy({
        algorithms: ['ecdsa-p256-sha256'],
        requiredComponents: b24Components,
        requiredParameters: ['created', 'keyid'],
      }),
    })
    assert.equal(signature.label, 'sig-b24')
  })

  it('recreates B.2.5 HMAC-SHA256 signature base', () => {
    assert.equal(
      createSignatureBase(rfcRequest(), { components: b25Components, parameters: b25Parameters }),
      [
        '"date": Tue, 20 Apr 2021 02:07:55 GMT',
        '"@authority": example.com',
        '"content-type": application/json',
        '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
      ].join('\n'),
    )
  })

  it('creates the exact deterministic B.2.5 HMAC-SHA256 signature', async () => {
    const fields = await createSignature(rfcRequest(), {
      signer: hmacSigner,
      components: b25Components,
      parameters: b25Parameters,
      label: 'sig-b25',
    })
    assert.equal(bytesToBase64(fields.signature), b25Signature)
    assert.equal(
      fields.signatureInput,
      'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    )
  })

  it('verifies the published B.2.5 HMAC-SHA256 signature', async () => {
    const message = signedRequest(
      'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
      `sig-b25=:${b25Signature}:`,
    )
    const signature = await verify(message, {
      verifier: hmacVerifier,
      policy: verificationPolicy({
        algorithms: ['hmac-sha256'],
        requiredComponents: b25Components,
        requiredParameters: ['created', 'keyid'],
      }),
    })
    assert.equal(signature.label, 'sig-b25')
  })

  it('recreates B.2.6 Ed25519 signature base', () => {
    assert.equal(
      createSignatureBase(rfcRequest(), { components: b26Components, parameters: b26Parameters }),
      [
        '"date": Tue, 20 Apr 2021 02:07:55 GMT',
        '"@method": POST',
        '"@path": /foo',
        '"@authority": example.com',
        '"content-type": application/json',
        '"content-length": 18',
        '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
      ].join('\n'),
    )
  })

  it('creates the exact deterministic B.2.6 Ed25519 signature', async () => {
    // Ed25519 is deterministic under RFC 8032, so this asserts the exact published bytes. WebKit
    // produces a different signature for the same key and message, so the vector is only asserted
    // where the host agrees with the RFC. The round trip below still covers WebKit.
    if (!(await ed25519IsDeterministic())) {
      return
    }
    const fields = await createSignature(rfcRequest(), {
      signer: ed25519Signer,
      components: b26Components,
      parameters: b26Parameters,
      label: 'sig-b26',
    })
    assert.equal(bytesToBase64(fields.signature), b26Signature)
    assert.equal(
      fields.signatureInput,
      'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    )
  })

  it('verifies the published B.2.6 Ed25519 signature', async () => {
    const message = signedRequest(
      'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
      `sig-b26=:${b26Signature}:`,
    )
    const signature = await verify(message, {
      verifier: ed25519Verifier,
      policy: verificationPolicy({
        algorithms: ['ed25519'],
        requiredComponents: b26Components,
        requiredParameters: ['created', 'keyid'],
      }),
    })
    assert.equal(signature.label, 'sig-b26')
  })
})

describe('RFC 9421 Appendix B.3 TLS-terminating proxy', () => {
  const components = ['@path', '@query', '@method', '@authority', 'client-cert']
  const parameters = [
    ['created', RFC_CREATED],
    ['keyid', 'test-key-ecc-p256'],
  ] as const
  const signatureInput =
    'ttrp=("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"'

  function proxyRequest(): Request {
    return fixtureRequest('https://service.internal.example/foo?param=Value&Pet=dog', {
      method: 'POST',
      headers: {
        date: 'Tue, 20 Apr 2021 02:07:55 GMT',
        'content-type': 'application/json',
        'content-length': '18',
        'client-cert': clientCert,
      },
      body: '{"hello": "world"}',
    })
  }

  it('recreates the published TLS-terminating proxy signature base', () => {
    assert.equal(
      createSignatureBase(proxyRequest(), { components, parameters }),
      [
        '"@path": /foo',
        '"@query": ?param=Value&Pet=dog',
        '"@method": POST',
        '"@authority": service.internal.example',
        `"client-cert": ${clientCert}`,
        '"@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"',
      ].join('\n'),
    )
  })

  it('verifies the published proxy ECDSA P-256 signature', async () => {
    const message = signedRequest(signatureInput, `ttrp=:${b3Signature}:`, proxyRequest())
    const signature = await verify(message, {
      verifier: p256Verifier,
      policy: verificationPolicy({
        algorithms: ['ecdsa-p256-sha256'],
        requiredComponents: components,
        requiredParameters: ['created', 'keyid'],
      }),
    })
    assert.equal(signature.label, 'ttrp')
  })
})

describe('RFC 9421 Appendix B.4 HTTP transformations', () => {
  const signatureInput =
    'transform=("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"'
  const components = ['@method', '@path', '@authority', 'accept']

  function transformedRequest(
    url = 'https://example.org/demo?name1=Value1&Name2=value2',
    options: { method?: string; accept?: string; headers?: HeadersInit } = {},
  ): Request {
    const headers = new Headers(options.headers)
    headers.set('accept', options.accept ?? 'application/json, */*')
    return signedRequest(
      signatureInput,
      `transform=:${b4Signature}:`,
      new Request(url, { method: options.method ?? 'GET', headers }),
    )
  }

  function verifyTransformation(message: Request) {
    return verify(message, {
      verifier: ed25519Verifier,
      policy: verificationPolicy({
        algorithms: ['ed25519'],
        requiredComponents: components,
        requiredParameters: ['created', 'keyid'],
      }),
    })
  }

  it('recreates and verifies the published transformation signature base', async () => {
    const request = transformedRequest(undefined, {
      headers: { date: 'Fri, 15 Jul 2022 14:24:55 GMT' },
    })
    assert.equal(
      createSignatureBase(request, {
        components,
        parameters: [
          ['created', RFC_CREATED],
          ['keyid', 'test-key-ed25519'],
        ],
      }),
      [
        '"@method": GET',
        '"@path": /demo',
        '"@authority": example.org',
        '"accept": application/json, */*',
        '"@signature-params": ("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"',
      ].join('\n'),
    )
    await assert.doesNotReject(verifyTransformation(request))
  })

  it('survives changes to uncovered query and header components', async () => {
    await assert.doesNotReject(
      verifyTransformation(
        transformedRequest('https://example.org/demo?name1=Value1&Name2=value2&param=added', {
          headers: { date: 'Fri, 15 Jul 2022 14:24:55 GMT', 'accept-language': 'en-US,en;q=0.5' },
        }),
      ),
    )
    await assert.doesNotReject(
      verifyTransformation(
        transformedRequest(undefined, {
          headers: { referer: 'https://developer.example.org/demo' },
        }),
      ),
    )
  })

  it('fails after covered method or authority transformations', async () => {
    await assert.rejects(
      verifyTransformation(
        transformedRequest('https://example.com/demo?name1=Value1&Name2=value2', {
          method: 'POST',
        }),
      ),
      /HTTP message signature verification failed/,
    )
  })

  it('fails when repeated field values are reordered', async () => {
    await assert.rejects(
      verifyTransformation(transformedRequest(undefined, { accept: '*/*, application/json' })),
      /HTTP message signature verification failed/,
    )
  })
})

describe('RFC 9421 Section 2.4 response bound to its request', () => {
  // The only worked example in the RFC that publishes a signature over ";req" components, so it is
  // the one vector that exercises response/request binding against bytes this package did not
  // produce. The ECDSA signature is non-deterministic, so only verification can be asserted.
  const requestDigest =
    'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:'
  const responseDigest =
    'sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:'
  const reqresSignature =
    'dMT/A/76ehrdBTD/2Xx8QuKV6FoyzEP/I9hdzKN8LQJLNgzU4W767HK05rx1i8meNQQgQPgQp8wq2ive3tV5Ag=='
  const created = 1_618_884_479
  const signatureInput =
    '("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req' +
    ' "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"'

  const components = [
    '@status',
    'content-digest',
    'content-type',
    component('@authority', [['req', true]]),
    component('@method', [['req', true]]),
    component('@path', [['req', true]]),
    component('content-digest', [['req', true]]),
  ]
  const parameters = [
    ['created', created],
    ['keyid', 'test-key-ecc-p256'],
  ] as const

  const triggeringRequest = () =>
    fixtureRequest('https://example.com/foo?param=Value&Pet=dog', {
      method: 'POST',
      headers: {
        date: 'Tue, 20 Apr 2021 02:07:55 GMT',
        'content-digest': requestDigest,
        'content-type': 'application/json',
        'content-length': '18',
      },
      body: '{"hello": "world"}',
    })

  const unavailableResponse = (fields: Readonly<Record<string, string>> = {}) =>
    new Response('{"busy": true, "message": "Your call is very important to us"}', {
      status: 503,
      headers: {
        date: 'Tue, 20 Apr 2021 02:07:56 GMT',
        'content-type': 'application/json',
        'content-length': '62',
        'content-digest': responseDigest,
        ...fields,
      },
    })

  it('recreates the published signature base', () => {
    assert.equal(
      createSignatureBase(unavailableResponse(), {
        request: triggeringRequest(),
        components,
        parameters,
      }),
      [
        '"@status": 503',
        `"content-digest": ${responseDigest}`,
        '"content-type": application/json',
        '"@authority";req: example.com',
        '"@method";req: POST',
        '"@path";req: /foo',
        `"content-digest";req: ${requestDigest}`,
        `"@signature-params": ${signatureInput}`,
      ].join('\n'),
    )
  })

  it('verifies the published ECDSA P-256 signature over request-bound components', async () => {
    const signature = await verify(
      unavailableResponse({
        'signature-input': `reqres=${signatureInput}`,
        signature: `reqres=:${reqresSignature}:`,
      }),
      {
        request: triggeringRequest(),
        verifier: p256Verifier,
        policy: verificationPolicy({
          requiredComponents: components,
          requiredParameters: ['created', 'keyid'],
          algorithms: ['ecdsa-p256-sha256'],
          now: created,
        }),
      },
    )
    assert.equal(signature.label, 'reqres')
    assert.equal(signature.algorithm, 'ecdsa-p256-sha256')
  })

  it('fails when the related request is not the one that was signed', async () => {
    await assert.rejects(
      verify(
        unavailableResponse({
          'signature-input': `reqres=${signatureInput}`,
          signature: `reqres=:${reqresSignature}:`,
        }),
        {
          request: new Request(triggeringRequest(), {
            headers: { 'content-digest': responseDigest },
          }),
          verifier: p256Verifier,
          policy: verificationPolicy({
            requiredComponents: components,
            requiredParameters: ['created', 'keyid'],
            algorithms: ['ecdsa-p256-sha256'],
            now: created,
          }),
        },
      ),
      /HTTP message signature verification failed/,
    )
  })
})
