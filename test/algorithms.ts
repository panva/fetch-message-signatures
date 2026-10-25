import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  createSignatureBase,
  ecdsaP256Sha256Signer,
  ecdsaP256Sha256Verifier,
  ecdsaP384Sha384Signer,
  ecdsaP384Sha384Verifier,
  ed25519Signer,
  ed25519Verifier,
  generateEcdsaP256Sha256KeyPair,
  generateEcdsaP384Sha384KeyPair,
  generateEd25519KeyPair,
  generateMlDsa44KeyPair,
  generateMlDsa65KeyPair,
  generateMlDsa87KeyPair,
  generateRsaPssSha512KeyPair,
  generateRsaV1_5Sha256KeyPair,
  mlDsa44Signer,
  mlDsa44Verifier,
  mlDsa65Signer,
  mlDsa65Verifier,
  mlDsa87Signer,
  mlDsa87Verifier,
  rsaPssSha512Signer,
  rsaPssSha512Verifier,
  rsaV1_5Sha256Signer,
  rsaV1_5Sha256Verifier,
  sign,
  verify,
  type MessageSignature,
  type SignerFactory,
  type SynchronousVerifierFactory,
  type VerificationContext,
} from '../index.ts'
import { pqVectors } from './fixtures/httpsig-pq.ts'
import { base64ToBytes, fixtureRequest } from './support.ts'

interface KeyMaterial {
  readonly signingKey: CryptoKey
  readonly verificationKey: CryptoKey
}

interface AlgorithmCase {
  readonly identifier: string
  readonly signatureLength: number
  readonly optionalWebCryptoAlgorithm?: string
  readonly generate: (extractable?: boolean) => Promise<KeyMaterial>
  readonly signer: (key: CryptoKey) => SignerFactory
  readonly verifier: (key: CryptoKey) => SynchronousVerifierFactory
  readonly assertAlgorithm: (key: CryptoKey) => void
}

function ecAlgorithm(key: CryptoKey): EcKeyAlgorithm {
  return key.algorithm as EcKeyAlgorithm
}

function rsaAlgorithm(key: CryptoKey): RsaHashedKeyAlgorithm {
  return key.algorithm as RsaHashedKeyAlgorithm
}

const pqAlgorithms: ReadonlyArray<AlgorithmCase> = [
  {
    identifier: 'ml-dsa-44',
    signatureLength: 2420,
    optionalWebCryptoAlgorithm: 'ML-DSA-44',
    async generate(extractable) {
      const pair = await generateMlDsa44KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: mlDsa44Signer,
    verifier: mlDsa44Verifier,
    assertAlgorithm(key) {
      assert.equal(key.algorithm.name, 'ML-DSA-44')
    },
  },
  {
    identifier: 'ml-dsa-65',
    signatureLength: 3309,
    optionalWebCryptoAlgorithm: 'ML-DSA-65',
    async generate(extractable) {
      const pair = await generateMlDsa65KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: mlDsa65Signer,
    verifier: mlDsa65Verifier,
    assertAlgorithm(key) {
      assert.equal(key.algorithm.name, 'ML-DSA-65')
    },
  },
  {
    identifier: 'ml-dsa-87',
    signatureLength: 4627,
    optionalWebCryptoAlgorithm: 'ML-DSA-87',
    async generate(extractable) {
      const pair = await generateMlDsa87KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: mlDsa87Signer,
    verifier: mlDsa87Verifier,
    assertAlgorithm(key) {
      assert.equal(key.algorithm.name, 'ML-DSA-87')
    },
  },
]

const algorithms: ReadonlyArray<AlgorithmCase> = [
  {
    identifier: 'ecdsa-p256-sha256',
    signatureLength: 64,
    async generate(extractable) {
      const pair = await generateEcdsaP256Sha256KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: ecdsaP256Sha256Signer,
    verifier: ecdsaP256Sha256Verifier,
    assertAlgorithm(key) {
      const algorithm = ecAlgorithm(key)
      assert.equal(algorithm.name, 'ECDSA')
      assert.equal(algorithm.namedCurve, 'P-256')
    },
  },
  {
    identifier: 'ecdsa-p384-sha384',
    signatureLength: 96,
    async generate(extractable) {
      const pair = await generateEcdsaP384Sha384KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: ecdsaP384Sha384Signer,
    verifier: ecdsaP384Sha384Verifier,
    assertAlgorithm(key) {
      const algorithm = ecAlgorithm(key)
      assert.equal(algorithm.name, 'ECDSA')
      assert.equal(algorithm.namedCurve, 'P-384')
    },
  },
  {
    identifier: 'ed25519',
    signatureLength: 64,
    async generate(extractable) {
      const pair = await generateEd25519KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: ed25519Signer,
    verifier: ed25519Verifier,
    assertAlgorithm(key) {
      assert.equal(key.algorithm.name, 'Ed25519')
    },
  },
  {
    identifier: 'rsa-pss-sha512',
    signatureLength: 256,
    async generate(extractable) {
      const pair = await generateRsaPssSha512KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: rsaPssSha512Signer,
    verifier: rsaPssSha512Verifier,
    assertAlgorithm(key) {
      const algorithm = rsaAlgorithm(key)
      assert.equal(algorithm.name, 'RSA-PSS')
      assert.equal(algorithm.hash.name, 'SHA-512')
      assert.equal(algorithm.modulusLength, 2048)
      assert.deepEqual(new Uint8Array(algorithm.publicExponent), new Uint8Array([1, 0, 1]))
    },
  },
  {
    identifier: 'rsa-v1_5-sha256',
    signatureLength: 256,
    async generate(extractable) {
      const pair = await generateRsaV1_5Sha256KeyPair(extractable)
      return { signingKey: pair.privateKey, verificationKey: pair.publicKey }
    },
    signer: rsaV1_5Sha256Signer,
    verifier: rsaV1_5Sha256Verifier,
    assertAlgorithm(key) {
      const algorithm = rsaAlgorithm(key)
      assert.equal(algorithm.name, 'RSASSA-PKCS1-v1_5')
      assert.equal(algorithm.hash.name, 'SHA-256')
      assert.equal(algorithm.modulusLength, 2048)
      assert.deepEqual(new Uint8Array(algorithm.publicExponent), new Uint8Array([1, 0, 1]))
    },
  },
  ...pqAlgorithms,
]

function algorithmCase(identifier: string): AlgorithmCase {
  const algorithm = algorithms.find((candidate) => candidate.identifier === identifier)
  assert.ok(algorithm)
  return algorithm
}

const defaultKeyMaterial = new Map<string, Promise<KeyMaterial>>()

function keysFor(algorithm: AlgorithmCase): Promise<KeyMaterial> {
  let keys = defaultKeyMaterial.get(algorithm.identifier)
  if (keys === undefined) {
    keys = algorithm.generate()
    defaultKeyMaterial.set(algorithm.identifier, keys)
  }
  return keys
}

let supportedAlgorithmCases: Promise<ReadonlyArray<AlgorithmCase>> | undefined

/** Probe the native algorithm so that a broken helper cannot be mistaken for missing support. */
function supportedAlgorithms(): Promise<ReadonlyArray<AlgorithmCase>> {
  supportedAlgorithmCases ??= Promise.all(
    algorithms.map(async (algorithm) => {
      if (algorithm.optionalWebCryptoAlgorithm !== undefined) {
        try {
          await crypto.subtle.generateKey(algorithm.optionalWebCryptoAlgorithm, false, [
            'sign',
            'verify',
          ])
        } catch (error) {
          if (error instanceof Error && error.name === 'NotSupportedError') {
            return undefined
          }
          throw error
        }
      }
      return algorithm
    }),
  ).then((supported) => supported.filter((algorithm) => algorithm !== undefined))
  return supportedAlgorithmCases
}

const providerSignature: MessageSignature = {
  label: 'test',
  components: [],
  parameters: [],
  signature: new Uint8Array(),
}
const providerContext = Object.freeze({
  message: Object.freeze({
    method: 'GET',
    url: 'https://example.com/',
    headers: Object.freeze({}),
    trailers: Object.freeze({}),
  }),
}) satisfies VerificationContext
const message = new TextEncoder().encode('HTTP Message Signatures')
const differentMessage = new TextEncoder().encode('HTTP Message Signaturez')
const created = 1_618_884_473

function assertKeyMetadata(
  algorithm: AlgorithmCase,
  keys: KeyMaterial,
  extractable: boolean,
): void {
  algorithm.assertAlgorithm(keys.signingKey)
  algorithm.assertAlgorithm(keys.verificationKey)

  assert.notStrictEqual(keys.signingKey, keys.verificationKey)
  assert.equal(keys.signingKey.type, 'private')
  assert.equal(keys.verificationKey.type, 'public')
  assert.equal(keys.signingKey.extractable, extractable)
  assert.equal(keys.verificationKey.extractable, true)
  assert.deepEqual(keys.signingKey.usages, ['sign'])
  assert.deepEqual(keys.verificationKey.usages, ['verify'])
}

describe('Web Cryptography algorithm helpers', () => {
  it('generates non-extractable signing keys by default with the expected metadata and usages', async () => {
    const supported = await supportedAlgorithms()
    const generated = await Promise.all(supported.map(keysFor))

    for (const [index, algorithm] of supported.entries()) {
      assertKeyMetadata(algorithm, generated[index]!, false)
    }
  })

  it('generates extractable keys only when requested', async () => {
    const supported = await supportedAlgorithms()
    const generated = await Promise.all(supported.map((algorithm) => algorithm.generate(true)))

    for (const [index, algorithm] of supported.entries()) {
      assertKeyMetadata(algorithm, generated[index]!, true)
    }
  })

  it('rejects invalid extractable values in every key generator', async () => {
    const invalidValues = [null, 0, 'true', {}]

    for (const algorithm of algorithms) {
      const generate = algorithm.generate as unknown as (
        extractable: unknown,
      ) => Promise<KeyMaterial>
      for (const invalid of invalidValues) {
        await assert.rejects(generate(invalid), {
          name: 'TypeError',
          message: '"extractable" must be a boolean',
        })
      }
    }
  })

  it('signs and verifies bytes with every built-in algorithm', async () => {
    for (const algorithm of await supportedAlgorithms()) {
      const keys = await keysFor(algorithm)
      const signerFactory = algorithm.signer(keys.signingKey)
      const verifierFactory = algorithm.verifier(keys.verificationKey)
      const signer = signerFactory()
      const verifier = verifierFactory(providerSignature, providerContext)

      assert.equal(signer.alg, algorithm.identifier)
      assert.equal(verifier.alg, algorithm.identifier)

      const signature = await signer.sign(message)
      assert.ok(signature instanceof Uint8Array)
      assert.equal(signature.byteLength, algorithm.signatureLength)
      const verificationSignature = new Uint8Array(signature)
      assert.equal(await verifier.verify(message, verificationSignature), true)
      assert.equal(await verifier.verify(differentMessage, verificationSignature), false)
    }
  })

  it('round trips complete HTTP message signatures with every built-in algorithm', async () => {
    for (const algorithm of await supportedAlgorithms()) {
      const keys = await keysFor(algorithm)
      const signed = await sign(
        new Request(`https://api.example/${algorithm.identifier}?page=1`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{"ok":true}',
        }),
        {
          signer: algorithm.signer(keys.signingKey),
          components: ['@method', '@authority', '@path', 'content-type'],
          parameters: { created, alg: algorithm.identifier, keyid: `${algorithm.identifier}-key` },
        },
      )

      const verified = await verify(signed, {
        verifier: algorithm.verifier(keys.verificationKey),
        policy: {
          requiredComponents: ['@method', '@authority', '@path', 'content-type'],
          requiredParameters: ['created', 'alg', 'keyid'],
          algorithms: [algorithm.identifier],
          maxAge: 60,
          now: created,
        },
      })

      assert.equal(verified.label, 'sig1')
      assert.equal(verified.algorithm, algorithm.identifier)
      assert.deepEqual(
        verified.parameters.find(([name]) => name === 'alg'),
        ['alg', algorithm.identifier],
      )
    }
  })

  it('rejects public signing keys and private verification keys synchronously', async () => {
    for (const algorithm of await supportedAlgorithms()) {
      const keys = await keysFor(algorithm)
      assert.throws(
        () => algorithm.signer(keys.verificationKey),
        new RegExp(`private CryptoKey for "${algorithm.identifier}"`),
      )
      assert.throws(
        () => algorithm.verifier(keys.signingKey),
        new RegExp(`public CryptoKey for "${algorithm.identifier}"`),
      )
    }
  })

  it('rejects keys without the required usage synchronously', async () => {
    for (const algorithm of await supportedAlgorithms()) {
      const keys = await keysFor(algorithm)
      const privateKeyWithoutSign: CryptoKey = {
        algorithm: keys.signingKey.algorithm,
        extractable: keys.signingKey.extractable,
        type: keys.signingKey.type,
        usages: [],
      }
      const publicKeyWithoutVerify: CryptoKey = {
        algorithm: keys.verificationKey.algorithm,
        extractable: keys.verificationKey.extractable,
        type: keys.verificationKey.type,
        usages: [],
      }

      assert.throws(() => algorithm.signer(privateKeyWithoutSign), /with "sign" usage/)
      assert.throws(() => algorithm.verifier(publicKeyWithoutVerify), /with "verify" usage/)
    }
  })

  it('rejects ML-DSA keys for another parameter set synchronously even on unsupported runtimes', () => {
    for (const expected of pqAlgorithms) {
      for (const other of pqAlgorithms) {
        if (expected === other) {
          continue
        }
        const key: CryptoKey = {
          algorithm: { name: other.identifier.toUpperCase() },
          extractable: false,
          type: 'private',
          usages: ['sign'],
        }
        assert.throws(() => expected.signer(key), new RegExp(expected.identifier))
        assert.throws(
          () => expected.verifier({ ...key, type: 'public', usages: ['verify'] }),
          new RegExp(expected.identifier),
        )
      }
    }
  })

  it('rejects malformed ML-DSA signatures, non-empty contexts, and external pre-hashing', async () => {
    for (const algorithm of await supportedAlgorithms()) {
      if (algorithm.optionalWebCryptoAlgorithm === undefined) {
        continue
      }
      const keys = await keysFor(algorithm)
      const signer = algorithm.signer(keys.signingKey)()
      const verifier = algorithm.verifier(keys.verificationKey)(providerSignature, providerContext)
      const signature = new Uint8Array(await signer.sign(message))
      const modified = new Uint8Array(signature)
      modified[0] = modified[0]! ^ 1
      const extended = new Uint8Array(signature.length + 1)
      extended.set(signature)
      for (const malformed of [new Uint8Array(), modified, signature.slice(1), extended]) {
        assert.equal(await verifier.verify(message, malformed), false)
      }

      const name = keys.signingKey.algorithm.name
      const context = new TextEncoder().encode('HTTP Message Signatures')
      assert.equal(
        await crypto.subtle.verify(
          { name, context } as Algorithm,
          keys.verificationKey,
          signature,
          message,
        ),
        false,
      )
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', message))
      assert.equal(await verifier.verify(digest, signature), false)
      const overDigest = await crypto.subtle.sign(name, keys.signingKey, digest)
      assert.equal(await verifier.verify(message, new Uint8Array(overDigest)), false)
    }
  })

  it('recreates and verifies all C2SP httpsig-pq v1.0.1 conformance vectors', async () => {
    const supported = await supportedAlgorithms()
    for (const vector of pqVectors) {
      const request = fixtureRequest('https://example.com/foo?param=Value&Pet=dog', {
        headers: { host: 'example.com', date: 'Mon, 06 Jul 2026 20:00:00 GMT' },
      })
      const components = ['@method', '@target-uri', 'host', 'date']
      const created = 1_783_368_000
      const keyid = `test-key-mldsa${vector.algorithm.slice(-2)}`
      assert.equal(
        createSignatureBase(request, {
          components,
          parameters: { created, keyid, alg: vector.algorithm },
        }),
        new TextDecoder().decode(base64ToBytes(vector.signatureBase)),
      )

      if (!supported.some((algorithm) => algorithm.identifier === vector.algorithm)) {
        continue
      }
      const algorithm = algorithmCase(vector.algorithm)
      const publicKey = await crypto.subtle.importKey(
        'spki',
        base64ToBytes(vector.publicKeySpki),
        vector.algorithm.toUpperCase(),
        false,
        ['verify'],
      )
      request.headers.set('signature-input', vector.signatureInput)
      request.headers.set('signature', `sig1=:${vector.signature}:`)
      const verified = await verify(request, {
        verifier: algorithm.verifier(publicKey),
        policy: {
          requiredComponents: components,
          requiredParameters: ['created', 'keyid', 'alg'],
          algorithms: [vector.algorithm],
          now: created,
          maxAge: 60,
        },
      })
      assert.equal(verified.algorithm, vector.algorithm)
    }
  })

  it('rejects ECDSA keys on the wrong curve synchronously', async () => {
    const [p256, p384] = await Promise.all([
      keysFor(algorithmCase('ecdsa-p256-sha256')),
      keysFor(algorithmCase('ecdsa-p384-sha384')),
    ])

    assert.throws(() => ecdsaP256Sha256Signer(p384.signingKey), /ecdsa-p256-sha256/)
    assert.throws(() => ecdsaP256Sha256Verifier(p384.verificationKey), /ecdsa-p256-sha256/)
    assert.throws(() => ecdsaP384Sha384Signer(p256.signingKey), /ecdsa-p384-sha384/)
    assert.throws(() => ecdsaP384Sha384Verifier(p256.verificationKey), /ecdsa-p384-sha384/)
  })

  it('rejects RSA keys bound to the wrong padding or digest synchronously', async () => {
    const [pss, v15] = await Promise.all([
      keysFor(algorithmCase('rsa-pss-sha512')),
      keysFor(algorithmCase('rsa-v1_5-sha256')),
    ])
    // An RSA-PSS key carries its digest, and signing with the wrong one would name a digest the
    // signature was not computed with.
    const pssSha256 = (await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair

    assert.throws(() => rsaPssSha512Signer(v15.signingKey), /rsa-pss-sha512/)
    assert.throws(() => rsaPssSha512Verifier(v15.verificationKey), /rsa-pss-sha512/)
    assert.throws(() => rsaV1_5Sha256Signer(pss.signingKey), /rsa-v1_5-sha256/)
    assert.throws(() => rsaV1_5Sha256Verifier(pss.verificationKey), /rsa-v1_5-sha256/)
    assert.throws(() => rsaPssSha512Signer(pssSha256.privateKey), /rsa-pss-sha512/)
    assert.throws(() => rsaPssSha512Verifier(pssSha256.publicKey), /rsa-pss-sha512/)
  })

  it('generates RSA keys at a requested modulus length', async () => {
    const [pss, v15] = await Promise.all([
      generateRsaPssSha512KeyPair(false, 3072),
      generateRsaV1_5Sha256KeyPair(false, 3072),
    ])

    for (const pair of [pss, v15]) {
      assert.equal(rsaAlgorithm(pair.privateKey).modulusLength, 3072)
      assert.equal(rsaAlgorithm(pair.publicKey).modulusLength, 3072)
    }

    // An RSA signature is exactly as long as the modulus, so the requested length reaches the wire.
    assert.equal((await rsaPssSha512Signer(pss.privateKey)().sign(message)).byteLength, 384)
    assert.equal((await rsaV1_5Sha256Signer(v15.privateKey)().sign(message)).byteLength, 384)
  })

  it('rejects invalid modulus lengths in both RSA key generators', async () => {
    const generators = [generateRsaPssSha512KeyPair, generateRsaV1_5Sha256KeyPair]
    const invalidValues = [null, '2048', 2048.5, 0, -2048, Number.NaN, {}]

    for (const generate of generators) {
      const generateWith = generate as unknown as (
        extractable: boolean,
        modulusLength: unknown,
      ) => Promise<CryptoKeyPair>
      for (const invalid of invalidValues) {
        await assert.rejects(generateWith(false, invalid), {
          name: 'TypeError',
          message: '"modulusLength" must be a positive integer',
        })
      }
    }
  })
})
