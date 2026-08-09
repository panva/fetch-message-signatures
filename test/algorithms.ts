import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  ecdsaP256Sha256Signer,
  ecdsaP256Sha256Verifier,
  ecdsaP384Sha384Signer,
  ecdsaP384Sha384Verifier,
  ed25519Signer,
  ed25519Verifier,
  generateEcdsaP256Sha256KeyPair,
  generateEcdsaP384Sha384KeyPair,
  generateEd25519KeyPair,
  generateRsaPssSha512KeyPair,
  generateRsaV1_5Sha256KeyPair,
  rsaPssSha512Signer,
  rsaPssSha512Verifier,
  rsaV1_5Sha256Signer,
  rsaV1_5Sha256Verifier,
  sign,
  verify,
  type MessageSignature,
  type SignerFactory,
  type SynchronousVerifierFactory,
} from '../index.ts'

interface KeyMaterial {
  readonly signingKey: CryptoKey
  readonly verificationKey: CryptoKey
}

interface AlgorithmCase {
  readonly identifier: string
  readonly signatureLength: number
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

const providerSignature: MessageSignature = {
  label: 'test',
  components: [],
  parameters: [],
  signature: new Uint8Array(),
}
const providerContext = { message: new Request('https://example.com/') }
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
    const generated = await Promise.all(algorithms.map(keysFor))

    for (const [index, algorithm] of algorithms.entries()) {
      assertKeyMetadata(algorithm, generated[index]!, false)
    }
  })

  it('generates extractable keys only when requested', async () => {
    const generated = await Promise.all(algorithms.map((algorithm) => algorithm.generate(true)))

    for (const [index, algorithm] of algorithms.entries()) {
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
    for (const algorithm of algorithms) {
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
    for (const algorithm of algorithms) {
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
    for (const algorithm of algorithms) {
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
    const p256 = algorithmCase('ecdsa-p256-sha256')
    const keys = await keysFor(p256)
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

    assert.throws(() => p256.signer(privateKeyWithoutSign), /with "sign" usage/)
    assert.throws(() => p256.verifier(publicKeyWithoutVerify), /with "verify" usage/)
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
