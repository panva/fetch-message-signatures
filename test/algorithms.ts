import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto'
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
  sign,
  verify,
  type MessageSignature,
  type SignerFactory,
  type VerifierFactory,
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
  readonly verifier: (key: CryptoKey) => VerifierFactory
  readonly assertAlgorithm: (key: CryptoKey) => void
}

function ecAlgorithm(key: CryptoKey): EcKeyAlgorithm {
  return key.algorithm as EcKeyAlgorithm
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

  it('signs and verifies bytes with all three algorithms', async () => {
    for (const algorithm of algorithms) {
      const keys = await keysFor(algorithm)
      const signerFactory = algorithm.signer(keys.signingKey)
      const verifierFactory = algorithm.verifier(keys.verificationKey)
      const signer = signerFactory()
      const verifier = verifierFactory(providerSignature, providerContext)

      assert.equal(signer.type, 'signer')
      assert.equal(signer.alg, algorithm.identifier)
      assert.equal(verifier.type, 'verifier')
      assert.equal(verifier.alg, algorithm.identifier)

      const signature = await signer.sign(message)
      assert.ok(signature instanceof Uint8Array)
      assert.equal(signature.byteLength, algorithm.signatureLength)
      const verificationSignature = new Uint8Array(signature)
      assert.equal(await verifier.verify(message, verificationSignature), true)
      assert.equal(await verifier.verify(differentMessage, verificationSignature), false)
    }
  })

  it('round trips complete HTTP message signatures with all three algorithms', async () => {
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

  it('interoperates with node:crypto for ECDSA P-384 in both directions', async () => {
    const p384 = await generateEcdsaP384Sha384KeyPair(true)
    const [p384Private, p384Public] = await Promise.all([
      crypto.subtle.exportKey('pkcs8', p384.privateKey),
      crypto.subtle.exportKey('spki', p384.publicKey),
    ])
    const p384PrivateKey = createPrivateKey({
      key: Buffer.from(p384Private),
      format: 'der',
      type: 'pkcs8',
    })
    const p384PublicKey = createPublicKey({
      key: Buffer.from(p384Public),
      format: 'der',
      type: 'spki',
    })

    const p384WebCryptoSignature = await ecdsaP384Sha384Signer(p384.privateKey)().sign(message)
    assert.equal(
      nodeVerify(
        'sha384',
        message,
        { key: p384PublicKey, dsaEncoding: 'ieee-p1363' },
        p384WebCryptoSignature,
      ),
      true,
    )
    const p384NodeSignature = new Uint8Array(
      nodeSign('sha384', message, { key: p384PrivateKey, dsaEncoding: 'ieee-p1363' }),
    )
    assert.equal(
      await ecdsaP384Sha384Verifier(p384.publicKey)(providerSignature, providerContext).verify(
        message,
        p384NodeSignature,
      ),
      true,
    )
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
})
