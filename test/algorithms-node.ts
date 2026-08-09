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
  ecdsaP384Sha384Signer,
  ecdsaP384Sha384Verifier,
  generateEcdsaP384Sha384KeyPair,
  type MessageSignature,
  type VerificationContext,
} from '../index.ts'

// Kept out of test/algorithms.ts so that the rest of that file stays portable: it is the only case
// there that needs node:crypto, and importing it excluded every other algorithm case from the
// browser and Cloudflare Workers suites.

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

describe('node:crypto interoperability', () => {
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
})
