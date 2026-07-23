import type { SignerFactory, VerifierFactory } from '../index.ts'

let privateKey!: CryptoKey
let publicKey!: CryptoKey

const signer: SignerFactory = () => ({
  type: 'signer',
  alg: 'ed25519',
  async sign(data) {
    return new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, data))
  },
})

const verifier: VerifierFactory = () => ({
  type: 'verifier',
  alg: 'ed25519',
  async verify(data, signature) {
    return crypto.subtle.verify('Ed25519', publicKey, signature, data)
  },
})

void signer
void verifier
