import {
  createSignedFetch,
  createSigningFetch,
  createVerifyingFetch,
  date,
  displayString,
} from '../index.ts'
import type {
  SignatureParameters,
  SignedFetchOptions,
  SignerFactory,
  SigningFetchOptions,
  StructuredFieldDate,
  StructuredFieldDisplayString,
  VerifierFactory,
  VerifyingFetchOptions,
} from '../index.ts'

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

const structuredDate: StructuredFieldDate = date(1_659_578_233)
const structuredDisplayString: StructuredFieldDisplayString = displayString('snowman ☃')
const parameters: SignatureParameters = { structuredDate, structuredDisplayString }
void parameters

const signingOptions: SigningFetchOptions = { sign: { signer, components: ['@method'] } }
const verifyingOptions: VerifyingFetchOptions = {
  verify: {
    verifier,
    policy: {
      requiredComponents: ['@status'],
      requiredParameters: ['created'],
      algorithms: ['ed25519'],
    },
  },
}
const signedOptions: SignedFetchOptions = { ...signingOptions, verify: verifyingOptions.verify }

const signingFetch: typeof globalThis.fetch = createSigningFetch(signingOptions)
const verifyingFetch: typeof globalThis.fetch = createVerifyingFetch(verifyingOptions)
const signedFetch: typeof globalThis.fetch = createSignedFetch(signedOptions)

void signingFetch
void verifyingFetch
void signedFetch
