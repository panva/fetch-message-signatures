import {
  createSignedFetch,
  createSigningFetch,
  createVerifyingFetch,
  date,
  displayString,
  parseStructuredField,
  serializeStructuredField,
} from '../index.ts'
import type {
  SignatureParameters,
  StructuredFieldDictionary,
  StructuredFieldItem,
  StructuredFieldList,
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

// A provider backed by a synchronous library needs no Promise wrapper.
const synchronousSigner: SignerFactory = () => ({
  type: 'signer',
  alg: 'ed25519',
  sign(data) {
    return signSynchronously(data)
  },
})

const synchronousVerifier: VerifierFactory = () => ({
  type: 'verifier',
  alg: 'ed25519',
  verify(data, signature) {
    return verifySynchronously(data, signature)
  },
})

declare function signSynchronously(data: Uint8Array): Uint8Array
declare function verifySynchronously(data: Uint8Array, signature: Uint8Array): boolean

void signer
void verifier
void synchronousSigner
void synchronousVerifier

// A literal top-level type narrows the result, so no assertion is needed at a call site.
const parsedDictionary: StructuredFieldDictionary = parseStructuredField('a=1', 'dictionary')
const parsedList: StructuredFieldList = parseStructuredField('1, 2', 'list')
const parsedItem: StructuredFieldItem = parseStructuredField('1', 'item')

const roundTripped: string = serializeStructuredField(parsedDictionary, 'dictionary')

void parsedList
void parsedItem
void roundTripped

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
