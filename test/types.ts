import {
  createSignatureBase,
  createSignedFetch,
  createSigningFetch,
  createVerifyingFetch,
  date,
  displayString,
  parseStructuredField,
  serializeStructuredField,
  VerificationError,
} from '../index.ts'
import type {
  SignableRequest,
  SignableResponse,
  SignatureParameters,
  StructuredFieldDictionary,
  StructuredFieldItem,
  StructuredFieldList,
  SignedFetchOptions,
  SignerFactory,
  SigningFetchOptions,
  StructuredFieldDate,
  StructuredFieldDisplayString,
  VerificationErrorCode,
  VerifierFactory,
  VerifyingFetchOptions,
} from '../index.ts'

let privateKey!: CryptoKey
let publicKey!: CryptoKey

const verificationCause = new Error('key store unavailable')
const verificationError = new VerificationError('unknown_key', 'Unknown signing key', {
  cause: verificationCause,
})
const verificationCode: VerificationErrorCode = verificationError.code

void verificationCode

const signer: SignerFactory = () => ({
  alg: 'ed25519',
  async sign(data) {
    return new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, data))
  },
})

const verifier: VerifierFactory = () => ({
  alg: 'ed25519',
  async verify(data, signature) {
    return crypto.subtle.verify('Ed25519', publicKey, signature, data)
  },
})

// A provider backed by a synchronous library needs no Promise wrapper.
const synchronousSigner: SignerFactory = () => ({
  alg: 'ed25519',
  sign(data) {
    return signSynchronously(data)
  },
})

const synchronousVerifier: VerifierFactory = () => ({
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

// A plain descriptor is accepted with no cast, and a Fetch message still is.
const descriptorRequest: SignableRequest = {
  method: 'POST',
  url: 'https://api.example/orders',
  headers: { 'content-type': 'application/json', 'x-multi': ['one', 'two'] },
}
const descriptorResponse: SignableResponse = { status: 200, headers: new Headers() }
const fetchRequest: SignableRequest = new Request('https://api.example/orders')
const fetchResponse: SignableResponse = new Response('')

void createSignatureBase(descriptorRequest, { components: ['@method'] })
void createSignatureBase(descriptorResponse, { components: ['@status'] })
void createSignatureBase(fetchRequest, { components: ['@method'] })
void createSignatureBase(fetchResponse, { components: ['@status'] })

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
