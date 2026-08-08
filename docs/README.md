# fetch-message-signatures

HTTP Message Signatures for the Fetch API.

Implements the sender, recipient, and `Accept-Signature` operations from [RFC
9421](https://www.rfc-editor.org/info/rfc9421/) on top of `Request`, `Response`, `Headers`, and
`fetch`. The module constructs and parses the required Structured Fields, includes Web
Cryptography implementations of the ECDSA, Ed25519, and RSA signature algorithms, and supports
custom cryptographic providers.

## Examples

Sign and verify a request with Ed25519 through Web Cryptography.

```ts
import * as FetchSig from 'fetch-message-signatures'

const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
const signer = FetchSig.ed25519Signer(privateKey)
const verifyWithKey = FetchSig.ed25519Verifier(publicKey)

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = FetchSig.getSignatureParameter(signature, 'keyid')
  if (keyid !== 'example-key') throw new Error('Untrusted signing key')
  return verifyWithKey(signature, context)
}

const request = await FetchSig.sign(new Request('https://api.example/orders/123'), {
  signer,
  components: ['@method', '@authority', '@path'],
  parameters: { alg: 'ed25519', keyid: 'example-key' },
})

// sig1=("@method" "@authority" "@path");created=1735689600;alg="ed25519";keyid="example-key"
console.log(request.headers.get('signature-input'))

const verified = await FetchSig.verify(request, {
  verifier,
  policy: {
    requiredComponents: ['@method', '@authority', '@path'],
    requiredParameters: ['created', 'alg', 'keyid'],
    algorithms: ['ed25519'],
    maxAge: 60,
  },
})

// sig1 ed25519
console.log(verified.label, verified.algorithm)
```

Send signed requests through `fetch`. Three wrappers cover the three directions:

| wrapper                  | outgoing request | incoming response |
| ------------------------ | ---------------- | ----------------- |
| `createSigningFetch()`   | signed           | not verified      |
| `createVerifyingFetch()` | not signed       | verified          |
| `createSignedFetch()`    | signed           | verified          |

```ts
import * as FetchSig from 'fetch-message-signatures'

declare const clientPrivateKey: CryptoKey
declare const serverPublicKey: CryptoKey

const signedFetch = FetchSig.createSignedFetch({
  sign: {
    signer: FetchSig.ed25519Signer(clientPrivateKey),
    components: ['@method', '@authority', '@path'],
    parameters: { alg: 'ed25519', keyid: 'client-key' },
  },
  verify: {
    verifier: FetchSig.ed25519Verifier(serverPublicKey),
    policy: {
      requiredComponents: ['@status', FetchSig.component('@path', { req: true })],
      requiredParameters: ['created', 'keyid'],
      algorithms: ['ed25519'],
      maxAge: 60,
    },
  },
})

// Used exactly like fetch. The request is signed on the way out, and the response is
// verified against that exact request before this resolves.
const response = await signedFetch('https://api.example/orders/123')
const order = await response.json()
```

## Fetch Wrappers

| Function | Description |
| :------ | :------ |
| [createSignedFetch](functions/createSignedFetch.md) | Drop-in `fetch` that signs outgoing requests and verifies responses, in both directions. |
| [createSigningFetch](functions/createSigningFetch.md) | Drop-in `fetch` that signs outgoing requests only. Responses are returned unverified. |
| [createVerifyingFetch](functions/createVerifyingFetch.md) | Drop-in `fetch` that verifies responses only. Requests are sent unsigned. |

## Sender

| Function | Description |
| :------ | :------ |
| [appendSignature](functions/appendSignature.md) | Adds one signature to `Headers` and returns a new `Headers` object. |
| [createSignature](functions/createSignature.md) | Creates one HTTP message signature without modifying or cloning the Fetch message. |
| [sign](functions/sign.md) | Creates and appends one HTTP message signature. |

## Recipient

| Function | Description |
| :------ | :------ |
| [getSignatureParameter](functions/getSignatureParameter.md) | Returns one signature metadata parameter by name, or `undefined` when the signature omits it. |
| [getSignatures](functions/getSignatures.md) | Parses and pairs every signature carried by a Fetch message, so that an application can choose which label to verify. |
| [parseSignature](functions/parseSignature.md) | Parses a `Signature` field value into its labeled signature byte sequences. |
| [parseSignatureInput](functions/parseSignatureInput.md) | Parses a `Signature-Input` field value into its labeled covered component lists and signature metadata parameters. |
| [verify](functions/verify.md) | Verifies and applies explicit application policy to one HTTP message signature. |

## Signature Negotiation

| Function | Description |
| :------ | :------ |
| [appendAcceptSignature](functions/appendAcceptSignature.md) | Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message. |
| [createAcceptSignature](functions/createAcceptSignature.md) | Serializes one or more signature requests as an `Accept-Signature` Structured Field Dictionary. |
| [createRequestedSignature](functions/createRequestedSignature.md) | Fulfills one parsed `Accept-Signature` request without modifying the target Fetch message. |
| [getSignatureRequests](functions/getSignatureRequests.md) | Parses every signature request carried by a Fetch message and checks that each requested component applies to the message that would be signed. |
| [parseAcceptSignature](functions/parseAcceptSignature.md) | Parses an `Accept-Signature` field value into its labeled signature requests. |
| [signRequested](functions/signRequested.md) | Fulfills and appends one parsed `Accept-Signature` request. |

## Components and Structured Fields

| Function | Description |
| :------ | :------ |
| [component](functions/component.md) | Creates a component identifier while preserving the supplied parameter order. |
| [createSignatureBase](functions/createSignatureBase.md) | Creates the RFC 9421 signature base for a Fetch `Request` or `Response`. |
| [date](functions/date.md) | Creates a validated Structured Field Date. |
| [decimal](functions/decimal.md) | Creates a validated Structured Field Decimal. |
| [displayString](functions/displayString.md) | Creates a validated Structured Field Display String. |
| [token](functions/token.md) | Creates a validated Structured Field Token, for use as an extension signature metadata parameter value. |

## Cryptographic Algorithms

| Function | Description |
| :------ | :------ |
| [ecdsaP256Sha256Signer](functions/ecdsaP256Sha256Signer.md) | Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`. |
| [ecdsaP256Sha256Verifier](functions/ecdsaP256Sha256Verifier.md) | Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`. |
| [ecdsaP384Sha384Signer](functions/ecdsaP384Sha384Signer.md) | Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`. |
| [ecdsaP384Sha384Verifier](functions/ecdsaP384Sha384Verifier.md) | Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`. |
| [ed25519Signer](functions/ed25519Signer.md) | Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ed25519`. |
| [ed25519Verifier](functions/ed25519Verifier.md) | Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ed25519`. |
| [generateEcdsaP256Sha256KeyPair](functions/generateEcdsaP256Sha256KeyPair.md) | Generates an ECDSA P-256 key pair for the RFC 9421 `ecdsa-p256-sha256` algorithm. |
| [generateEcdsaP384Sha384KeyPair](functions/generateEcdsaP384Sha384KeyPair.md) | Generates an ECDSA P-384 key pair for the RFC 9421 `ecdsa-p384-sha384` algorithm. |
| [generateEd25519KeyPair](functions/generateEd25519KeyPair.md) | Generates an Ed25519 key pair for the RFC 9421 `ed25519` algorithm. |
| [generateRsaPssSha512KeyPair](functions/generateRsaPssSha512KeyPair.md) | Generates an RSA key pair for the RFC 9421 `rsa-pss-sha512` algorithm. |
| [generateRsaV1\_5Sha256KeyPair](functions/generateRsaV1_5Sha256KeyPair.md) | Generates an RSA key pair for the RFC 9421 `rsa-v1_5-sha256` algorithm. |
| [rsaPssSha512Signer](functions/rsaPssSha512Signer.md) | Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `rsa-pss-sha512`. |
| [rsaPssSha512Verifier](functions/rsaPssSha512Verifier.md) | Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `rsa-pss-sha512`. |
| [rsaV1\_5Sha256Signer](functions/rsaV1_5Sha256Signer.md) | Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `rsa-v1_5-sha256`. |
| [rsaV1\_5Sha256Verifier](functions/rsaV1_5Sha256Verifier.md) | Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `rsa-v1_5-sha256`. |

## Interfaces

| Interface | Description |
| :------ | :------ |
| [CryptoKeyPair](interfaces/CryptoKeyPair.md) | A Web Cryptography key pair, resolved from the host runtime the same way [CryptoKey](type-aliases/CryptoKey.md) is. |
| [CryptoKeyStructuralFallback](interfaces/CryptoKeyStructuralFallback.md) | Used as [CryptoKey](type-aliases/CryptoKey.md) when the host runtime's `crypto` global is not exposed on `typeof globalThis`, including when it is absent from ambient types or declared with `const` or `let`. It stays structurally compatible with host `CryptoKey` declarations. |
| [FieldValueContext](interfaces/FieldValueContext.md) | Context supplied while deriving HTTP message components. |
| [MessageComponent](interfaces/MessageComponent.md) | A normalized HTTP message component identifier with ordered parameters. |
| [MessageSignature](interfaces/MessageSignature.md) | A parsed HTTP message signature. |
| [ParameterizedComponent](interfaces/ParameterizedComponent.md) | A parameterized HTTP message component identifier. |
| [RequestedSignOptions](interfaces/RequestedSignOptions.md) | Options for fulfilling an `Accept-Signature` member. |
| [SignatureBaseOptions](interfaces/SignatureBaseOptions.md) | Options for direct signature-base creation. |
| [SignatureContext](interfaces/SignatureContext.md) | Options shared by signature-base creation, signing, and verification. |
| [SignatureFields](interfaces/SignatureFields.md) | The result of creating one signature, ready to be added to the corresponding HTTP fields. |
| [SignatureRequest](interfaces/SignatureRequest.md) | A requested HTTP message signature parsed from `Accept-Signature`. |
| [SignatureRequestInput](interfaces/SignatureRequestInput.md) | Input used to create an `Accept-Signature` member. |
| [SignedFetchOptions](interfaces/SignedFetchOptions.md) | Options for a Fetch-compatible function that signs requests and optionally verifies responses. |
| [Signer](interfaces/Signer.md) | A Promise-based signer implementation returned by a synchronous factory. |
| [SigningFetchOptions](interfaces/SigningFetchOptions.md) | Options for a Fetch-compatible function that signs requests. |
| [SignOptions](interfaces/SignOptions.md) | Sender options. |
| [StructuredFieldDate](interfaces/StructuredFieldDate.md) | A Structured Field Date represented as integer UNIX seconds. |
| [StructuredFieldDecimal](interfaces/StructuredFieldDecimal.md) | A Structured Field Decimal, including integral decimal values such as `1.0`. |
| [StructuredFieldDisplayString](interfaces/StructuredFieldDisplayString.md) | A Structured Field Display String. |
| [StructuredFieldToken](interfaces/StructuredFieldToken.md) | A Structured Field Token. Plain JavaScript strings represent Structured Field Strings. |
| [VerificationContext](interfaces/VerificationContext.md) | Target-message context supplied to a verifier factory. |
| [VerificationPolicy](interfaces/VerificationPolicy.md) | Explicit application policy required before a cryptographically valid signature is accepted. |
| [VerifiedSignature](interfaces/VerifiedSignature.md) | A successfully verified signature. |
| [VerifiedSignatureContext](interfaces/VerifiedSignatureContext.md) | Authenticated context supplied to additional application policy. |
| [Verifier](interfaces/Verifier.md) | A Promise-based verifier implementation returned by a [VerifierFactory](type-aliases/VerifierFactory.md). |
| [VerifyingFetchOptions](interfaces/VerifyingFetchOptions.md) | Options for a Fetch-compatible function that verifies responses against their requests. |
| [VerifyOptions](interfaces/VerifyOptions.md) | Recipient options. |

## Type Aliases

| Type Alias | Description |
| :------ | :------ |
| [ComponentIdentifier](type-aliases/ComponentIdentifier.md) | An HTTP message component identifier. |
| [ComponentParameter](type-aliases/ComponentParameter.md) | An ordered HTTP message component parameter. |
| [ComponentParameters](type-aliases/ComponentParameters.md) | Ordered parameters are recommended because their serialization order is covered by the signature. Object property insertion order is preserved when a record is supplied. |
| [ComponentParameterValue](type-aliases/ComponentParameterValue.md) | A value supported by an HTTP message component parameter. |
| [CryptoKey](type-aliases/CryptoKey.md) | A Web Cryptography key, resolved from the host runtime. |
| [FieldValues](type-aliases/FieldValues.md) | Supplies individual HTTP field occurrences in wire order. |
| [SignatureParameter](type-aliases/SignatureParameter.md) | An ordered signature metadata parameter. |
| [SignatureParameterInput](type-aliases/SignatureParameterInput.md) | A signature metadata parameter input. |
| [SignatureParameters](type-aliases/SignatureParameters.md) | Ordered parameters are recommended because their order is covered by the signature. Object property insertion order is preserved when a record is supplied. |
| [SignatureParameterValue](type-aliases/SignatureParameterValue.md) | A value that can be used as an HTTP signature metadata parameter. |
| [SignerFactory](type-aliases/SignerFactory.md) | A synchronous factory returning a signer implementation. |
| [StructuredFieldType](type-aliases/StructuredFieldType.md) | The top-level type of an HTTP Structured Field. |
| [SynchronousVerifierFactory](type-aliases/SynchronousVerifierFactory.md) | A [VerifierFactory](type-aliases/VerifierFactory.md) that resolves its verifier without suspending. |
| [VerifierFactory](type-aliases/VerifierFactory.md) | A factory that selects trusted verification key material and an algorithm. |
