# fetch-message-signatures

HTTP Message Signatures for the Fetch API.

Implements the sender, recipient, and `Accept-Signature` operations from [RFC
9421](https://www.rfc-editor.org/info/rfc9421/) on top of `Request`, `Response`, `Headers`, and
`fetch`. The module constructs and parses the required Structured Fields, includes Web
Cryptography implementations of the ECDSA, Ed25519, and RSA signature algorithms, and supports
custom cryptographic providers.

Package configuration records, including Fetch-wrapper `RequestInit` values, must be object
literals or null-prototype objects containing only own enumerable data properties. Messages,
headers, provider implementations, and host objects retain their own documented semantics.

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

| wrapper                      | outgoing request | incoming response |
| ---------------------------- | ---------------- | ----------------- |
| [createSigningFetch](functions/createSigningFetch.md)   | signed           | not verified      |
| [createVerifyingFetch](functions/createVerifyingFetch.md) | not signed       | verified          |
| [createSignedFetch](functions/createSignedFetch.md)    | signed           | verified          |

Signing outgoing requests is the common case, because it only requires the recipient to verify.
Verifying responses additionally requires the server to sign them.

```ts
import * as FetchSig from 'fetch-message-signatures'

declare const clientPrivateKey: CryptoKey

const signingFetch = FetchSig.createSigningFetch({
  sign: {
    signer: FetchSig.ed25519Signer(clientPrivateKey),
    components: ['@method', '@authority', '@path'],
    parameters: { alg: 'ed25519', keyid: 'client-key' },
  },
})

// Used exactly like fetch. The request is signed on the way out.
const response = await signingFetch('https://api.example/orders/123')
const order = await response.json()
```

When the server signs its responses too, [createSignedFetch](functions/createSignedFetch.md) takes the same `sign` options
plus a `verify` block, and checks the response against the exact request that produced it.

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
| [createSignature](functions/createSignature.md) | Creates one HTTP message signature without modifying or cloning the source message. |
| [createSignatureFields](functions/createSignatureFields.md) | Serializes a signature produced outside this package into its `Signature-Input` and `Signature` fields. |
| [sign](functions/sign.md) | Creates and appends one HTTP message signature. |

## Recipient

| Function | Description |
| :------ | :------ |
| [getSignatureParameter](functions/getSignatureParameter.md) | Returns one signature metadata parameter by name, or `undefined` when the signature omits it. |
| [getSignatures](functions/getSignatures.md) | Parses and pairs every signature carried by a message, so that an application can choose which label to verify. |
| [parseSignature](functions/parseSignature.md) | Parses a `Signature` field value into its labeled signature byte sequences. |
| [parseSignatureInput](functions/parseSignatureInput.md) | Parses a `Signature-Input` field value into its labeled covered component lists and signature metadata parameters. |
| [verify](functions/verify.md) | Verifies and applies explicit application policy to one HTTP message signature. |

## Signature Negotiation

| Function | Description |
| :------ | :------ |
| [appendAcceptSignature](functions/appendAcceptSignature.md) | Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message. |
| [createAcceptSignature](functions/createAcceptSignature.md) | Serializes one or more signature requests as an `Accept-Signature` Structured Field Dictionary. |
| [createRequestedSignature](functions/createRequestedSignature.md) | Fulfills one parsed `Accept-Signature` request without modifying the target message. |
| [getSignatureRequests](functions/getSignatureRequests.md) | Parses every signature request carried by a message and checks that each requested component applies to the message that would be signed. |
| [parseAcceptSignature](functions/parseAcceptSignature.md) | Parses an `Accept-Signature` field value into its labeled signature requests. |
| [signRequested](functions/signRequested.md) | Fulfills and appends one parsed `Accept-Signature` request. |

## Components

| Function | Description |
| :------ | :------ |
| [component](functions/component.md) | Creates a component identifier while preserving the supplied parameter order. |
| [createSignatureBase](functions/createSignatureBase.md) | Creates the RFC 9421 signature base for a signable request or response. |
| [findComponents](functions/findComponents.md) | Returns every component identifier in a list that resolves to one field or derived component name, whatever parameters it carries. |
| [includesComponent](functions/includesComponent.md) | Reports whether a list of component identifiers contains one particular identifier. |

## Structured Fields

| Function | Description |
| :------ | :------ |
| [date](functions/date.md) | Creates a validated Structured Field Date. |
| [decimal](functions/decimal.md) | Creates a validated Structured Field Decimal. |
| [displayString](functions/displayString.md) | Creates a validated Structured Field Display String. |
| [parseStructuredField](functions/parseStructuredField.md) | Parses an HTTP field value as one of the three RFC 9651 top-level Structured Field types. |
| [serializeStructuredField](functions/serializeStructuredField.md) | Serializes a Structured Field value into an HTTP field value. |
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
| [MessageComponent](interfaces/MessageComponent.md) | A normalized HTTP message component identifier with ordered parameters. |
| [MessageSignature](interfaces/MessageSignature.md) | A parsed HTTP message signature. |
| [ParameterizedComponent](interfaces/ParameterizedComponent.md) | A parameterized HTTP message component identifier. |
| [RequestedSignOptions](interfaces/RequestedSignOptions.md) | Options for fulfilling an `Accept-Signature` member. |
| [RequestSnapshot](interfaces/RequestSnapshot.md) | An immutable request snapshot supplied to verification callbacks. |
| [ResponseSnapshot](interfaces/ResponseSnapshot.md) | An immutable response snapshot supplied to verification callbacks. |
| [SignatureBaseOptions](interfaces/SignatureBaseOptions.md) | Options for direct signature-base creation. |
| [SignatureContext](interfaces/SignatureContext.md) | Options shared by signature-base creation, signing, and verification. |
| [SignatureFields](interfaces/SignatureFields.md) | The result of creating one signature, ready to be added to the corresponding HTTP fields. |
| [SignatureFieldsOptions](interfaces/SignatureFieldsOptions.md) | Options for serializing a signature that was produced elsewhere into its two HTTP fields. |
| [SignatureRequest](interfaces/SignatureRequest.md) | A requested HTTP message signature parsed from `Accept-Signature`. |
| [SignatureRequestInput](interfaces/SignatureRequestInput.md) | Input used to create an `Accept-Signature` member. |
| [SignedFetchOptions](interfaces/SignedFetchOptions.md) | Options for a Fetch-compatible function that signs requests and optionally verifies responses. |
| [Signer](interfaces/Signer.md) | A signer implementation returned by a [SignerFactory](type-aliases/SignerFactory.md). |
| [SigningFetchOptions](interfaces/SigningFetchOptions.md) | Options for a Fetch-compatible function that signs requests. |
| [SignOptions](interfaces/SignOptions.md) | Sender options. |
| [StructuredFieldDate](interfaces/StructuredFieldDate.md) | A Structured Field Date represented as integer UNIX seconds. |
| [StructuredFieldDecimal](interfaces/StructuredFieldDecimal.md) | A Structured Field Decimal, including integral decimal values such as `1.0`. |
| [StructuredFieldDisplayString](interfaces/StructuredFieldDisplayString.md) | A Structured Field Display String. |
| [StructuredFieldInnerList](interfaces/StructuredFieldInnerList.md) | A Structured Field Inner List: an ordered list of Items with its own parameters. |
| [StructuredFieldItem](interfaces/StructuredFieldItem.md) | A Structured Field Item: one bare item with its parameters. |
| [StructuredFieldToken](interfaces/StructuredFieldToken.md) | A Structured Field Token. Plain JavaScript strings represent Structured Field Strings. |
| [VerificationContext](interfaces/VerificationContext.md) | Target-message context supplied to a verifier factory. |
| [VerificationPolicy](interfaces/VerificationPolicy.md) | Explicit application policy required before a cryptographically valid signature is accepted. |
| [VerifiedSignature](interfaces/VerifiedSignature.md) | A successfully verified signature. |
| [VerifiedSignatureContext](interfaces/VerifiedSignatureContext.md) | Authenticated context supplied to additional application policy. |
| [Verifier](interfaces/Verifier.md) | A verifier implementation returned by a [VerifierFactory](type-aliases/VerifierFactory.md). |
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
| [FieldOccurrences](type-aliases/FieldOccurrences.md) | Immutable HTTP field occurrences indexed by lowercase field name, in their received order. |
| [HeadersInput](type-aliases/HeadersInput.md) | HTTP fields supplied to a reading operation. |
| [MessageSnapshot](type-aliases/MessageSnapshot.md) | A package-owned request or response snapshot. |
| [SignableRequest](type-aliases/SignableRequest.md) | A request this package can read components from. |
| [SignableResponse](type-aliases/SignableResponse.md) | A response this package can read components from. |
| [SignatureParameter](type-aliases/SignatureParameter.md) | An ordered signature metadata parameter. |
| [SignatureParameterInput](type-aliases/SignatureParameterInput.md) | A signature metadata parameter input. |
| [SignatureParameters](type-aliases/SignatureParameters.md) | Ordered parameters are recommended because their order is covered by the signature. Object property insertion order is preserved when a record is supplied. |
| [SignatureParameterValue](type-aliases/SignatureParameterValue.md) | A value that can be used as an HTTP signature metadata parameter. |
| [SignerFactory](type-aliases/SignerFactory.md) | A synchronous factory returning a signer implementation. |
| [StructuredFieldBareItem](type-aliases/StructuredFieldBareItem.md) | A bare item value in an HTTP Structured Field. |
| [StructuredFieldDictionary](type-aliases/StructuredFieldDictionary.md) | A Structured Field Dictionary as ordered entries. |
| [StructuredFieldList](type-aliases/StructuredFieldList.md) | A Structured Field List. |
| [StructuredFieldMember](type-aliases/StructuredFieldMember.md) | A member of a Structured Field List or Dictionary. |
| [StructuredFieldParameter](type-aliases/StructuredFieldParameter.md) | An ordered parameter on a Structured Field Item or Inner List. |
| [StructuredFieldType](type-aliases/StructuredFieldType.md) | The top-level type of an HTTP Structured Field. |
| [StructuredFieldValue](type-aliases/StructuredFieldValue.md) | A complete Structured Field value of one of the three top-level types. |
| [SynchronousVerifierFactory](type-aliases/SynchronousVerifierFactory.md) | A [VerifierFactory](type-aliases/VerifierFactory.md) that resolves its verifier without suspending. |
| [VerifierFactory](type-aliases/VerifierFactory.md) | A factory that selects trusted verification key material and an algorithm. |
