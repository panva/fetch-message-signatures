# fetch-message-signatures

HTTP Message Signatures for the Fetch API.

Implements the sender, recipient, and `Accept-Signature` operations from [RFC
9421](https://www.rfc-editor.org/rfc/rfc9421.html) on top of `Request`, `Response`, `Headers`,
and `fetch`. The module constructs and parses the required Structured Fields, includes Web
Cryptography implementations of the ECDSA and Ed25519 signature algorithms, and supports custom
cryptographic providers.

## Example

Sign and verify a request with Ed25519 through Web Cryptography.

```ts
import * as FetchSig from 'fetch-message-signatures'

const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
const signer = FetchSig.ed25519Signer(privateKey)
const verifyWithKey = FetchSig.ed25519Verifier(publicKey)

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = signature.parameters.find(([name]) => name === 'keyid')?.[1]
  if (keyid !== 'example-key') throw new Error('Untrusted signing key')
  return verifyWithKey(signature, context)
}

const request = await FetchSig.sign(new Request('https://api.example/orders/123'), {
  signer,
  components: ['@method', '@authority', '@path'],
  parameters: { alg: 'ed25519', keyid: 'example-key' },
})

const verified = await FetchSig.verify(request, {
  verifier,
  policy: {
    requiredComponents: ['@method', '@authority', '@path'],
    requiredParameters: ['created', 'alg', 'keyid'],
    algorithms: ['ed25519'],
    maxAge: 60,
  },
})

console.log(verified.label, verified.algorithm)
```

## Sender

- [appendSignature](functions/appendSignature.md)
- [createSignature](functions/createSignature.md)
- [sign](functions/sign.md)

## Recipient

- [getSignatures](functions/getSignatures.md)
- [parseSignature](functions/parseSignature.md)
- [parseSignatureInput](functions/parseSignatureInput.md)
- [verify](functions/verify.md)

## Cryptographic Algorithms

- [ecdsaP256Sha256Signer](functions/ecdsaP256Sha256Signer.md)
- [ecdsaP256Sha256Verifier](functions/ecdsaP256Sha256Verifier.md)
- [ecdsaP384Sha384Signer](functions/ecdsaP384Sha384Signer.md)
- [ecdsaP384Sha384Verifier](functions/ecdsaP384Sha384Verifier.md)
- [ed25519Signer](functions/ed25519Signer.md)
- [ed25519Verifier](functions/ed25519Verifier.md)
- [generateEcdsaP256Sha256KeyPair](functions/generateEcdsaP256Sha256KeyPair.md)
- [generateEcdsaP384Sha384KeyPair](functions/generateEcdsaP384Sha384KeyPair.md)
- [generateEd25519KeyPair](functions/generateEd25519KeyPair.md)

## Signature Negotiation

- [appendAcceptSignature](functions/appendAcceptSignature.md)
- [createAcceptSignature](functions/createAcceptSignature.md)
- [createRequestedSignature](functions/createRequestedSignature.md)
- [getSignatureRequests](functions/getSignatureRequests.md)
- [parseAcceptSignature](functions/parseAcceptSignature.md)
- [signRequested](functions/signRequested.md)

## Fetch Integration

- [createSignedFetch](functions/createSignedFetch.md)

## Components and Structured Fields

- [component](functions/component.md)
- [createSignatureBase](functions/createSignatureBase.md)
- [decimal](functions/decimal.md)
- [token](functions/token.md)

## Interfaces

- [FieldValueContext](interfaces/FieldValueContext.md)
- [MessageComponent](interfaces/MessageComponent.md)
- [MessageSignature](interfaces/MessageSignature.md)
- [ParameterizedComponent](interfaces/ParameterizedComponent.md)
- [RequestedSignOptions](interfaces/RequestedSignOptions.md)
- [SignatureBaseOptions](interfaces/SignatureBaseOptions.md)
- [SignatureContext](interfaces/SignatureContext.md)
- [SignatureFields](interfaces/SignatureFields.md)
- [SignatureRequest](interfaces/SignatureRequest.md)
- [SignatureRequestInput](interfaces/SignatureRequestInput.md)
- [SignedFetchOptions](interfaces/SignedFetchOptions.md)
- [Signer](interfaces/Signer.md)
- [SignOptions](interfaces/SignOptions.md)
- [StructuredFieldDecimal](interfaces/StructuredFieldDecimal.md)
- [StructuredFieldDefinition](interfaces/StructuredFieldDefinition.md)
- [StructuredFieldToken](interfaces/StructuredFieldToken.md)
- [VerificationContext](interfaces/VerificationContext.md)
- [VerificationPolicy](interfaces/VerificationPolicy.md)
- [VerifiedSignature](interfaces/VerifiedSignature.md)
- [VerifiedSignatureContext](interfaces/VerifiedSignatureContext.md)
- [Verifier](interfaces/Verifier.md)
- [VerifyOptions](interfaces/VerifyOptions.md)

## Type Aliases

- [ComponentIdentifier](type-aliases/ComponentIdentifier.md)
- [ComponentParameter](type-aliases/ComponentParameter.md)
- [ComponentParameters](type-aliases/ComponentParameters.md)
- [ComponentParameterValue](type-aliases/ComponentParameterValue.md)
- [FieldValues](type-aliases/FieldValues.md)
- [SignatureParameter](type-aliases/SignatureParameter.md)
- [SignatureParameterInput](type-aliases/SignatureParameterInput.md)
- [SignatureParameters](type-aliases/SignatureParameters.md)
- [SignatureParameterValue](type-aliases/SignatureParameterValue.md)
- [SignerFactory](type-aliases/SignerFactory.md)
- [StructuredFieldType](type-aliases/StructuredFieldType.md)
- [StructuredFieldVersion](type-aliases/StructuredFieldVersion.md)
- [VerifierFactory](type-aliases/VerifierFactory.md)
