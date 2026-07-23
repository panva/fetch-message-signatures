# fetch-message-signatures

`fetch-message-signatures` is a JavaScript module for HTTP Message Signatures ([RFC 9421][]) built
on the Fetch API.

The module provides sender, recipient, and `Accept-Signature` operations on top of `Request`,
`Response`, `Headers`, and `fetch`, together with Web Cryptography implementations for ECDSA P-256,
ECDSA P-384, and Ed25519. RSA, HMAC, and other cryptography can be supplied through custom
providers. Trusted-key selection and authorization remain application responsibilities.

## [💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find
this module useful, please consider supporting this project by
[becoming a sponsor](https://github.com/sponsors/panva).

## Dependencies: 0

`fetch-message-signatures` has no dependencies and it exports tree-shakeable ESM from a single
module.

## [API Reference](docs/README.md)

`fetch-message-signatures` is distributed via
[npmjs.com](https://www.npmjs.com/package/fetch-message-signatures),
[jsdelivr.com](https://www.jsdelivr.com/package/npm/fetch-message-signatures), and
[github.com](https://github.com/panva/fetch-message-signatures).

## Quick Start

```ts
import * as FetchSig from 'fetch-message-signatures'

// 1. Generate a non-extractable private key and create its providers
const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
const signer = FetchSig.ed25519Signer(privateKey)
const verifyWithKey = FetchSig.ed25519Verifier(publicKey)

// 2. Resolve trusted key material from authenticated application configuration
const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = signature.parameters.find(([name]) => name === 'keyid')?.[1]
  if (keyid !== 'example-key') {
    throw new Error('Untrusted signing key')
  }
  return verifyWithKey(signature, context)
}

// 3. Sign a Fetch request
const request = await FetchSig.sign(new Request('https://api.example/orders/123'), {
  signer,
  components: ['@method', '@authority', '@path'],
  parameters: { alg: 'ed25519', keyid: 'example-key' },
})

// 4. Verify it against explicit recipient policy
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

## [Guides](guides/README.md)

For sender and recipient integration, cryptographic providers, component selection,
`Accept-Signature`, Fetch behavior, and security guidance, see the
[guides directory](guides/README.md).

## Runtime Requirements

The module requires standards-compatible `Request`, `Response`, and `Headers` implementations. The
Fetch wrappers also require a Fetch implementation. The built-in cryptographic providers require the
Web Cryptography API and runtime support for the selected algorithm. The package does not provide
polyfills.

## Supported Operations

- Sign requests and responses.
- Verify one or more message signatures against explicit recipient policy.
- Generate key pairs containing Web Cryptography's `CryptoKey` objects and providers for ECDSA
  P-256, ECDSA P-384, and Ed25519.
- Bind a response signature to components of its related request.
- Create, parse, append, and fulfill `Accept-Signature` requests.
- Derive RFC 9421 request and response components from Fetch messages.
- Process HTTP fields as Structured Fields, dictionary members, raw byte sequences, or trailers.
- Wrap `fetch` with request signing, response verification, or both through independent
  tree-shakeable exports.

## Cryptographic Algorithms

`fetch-message-signatures` includes tree-shakeable key-pair generators, signer factories, and
verifier factories backed by Web Cryptography for ECDSA P-256, ECDSA P-384, and Ed25519. Other
algorithms and key systems can be supplied through the [`Signer`](docs/interfaces/Signer.md) and
[`Verifier`](docs/interfaces/Verifier.md) interfaces. Applications choose trusted keys, algorithms,
and authorization policy.

The [cryptographic providers guide](guides/cryptography.md) documents the exact algorithm mappings,
key extractability, signature parameter handling, and custom provider contract. Exported functions
are listed under [Cryptographic Algorithms](docs/README.md#cryptographic-algorithms) in the API
reference.

## Security Considerations

A valid signature authenticates only its covered components. It does not by itself establish
authorization, freshness, replay protection, or body integrity. Applications must define trusted
keys, required component coverage, timestamp and nonce policy, and independently validate
`Content-Digest` when body integrity matters.

Fetch also hides or normalizes some protocol-layer HTTP details. Read the
[security guidance](guides/security.md) and [Fetch behavior](guides/fetch.md) before deploying
signatures across a network boundary. Security vulnerabilities should be reported according to the
[Security Policy].

## Specifications

- [HTTP Message Signatures (RFC 9421)][RFC 9421]

[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421/
[Security Policy]: https://github.com/panva/fetch-message-signatures/security/policy
