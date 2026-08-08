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

Sign every outgoing request and send it. `createSignedFetch()` returns a drop-in `fetch`, so the
signing and verification happen around the call you already make.

```ts
import * as FetchSig from 'fetch-message-signatures'

// 1. Your signing key, and the public key of the server you are calling
const { privateKey } = await FetchSig.generateEd25519KeyPair()
declare const serverPublicKey: CryptoKey

// 2. Wrap fetch. `sign` covers the request, `verify` covers the response it gets back
const signedFetch = FetchSig.createSignedFetch({
  sign: {
    signer: FetchSig.ed25519Signer(privateKey),
    components: ['@method', '@authority', '@path'],
    parameters: { alg: 'ed25519', keyid: 'client-key' },
  },
  verify: {
    verifier: FetchSig.ed25519Verifier(serverPublicKey),
    policy: {
      // ";req" binds the response to the request that produced it
      requiredComponents: ['@status', FetchSig.component('@path', { req: true })],
      requiredParameters: ['created', 'keyid'],
      algorithms: ['ed25519'],
      maxAge: 60,
    },
  },
})

// 3. Send it. The request goes out signed, and this rejects rather than resolving if the
//    response is missing a signature, carries a bad one, or fails the policy above
const response = await signedFetch('https://api.example/orders/123')
const order = await response.json()
```

The request that went out carries the two fields RFC 9421 defines:

```text
signature-input: sig1=("@method" "@authority" "@path");created=1735689600;alg="ed25519";keyid="client-key"
signature:       sig1=:<base64 of the 64 Ed25519 signature bytes>:
```

Drop `verify` to sign without checking responses, or use
[`createSigningFetch()`](docs/functions/createSigningFetch.md) and
[`createVerifyingFetch()`](docs/functions/createVerifyingFetch.md) for a single direction so a
bundler can omit the other. To sign or verify a message you already hold, rather than wrapping
`fetch`, use [`sign()`](docs/functions/sign.md) and [`verify()`](docs/functions/verify.md).

The bytes that were signed are one canonicalized line per covered component plus the
`@signature-params` line, which repeats the `Signature-Input` member value. `createSignatureBase()`
returns exactly that string, which is the first thing to compare when two implementations disagree:

```text
"@method": GET
"@authority": api.example
"@path": /orders/123
"@signature-params": ("@method" "@authority" "@path");created=1735689600;alg="ed25519";keyid="client-key"
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

Structured Field Byte Sequences use `Uint8Array.prototype.toBase64()` and `Uint8Array.fromBase64()`
where they are available, and fall back to `btoa()` and `atob()` where they are not. Both paths
produce the same results and are covered by the test suite.

Runtime-specific behavior that affects signatures, such as manual redirect handling in browsers,
repeated field lines, trailers, and response reconstruction, is documented in
[Fetch behavior and limitations](guides/fetch.md).

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

[RFC 9421]: https://www.rfc-editor.org/info/rfc9421/
[Security Policy]: https://github.com/panva/fetch-message-signatures/security/policy
