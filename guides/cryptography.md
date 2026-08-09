# Cryptographic providers

`fetch-message-signatures` includes key-pair generators, signer factories, and verifier factories
backed by Web Cryptography for ECDSA P-256, ECDSA P-384, Ed25519, RSA-PSS with SHA-512, and
RSASSA-PKCS1-v1_5 with SHA-256. HMAC and other cryptographic implementations plug into sender and
recipient operations through the same small provider interfaces. A `SignerFactory` returns a signer
with `alg` and a `sign()` method. A `VerifierFactory` selects trusted key material and returns a
verifier with `alg` and a `verify()` method.

The exported algorithm functions map RFC algorithm identifiers to Web Cryptography parameters and
signature encoding. The application remains responsible for persistent key storage, key rotation,
trusted-key lookup, and authorization.

## Built-in Web Cryptography algorithms

Each built-in algorithm has one key generator, one signer factory, and one verifier factory.

| RFC 9421 algorithm  | Key generator                                                                           | Signer / verifier                                                                                                                                 |
| ------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ecdsa-p256-sha256` | [`generateEcdsaP256Sha256KeyPair`](../docs/functions/generateEcdsaP256Sha256KeyPair.md) | [`ecdsaP256Sha256Signer`](../docs/functions/ecdsaP256Sha256Signer.md) / [`ecdsaP256Sha256Verifier`](../docs/functions/ecdsaP256Sha256Verifier.md) |
| `ecdsa-p384-sha384` | [`generateEcdsaP384Sha384KeyPair`](../docs/functions/generateEcdsaP384Sha384KeyPair.md) | [`ecdsaP384Sha384Signer`](../docs/functions/ecdsaP384Sha384Signer.md) / [`ecdsaP384Sha384Verifier`](../docs/functions/ecdsaP384Sha384Verifier.md) |
| `ed25519`           | [`generateEd25519KeyPair`](../docs/functions/generateEd25519KeyPair.md)                 | [`ed25519Signer`](../docs/functions/ed25519Signer.md) / [`ed25519Verifier`](../docs/functions/ed25519Verifier.md)                                 |
| `rsa-pss-sha512`    | [`generateRsaPssSha512KeyPair`](../docs/functions/generateRsaPssSha512KeyPair.md)       | [`rsaPssSha512Signer`](../docs/functions/rsaPssSha512Signer.md) / [`rsaPssSha512Verifier`](../docs/functions/rsaPssSha512Verifier.md)             |
| `rsa-v1_5-sha256`   | [`generateRsaV1_5Sha256KeyPair`](../docs/functions/generateRsaV1_5Sha256KeyPair.md)     | [`rsaV1_5Sha256Signer`](../docs/functions/rsaV1_5Sha256Signer.md) / [`rsaV1_5Sha256Verifier`](../docs/functions/rsaV1_5Sha256Verifier.md)         |

## Keys

Every key generator accepts an optional `extractable` boolean:

```ts
const protectedKeys = await FetchSig.generateEd25519KeyPair()
const portableKeys = await FetchSig.generateEd25519KeyPair(true)
```

It defaults to `false` and controls the private key. `SubtleCrypto.generateKey()` always marks the
generated public key extractable, whatever this argument is. Extractability is a per-key property,
not a property of `CryptoKey` in general. An extractable key can be exported for storage or
transport, so opt in only when the application's key-management design requires it.

All generators request only the usages needed here: `sign` on private keys and `verify` on public
keys.

The two RSA generators take a second optional argument, the modulus length in bits, and use a public
exponent of 65537:

```ts
const defaultLength = await FetchSig.generateRsaPssSha512KeyPair()
const longer = await FetchSig.generateRsaPssSha512KeyPair(false, 4096)
```

It defaults to 2048. Which lengths can actually be generated is up to the Web Cryptography
implementation. RSA-PSS with SHA-512 and a 64-byte salt needs at least a 1040-bit modulus to encode
a signature, so a shorter key fails when it signs rather than when it is generated. The signer and
verifier factories accept a key of any modulus length, so a key that comes from elsewhere does not
have to match the default.

Imported, deserialized, and hardware-backed instances of Web Cryptography's `CryptoKey` work with
the same factories. Import the key using the Web Cryptography algorithm that matches the RFC
identifier. ECDSA keys also bind their named curve, and RSA keys their digest. Common import formats
are `spki` for an asymmetric public key, `pkcs8` for an asymmetric private key, and `jwk` when the
surrounding protocol defines JWK use. RFC 9421 does not define public-key formats or key
distribution.

For example, an Ed25519 key pair can be used directly:

```ts
const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
const signer = FetchSig.ed25519Signer(privateKey)
const verifier = FetchSig.ed25519Verifier(publicKey)
```

The factories can be supplied directly as `signer` and `verifier` options when one trusted key is
fixed by the surrounding context.

## Algorithm metadata and key selection

A built-in verifier binds one trusted key to one RFC algorithm. Key lookup and authorization belong
in the application verifier factory:

```ts
declare const privateKey: CryptoKey
declare const publicKeys: ReadonlyMap<string, CryptoKey>

const signer = FetchSig.ed25519Signer(privateKey)

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = FetchSig.getSignatureParameter(signature, 'keyid')
  if (typeof keyid !== 'string') {
    throw new Error('Missing keyid')
  }
  const publicKey = publicKeys.get(keyid)
  if (publicKey === undefined) {
    throw new Error('Unknown keyid')
  }

  return FetchSig.ed25519Verifier(publicKey)(signature, context)
}
```

The `alg` signature parameter is optional. When present, RFC 9421 requires its value to be
registered in the extensible
[HTTP Signature Algorithms registry](https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml#signature-algorithms).
The package accepts any Structured Field String instead of copying the registry into a release. The
identifier must still match both the returned provider's `alg` and the verification policy. When
`alg` is absent, trusted key configuration can determine the algorithm.

Neither `alg` nor `keyid` establishes trust. Scope key lookup to the relevant issuer, tenant, or
protocol context, authorize the key for the message, and bind it to one configured algorithm. Do not
turn `keyid` into an unrestricted network lookup or try every known key until one verifies. The
factory may return a Promise, so a key can be fetched or refreshed there, but the endpoint it
reaches must come from configuration rather than from the message.

Built-in signer and verifier functions synchronously validate the key type, required usage, Web
Cryptography algorithm, named curve, and digest. A P-384 ECDSA key therefore cannot be used with the
`ecdsa-p256-sha256` identifier, and an RSA-PSS key created for SHA-256 cannot be used with
`rsa-pss-sha512`.

## Custom providers

RFC 9421 defines `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`, `ecdsa-p256-sha256`,
`ecdsa-p384-sha384`, and `ed25519`. Of those, `hmac-sha256` is the one this package does not
provide. Other identifiers can be used through application-supplied providers without a package
release. Accepting an identifier does not supply its cryptography.

HMAC uses SHA-256. A shared MAC key gives no non-repudiation, because any party that can verify can
also forge, which is why it is left to a custom provider rather than sitting next to the asymmetric
factories.

For new designs, prefer `ed25519` or `rsa-pss-sha512` over `rsa-v1_5-sha256`. RFC 9421 describes RSA
PKCS#1 v1.5 as weaker and warns about
[algorithm downgrade attacks](https://www.rfc-editor.org/info/rfc9421/#section-7.3.6). Bind each key
to its algorithm in trusted configuration and keep the verification allowlist narrow.

Providers can use hardware keys, remote signers, native bindings, or synchronous libraries. Both
methods may return their result directly or as a Promise, so a synchronous library needs no wrapper:

```ts
declare function signSynchronously(data: Uint8Array): Uint8Array
declare function verifySynchronously(data: Uint8Array, signature: Uint8Array): boolean

const signer: FetchSig.SignerFactory = () => ({
  alg: 'ed25519',
  sign(data) {
    return signSynchronously(data)
  },
})

const verifier: FetchSig.VerifierFactory = () => ({
  alg: 'ed25519',
  verify(data, signature) {
    return verifySynchronously(data, signature)
  },
})
```

The built-in providers are asynchronous because Web Cryptography is. Returning synchronously does
not make the surrounding operation synchronous either: `sign()`, `verify()`, `createSignature()`,
and the `fetch` wrappers all return Promises whatever the provider does.

The provider must use the signature representation defined for its HTTP Message Signatures
algorithm, including its hashing, padding, and encoding rules. Both provider methods receive owned
`Uint8Array` values backed by `ArrayBuffer`. `sign()` produces a `Uint8Array`, and `verify()` a
boolean. Provider exceptions become signature creation or `verification_failed` errors, with the
original error preserved as `cause`. Signer output is copied before it is returned or serialized.

Use a cryptographic library's verification primitive rather than comparing signatures in application
JavaScript. When implementing a custom MAC verifier, the provider is responsible for constant-time
comparison.
