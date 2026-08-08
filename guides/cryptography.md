# Cryptographic providers

`fetch-message-signatures` includes key-pair generators, signer factories, and verifier factories
backed by Web Cryptography for ECDSA P-256, ECDSA P-384, and Ed25519. RSA, HMAC, and other
cryptographic implementations plug into sender and recipient operations through the same small
provider interfaces. A synchronous `SignerFactory` returns a signer with `alg` and an asynchronous
`sign()` method. A synchronous `VerifierFactory` selects trusted key material and returns a verifier
with `alg` and an asynchronous `verify()` method.

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

Imported, deserialized, and hardware-backed instances of Web Cryptography's `CryptoKey` work with
the same factories. Import the key using the Web Cryptography algorithm that matches the RFC
identifier. ECDSA keys also bind their named curve. Common import formats are `spki` for an
asymmetric public key, `pkcs8` for an asymmetric private key, and `jwk` when the surrounding
protocol defines JWK use. RFC 9421 does not define public-key formats or key distribution.

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
Cryptography algorithm, and named curve. A P-384 ECDSA key therefore cannot be used with the
`ecdsa-p256-sha256` identifier.

## Custom providers

RFC 9421 defines `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`, `ecdsa-p256-sha256`,
`ecdsa-p384-sha384`, and `ed25519`. Later registry entries can be used through application-supplied
providers without a package release. Accepting an identifier does not supply its cryptography. RSA
and HMAC require custom providers.

RSA-PSS uses SHA-512, MGF1 with SHA-512, and a 64-byte salt. RSASSA-PKCS1-v1_5 and HMAC use SHA-256.
For new designs, prefer RSA-PSS or Ed25519 over `rsa-v1_5-sha256`. RFC 9421 describes RSA PKCS#1
v1.5 as weaker and warns about
[algorithm downgrade attacks](https://www.rfc-editor.org/info/rfc9421/#section-7.3.6). Bind each key
to its algorithm in trusted configuration and keep the verification allowlist narrow.

Providers can use hardware keys, remote signers, native bindings, or synchronous libraries. An
asynchronous wrapper is enough for a synchronous implementation:

```ts
declare function signSynchronously(data: Uint8Array): Uint8Array
declare function verifySynchronously(data: Uint8Array, signature: Uint8Array): boolean

const signer: FetchSig.SignerFactory = () => ({
  type: 'signer',
  alg: 'ed25519',
  async sign(data) {
    return signSynchronously(data)
  },
})

const verifier: FetchSig.VerifierFactory = () => ({
  type: 'verifier',
  alg: 'ed25519',
  async verify(data, signature) {
    return verifySynchronously(data, signature)
  },
})
```

The provider must use the signature representation defined for its HTTP Message Signatures
algorithm, including its hashing, padding, and encoding rules. Both provider methods receive owned
`Uint8Array` values backed by `ArrayBuffer`. `sign()` resolves to a `Uint8Array`, and `verify()`
resolves to a boolean. Provider exceptions become signature creation or verification failures whose
`cause` is the original error. Signer output is copied before it is returned or serialized.

Use a cryptographic library's verification primitive rather than comparing signatures in application
JavaScript. When implementing a custom MAC verifier, the provider is responsible for constant-time
comparison.
