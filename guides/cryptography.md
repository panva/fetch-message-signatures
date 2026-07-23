# Cryptographic providers

`fetch-message-signatures` includes key-pair generators, signer factories, and verifier factories
backed by Web Cryptography for ECDSA P-256, ECDSA P-384, and Ed25519. RSA, HMAC, and other
cryptographic implementations plug into sender and recipient operations through the same small
provider interfaces:

- a synchronous `SignerFactory` returns a signer with `alg` and an asynchronous `sign()` method;
- a synchronous `VerifierFactory` selects trusted key material and returns a verifier with `alg` and
  an asynchronous `verify()` method.

The exported algorithm functions map RFC algorithm identifiers to Web Cryptography parameters and
signature encoding. The application remains responsible for persistent key storage, key rotation,
trusted-key lookup, and authorization. Custom providers can still use hardware keys, remote signers,
native bindings, or synchronous libraries.

## Built-in Web Cryptography algorithms

Each built-in algorithm has one key generator, one signer factory, and one verifier factory.

| RFC 9421 algorithm  | Key generator                                                                           | Signer / verifier                                                                                                                                 |
| ------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ecdsa-p256-sha256` | [`generateEcdsaP256Sha256KeyPair`](../docs/functions/generateEcdsaP256Sha256KeyPair.md) | [`ecdsaP256Sha256Signer`](../docs/functions/ecdsaP256Sha256Signer.md) / [`ecdsaP256Sha256Verifier`](../docs/functions/ecdsaP256Sha256Verifier.md) |
| `ecdsa-p384-sha384` | [`generateEcdsaP384Sha384KeyPair`](../docs/functions/generateEcdsaP384Sha384KeyPair.md) | [`ecdsaP384Sha384Signer`](../docs/functions/ecdsaP384Sha384Signer.md) / [`ecdsaP384Sha384Verifier`](../docs/functions/ecdsaP384Sha384Verifier.md) |
| `ed25519`           | [`generateEd25519KeyPair`](../docs/functions/generateEd25519KeyPair.md)                 | [`ed25519Signer`](../docs/functions/ed25519Signer.md) / [`ed25519Verifier`](../docs/functions/ed25519Verifier.md)                                 |

The built-in functions use the exact RFC parameters:

- ECDSA P-256 and P-384 use SHA-256 and SHA-384 respectively, with fixed-width raw `r || s`
  signatures rather than ASN.1 DER.
- Ed25519 signs the message directly without an external pre-hash.

Algorithm availability depends on the runtime. In particular, older Web Cryptography implementations
may not provide Ed25519.

## RSA and HMAC providers

RFC 9421 also registers `rsa-pss-sha512`, `rsa-v1_5-sha256`, and `hmac-sha256`, but
`fetch-message-signatures` does not export RSA or HMAC key generators, signers, or verifiers. Use
custom `SignerFactory` and `VerifierFactory` implementations when interoperability with these
algorithms is required.

Those providers must follow the RFC parameters exactly: RSA-PSS uses SHA-512, MGF1 with SHA-512, and
a 64-byte salt; RSASSA-PKCS1-v1_5 and HMAC use SHA-256. For new designs, prefer RSA-PSS or Ed25519
over `rsa-v1_5-sha256`. RFC 9421 describes RSA PKCS#1 v1.5 as weaker and specifically warns about
[algorithm downgrade attacks](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.3.6). When it is
required, bind the key to that algorithm in trusted configuration and keep the verification
allowlist narrow.

## Key generation options

Every key generator accepts an optional `extractable` boolean:

```ts
const protectedKeys = await FetchSig.generateEd25519KeyPair()
const portableKeys = await FetchSig.generateEd25519KeyPair(true)
```

It defaults to `false` and controls the private key; the generated public key is Web Cryptography's
`CryptoKey`, which is always extractable regardless of this argument. An extractable key can be
exported for storage or transport, so opt in only when the application's key-management design
requires it.

All generators request only the usages needed here: `sign` on private keys and `verify` on public
keys.

## Ed25519 example

```ts
const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
const signer = FetchSig.ed25519Signer(privateKey)
const verifier = FetchSig.ed25519Verifier(publicKey)
```

The factories can be supplied directly as `signer` and `verifier` options when one trusted key is
fixed by the surrounding context.

## Trusted-key selection

A built-in verifier binds one already-trusted key to one RFC algorithm. It deliberately does not
interpret `keyid`, retrieve keys, or decide whether a key is authorized for a request. Put that
selection in the application verifier factory:

```ts
declare const privateKey: CryptoKey
declare const publicKeys: ReadonlyMap<string, CryptoKey>

const signer = FetchSig.ed25519Signer(privateKey)

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = signature.parameters.find(([name]) => name === 'keyid')?.[1]
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

Signer and verifier functions validate the key type, required usage, Web Cryptography algorithm, and
named curve synchronously. This prevents, for example, accidentally using a P-384 ECDSA key with the
`ecdsa-p256-sha256` identifier.

## Imported keys

Applications can pass imported, deserialized, or hardware-backed instances of Web Cryptography's
`CryptoKey` to the same functions. Import the key using the Web Cryptography algorithm that matches
the RFC identifier. ECDSA keys bind their named curve.

Public-key formats and key distribution are outside RFC 9421. Typical Web Cryptography imports use
`spki` for an asymmetric public key, `pkcs8` for an asymmetric private key, or `jwk` where the
surrounding protocol defines JWK use.

## Custom providers

The built-ins are optional, and RSA and HMAC require custom providers. To adapt synchronous
cryptography, declare the provider method `async` and return the synchronous result:

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

The provider must produce and consume the exact signature representation defined for the HTTP
Message Signature algorithm. A library name that looks similar is not enough; check hashing,
padding, parameter, and signature-encoding requirements against the algorithm specification.

Both provider methods receive owned `Uint8Array` values backed by `ArrayBuffer`, so they can be
passed directly to Web Cryptography. Signer output is copied before it is returned or serialized.

## Algorithm signaling

When the signature carries an `alg` parameter, this package accepts the algorithm identifiers in the
HTTP Message Signatures Algorithms registry defined by RFC 9421:

- `rsa-pss-sha512`
- `rsa-v1_5-sha256`
- `hmac-sha256`
- `ecdsa-p256-sha256`
- `ecdsa-p384-sha384`
- `ed25519`

Recognizing an identifier does not select or provide its cryptography. In particular, both RSA
identifiers and `hmac-sha256` require custom providers. The provider's `alg` must match the signaled
value. During verification it must also appear in `policy.algorithms`.

The signature can omit `alg`; trusted key configuration may determine the algorithm instead. This
often avoids algorithm negotiation from attacker-controlled input. Even when `alg` is present, the
verifier factory must not instantiate an algorithm merely because the message requested it.

## Key selection

A safe verifier factory commonly follows this sequence:

1. read a bounded identifier such as `keyid`;
2. look it up in local, issuer-scoped configuration;
3. check that the key is authorized for the target message context;
4. select the single configured algorithm for that key; and
5. return a verifier.

Do not:

- interpret `keyid` as a URL to fetch without a separate trusted discovery policy;
- allow an untrusted `alg` to change how one key is interpreted;
- fall back to every known key until one verifies; or
- assign authorization semantics to an unsigned signature label.

The factory is synchronous so network-backed discovery must complete before `verify()`. A bounded,
validated cache is generally a better fit for the verification hot path.

## Provider errors and return values

`sign()` must resolve to a `Uint8Array`. `verify()` must resolve to a boolean. Provider exceptions
are wrapped as signature creation or verification failures with the original error as `cause`.

Use a cryptographic library's verification primitive rather than comparing signatures in application
JavaScript. When implementing a custom MAC verifier, the provider is responsible for constant-time
comparison.
