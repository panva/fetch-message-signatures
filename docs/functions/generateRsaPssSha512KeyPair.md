# Function: generateRsaPssSha512KeyPair()

> **generateRsaPssSha512KeyPair**(`extractable?`, `modulusLength?`): `Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

Generates an RSA key pair for the RFC 9421 `rsa-pss-sha512` algorithm.

The generated public key is represented by Web Cryptography's `CryptoKey` and is always
extractable. RSA keys usually come from existing key management rather than from this generator,
and [rsaPssSha512Signer](rsaPssSha512Signer.md) and [rsaPssSha512Verifier](rsaPssSha512Verifier.md) accept an RSA-PSS key of any
modulus length.

SHA-512 with a 64-byte salt needs at least a 1040-bit modulus to encode a signature at all, so a
shorter key fails when it is used rather than when it is generated.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |
| `modulusLength?` | `number` | Modulus length in bits. Defaults to `2048`. |

## Returns

`Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

A randomly generated signing and verification key pair.

## Example

Generate a pair and turn it into the sender and recipient providers.

```ts
const { privateKey, publicKey } = await FetchSig.generateRsaPssSha512KeyPair()

const signer = FetchSig.rsaPssSha512Signer(privateKey)
const verifier = FetchSig.rsaPssSha512Verifier(publicKey)

// A longer modulus, when the surrounding key policy calls for one.
const strong = await FetchSig.generateRsaPssSha512KeyPair(false, 4096)
```
