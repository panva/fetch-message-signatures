# Function: generateRsaV1\_5Sha256KeyPair()

> **generateRsaV1\_5Sha256KeyPair**(`extractable?`, `modulusLength?`): `Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

Generates an RSA key pair for the RFC 9421 `rsa-v1_5-sha256` algorithm.

The generated public key is represented by Web Cryptography's `CryptoKey` and is always
extractable. RSA keys usually come from existing key management rather than from this generator,
and [rsaV1\_5Sha256Signer](rsaV1_5Sha256Signer.md) and [rsaV1\_5Sha256Verifier](rsaV1_5Sha256Verifier.md) accept an RSASSA-PKCS1-v1\_5 key
of any modulus length.

Prefer `rsa-pss-sha512` or `ed25519` for a new design. This algorithm is provided for peers that
require PKCS#1 v1.5, which RFC 9421 describes as the weaker RSA option.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |
| `modulusLength?` | `number` | Modulus length in bits. Defaults to `2048`. |

## Returns

`Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

A randomly generated signing and verification key pair.
