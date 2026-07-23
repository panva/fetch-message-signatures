# Function: generateEcdsaP256Sha256KeyPair()

> **generateEcdsaP256Sha256KeyPair**(`extractable?`): `Promise`<`CryptoKeyPair`>

Generates an ECDSA P-256 key pair for the RFC 9421 `ecdsa-p256-sha256` algorithm.

The generated public key is represented by Web Cryptography's `CryptoKey` and is always
extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |

## Returns

`Promise`<`CryptoKeyPair`>

A randomly generated signing and verification key pair.
