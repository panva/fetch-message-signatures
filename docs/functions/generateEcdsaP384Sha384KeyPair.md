# Function: generateEcdsaP384Sha384KeyPair()

> **generateEcdsaP384Sha384KeyPair**(`extractable?`): `Promise`<`CryptoKeyPair`>

Generates an ECDSA P-384 key pair for the RFC 9421 `ecdsa-p384-sha384` algorithm.

The generated public key is represented by Web Cryptography's `CryptoKey` and is always
extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |

## Returns

`Promise`<`CryptoKeyPair`>

A randomly generated signing and verification key pair.
