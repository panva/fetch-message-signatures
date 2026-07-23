# Function: ecdsaP384Sha384Signer()

> **ecdsaP384Sha384Signer**(`key`): [`SignerFactory`](../type-aliases/SignerFactory.md)

Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`.

Signatures use the RFC-required 96-byte raw `r || s` representation.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an ECDSA P-384 private key with `sign` usage. |

## Returns

[`SignerFactory`](../type-aliases/SignerFactory.md)
