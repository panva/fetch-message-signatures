# Function: ecdsaP256Sha256Signer()

> **ecdsaP256Sha256Signer**(`key`): [`SignerFactory`](../type-aliases/SignerFactory.md)

Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`.

Signatures use the RFC-required 64-byte raw `r || s` representation.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an ECDSA P-256 private key with `sign` usage. |

## Returns

[`SignerFactory`](../type-aliases/SignerFactory.md)
