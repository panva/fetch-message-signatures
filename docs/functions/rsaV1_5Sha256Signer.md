# Function: rsaV1\_5Sha256Signer()

> **rsaV1\_5Sha256Signer**(`key`): [`SignerFactory`](../type-aliases/SignerFactory.md)

Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `rsa-v1_5-sha256`.

Prefer [rsaPssSha512Signer](rsaPssSha512Signer.md) or [ed25519Signer](ed25519Signer.md) for a new design. This algorithm is
provided for peers that require PKCS#1 v1.5, which RFC 9421 describes as the weaker RSA option.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an RSASSA-PKCS1-v1\_5 private key with SHA-256 and `sign` usage. |

## Returns

[`SignerFactory`](../type-aliases/SignerFactory.md)
