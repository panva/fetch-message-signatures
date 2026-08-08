# Function: rsaPssSha512Signer()

> **rsaPssSha512Signer**(`key`): [`SignerFactory`](../type-aliases/SignerFactory.md)

Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `rsa-pss-sha512`.

Signatures use MGF1 with SHA-512 and the RFC-required 64-byte salt. The salt length is not
carried by the key, so a provider that leaves it at another value produces signatures no
conforming recipient accepts.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an RSA-PSS private key with SHA-512 and `sign` usage. |

## Returns

[`SignerFactory`](../type-aliases/SignerFactory.md)
