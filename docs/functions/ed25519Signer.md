# Function: ed25519Signer()

> **ed25519Signer**(`key`): [`SignerFactory`](../type-aliases/SignerFactory.md)

Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ed25519`.

The message is signed directly with Ed25519, without an external pre-hash.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an Ed25519 private key with `sign` usage. |

## Returns

[`SignerFactory`](../type-aliases/SignerFactory.md)
