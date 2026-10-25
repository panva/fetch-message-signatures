# Function: mlDsa65Signer()

> **mlDsa65Signer**(`key`): [`SignerFactory`](../type-aliases/SignerFactory.md)

Creates a fixed-key signer factory backed by Web Cryptography for `ml-dsa-65`.

The message is signed directly with pure ML-DSA-65 and an empty context, without an external
pre-hash. Signatures use the 3309-byte FIPS 204 encoding.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an ML-DSA-65 private key with `sign` usage. |

## Returns

[`SignerFactory`](../type-aliases/SignerFactory.md)

## See

https://c2sp.org/httpsig-pq@v1.0.1
