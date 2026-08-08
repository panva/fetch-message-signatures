# Function: rsaPssSha512Verifier()

> **rsaPssSha512Verifier**(`key`): [`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `rsa-pss-sha512`.

Signatures use MGF1 with SHA-512 and the RFC-required 64-byte salt. This fixed-key factory does
not perform `keyid` lookup or authorization. Select it from trusted application configuration
when more than one verification key can be used.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an RSA-PSS public key with SHA-512 and `verify` usage. |

## Returns

[`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)
