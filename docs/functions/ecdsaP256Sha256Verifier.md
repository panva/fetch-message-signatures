# Function: ecdsaP256Sha256Verifier()

> **ecdsaP256Sha256Verifier**(`key`): [`VerifierFactory`](../type-aliases/VerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`.

Signatures use the RFC-required 64-byte raw `r || s` representation. This fixed-key factory does
not perform `keyid` lookup or authorization. Select it from trusted application configuration
when more than one verification key can be used.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an ECDSA P-256 public key with `verify` usage. |

## Returns

[`VerifierFactory`](../type-aliases/VerifierFactory.md)
