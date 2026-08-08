# Function: ecdsaP384Sha384Verifier()

> **ecdsaP384Sha384Verifier**(`key`): [`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`.

Signatures use the RFC-required 96-byte raw `r || s` representation. This fixed-key factory does
not perform `keyid` lookup or authorization. Select it from trusted application configuration
when more than one verification key can be used.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an ECDSA P-384 public key with `verify` usage. |

## Returns

[`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)
