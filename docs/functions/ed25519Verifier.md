# Function: ed25519Verifier()

> **ed25519Verifier**(`key`): [`VerifierFactory`](../type-aliases/VerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ed25519`.

The message is verified directly with Ed25519, without an external pre-hash. This fixed-key
factory does not perform `keyid` lookup or authorization; select it from trusted application
configuration when more than one verification key can be used.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an Ed25519 public key with `verify` usage. |

## Returns

[`VerifierFactory`](../type-aliases/VerifierFactory.md)
