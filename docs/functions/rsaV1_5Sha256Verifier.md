# Function: rsaV1\_5Sha256Verifier()

> **rsaV1\_5Sha256Verifier**(`key`): [`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `rsa-v1_5-sha256`.

This fixed-key factory does not perform `keyid` lookup or authorization. Select it from trusted
application configuration when more than one verification key can be used.

Accept this algorithm only for peers that require PKCS#1 v1.5, and keep it out of the policy
allowlist everywhere else. RFC 9421 describes it as the weaker RSA option and warns about
[algorithm downgrade attacks](https://www.rfc-editor.org/info/rfc9421/#section-7.3.6).

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an RSASSA-PKCS1-v1\_5 public key with SHA-256 and `verify` usage. |

## Returns

[`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)
