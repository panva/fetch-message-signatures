# Function: mlDsa44Verifier()

> **mlDsa44Verifier**(`key`): [`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for `ml-dsa-44`.

The message is verified directly with pure ML-DSA-44 and an empty context, without an external
pre-hash. Signatures use the 2420-byte FIPS 204 encoding. This fixed-key factory does not perform
`keyid` lookup or authorization. Select it from trusted application configuration when more than
one verification key can be used.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an ML-DSA-44 public key with `verify` usage. |

## Returns

[`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

## See

https://c2sp.org/httpsig-pq@v1.0.1
