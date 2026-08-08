# Type Alias: VerifierFactory

> **VerifierFactory** = (`signature`, `context`) => `Readonly`<[`Verifier`](../interfaces/Verifier.md)>

A synchronous factory that selects trusted verification key material and an algorithm.

The factory is the application's key-resolution and trust-policy boundary. It MUST reject unknown
or inappropriate key identifiers and algorithms instead of returning a verifier for them.

It receives the parsed signature before any cryptography runs, so selection can depend on
`keyid`, `alg`, the covered component list, or the message itself. Use
[getSignatureParameter](../functions/getSignatureParameter.md) to read a metadata parameter.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `signature` | `Readonly`<[`MessageSignature`](../interfaces/MessageSignature.md)> |
| `context` | `Readonly`<[`VerificationContext`](../interfaces/VerificationContext.md)> |

## Returns

`Readonly`<[`Verifier`](../interfaces/Verifier.md)>
