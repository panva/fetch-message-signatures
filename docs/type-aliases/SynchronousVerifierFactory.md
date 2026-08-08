# Type Alias: SynchronousVerifierFactory

> **SynchronousVerifierFactory** = (`signature`, `context`) => `Readonly`<[`Verifier`](../interfaces/Verifier.md)>

A [VerifierFactory](VerifierFactory.md) that resolves its verifier without suspending.

Every factory this package returns is synchronous, and says so, so that composing one keeps
working without an `await`. It remains assignable to [VerifierFactory](VerifierFactory.md).

## Parameters

| Parameter | Type |
| :------ | :------ |
| `signature` | `Readonly`<[`MessageSignature`](../interfaces/MessageSignature.md)> |
| `context` | `Readonly`<[`VerificationContext`](../interfaces/VerificationContext.md)> |

## Returns

`Readonly`<[`Verifier`](../interfaces/Verifier.md)>
