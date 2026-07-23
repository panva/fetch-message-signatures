# Interface: VerificationPolicy

Explicit application policy required before a cryptographically valid signature is accepted.

## Contents

- [Methods](#methods)
  - [validate()?](#validate)
- [Properties](#properties)
  - [algorithms](#algorithms)
  - [requiredComponents](#requiredcomponents)
  - [requiredParameters](#requiredparameters)
  - [clockSkew?](#clockskew)
  - [maxAge?](#maxage)
  - [now?](#now)

## Methods

### validate()?

> `optional` **validate**(`signature`, `context`): `void` ∣ `Promise`<`void`>

Additional application policy, such as nonce uniqueness, expected tags, field semantics, and
key/message authorization.

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `signature` | `Readonly`<[`MessageSignature`](MessageSignature.md)> |
| `context` | `Readonly`<[`VerifiedSignatureContext`](VerifiedSignatureContext.md)> |

#### Returns

`void` ∣ `Promise`<`void`>

## Properties

### algorithms

> `readonly` **algorithms**: readonly `string`\[]

Non-empty allowlist matched against the algorithm selected by the verifier factory.

***

### requiredComponents

> `readonly` **requiredComponents**: readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[]

Every listed component identifier must be covered by the signature.

***

### requiredParameters

> `readonly` **requiredParameters**: readonly `string`\[]

Every listed metadata parameter must be present.

***

### clockSkew?

> `readonly` `optional` **clockSkew?**: `number`

Permitted timestamp skew in seconds. Defaults to zero.

***

### maxAge?

> `readonly` `optional` **maxAge?**: `number`

Maximum signature age in seconds. Requires a `created` parameter.

***

### now?

> `readonly` `optional` **now?**: `number` ∣ `Date`

Injectable verification clock.
