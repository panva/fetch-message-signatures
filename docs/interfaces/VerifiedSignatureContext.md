# Interface: VerifiedSignatureContext

Authenticated context supplied to additional application policy.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [algorithm](#algorithm)
  - [message](#message)
  - [request?](#request)

## Extends

- [`VerificationContext`](VerificationContext.md)

## Properties

### algorithm

> `readonly` **algorithm**: `string`

The algorithm selected by the verifier factory.

***

### message

> `readonly` **message**: [`MessageSnapshot`](../type-aliases/MessageSnapshot.md)

The target message carrying the signature.

This is an immutable, package-owned snapshot captured at the start of verification. Field names
are lowercase and each value is the ordered list of occurrences used to construct the signature
base. Every verification callback observes the same snapshot values.

#### Inherited from

[`VerificationContext`](VerificationContext.md).[`message`](VerificationContext.md#message)

***

### request?

> `readonly` `optional` **request?**: [`RequestSnapshot`](RequestSnapshot.md)

The related-request snapshot, when response/request binding is in use.

#### Inherited from

[`VerificationContext`](VerificationContext.md).[`request`](VerificationContext.md#request)
