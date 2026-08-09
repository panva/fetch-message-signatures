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

> `readonly` **message**: [`NormalizedMessage`](../type-aliases/NormalizedMessage.md)

The target message carrying the signature.

Its fields are always a `Headers`, whatever shape was passed to [verify](../functions/verify.md), so a callback
can read them without normalizing first. Record occurrences are converted using the host
`Headers` semantics for application processing; RFC 9421's signature-base combination is a
separate representation and can differ for non-list fields.

#### Inherited from

[`VerificationContext`](VerificationContext.md).[`message`](VerificationContext.md#message)

***

### request?

> `readonly` `optional` **request?**: [`NormalizedRequest`](../type-aliases/NormalizedRequest.md)

The normalized related request, when response/request binding is in use.

#### Inherited from

[`VerificationContext`](VerificationContext.md).[`request`](VerificationContext.md#request)
