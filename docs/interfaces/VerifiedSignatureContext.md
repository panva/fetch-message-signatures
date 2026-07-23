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

> `readonly` **message**: `Request` ∣ `Response`

The target message carrying the signature.

#### Inherited from

[`VerificationContext`](VerificationContext.md).[`message`](VerificationContext.md#message)

***

### request?

> `readonly` `optional` **request?**: `Request`

The exact related request, when response/request binding is in use.

#### Inherited from

[`VerificationContext`](VerificationContext.md).[`request`](VerificationContext.md#request)
