# Interface: VerificationContext

Target-message context supplied to a verifier factory.

## Contents

- [Extended by](#extended-by)
- [Properties](#properties)
  - [message](#message)
  - [request?](#request)

## Extended by

- [`VerifiedSignatureContext`](VerifiedSignatureContext.md)

## Properties

### message

> `readonly` **message**: `Request` ∣ `Response`

The target message carrying the signature.

***

### request?

> `readonly` `optional` **request?**: `Request`

The exact related request, when response/request binding is in use.
