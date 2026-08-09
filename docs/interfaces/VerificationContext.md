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

> `readonly` **message**: [`NormalizedMessage`](../type-aliases/NormalizedMessage.md)

The target message carrying the signature.

Its fields are always a `Headers`, whatever shape was passed to [verify](../functions/verify.md), so a callback
can read them without normalizing first. Record occurrences are converted using the host
`Headers` semantics for application processing; RFC 9421's signature-base combination is a
separate representation and can differ for non-list fields.

***

### request?

> `readonly` `optional` **request?**: [`NormalizedRequest`](../type-aliases/NormalizedRequest.md)

The normalized related request, when response/request binding is in use.
