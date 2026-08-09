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

> `readonly` **message**: [`MessageSnapshot`](../type-aliases/MessageSnapshot.md)

The target message carrying the signature.

This is an immutable, package-owned snapshot captured at the start of verification. Field names
are lowercase and each value is the ordered list of occurrences used to construct the signature
base. Every verification callback observes the same snapshot values.

***

### request?

> `readonly` `optional` **request?**: [`RequestSnapshot`](RequestSnapshot.md)

The related-request snapshot, when response/request binding is in use.
