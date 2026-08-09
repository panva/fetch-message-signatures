# Interface: SignatureContext

Options shared by signature-base creation, signing, and verification.

## Contents

- [Extended by](#extended-by)
- [Properties](#properties)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extended by

- [`SignOptions`](SignOptions.md)
- [`VerifyOptions`](VerifyOptions.md)
- [`SignatureBaseOptions`](SignatureBaseOptions.md)
- [`RequestedSignOptions`](RequestedSignOptions.md)

## Properties

### request?

> `readonly` `optional` **request?**: [`SignableRequest`](../type-aliases/SignableRequest.md)

The exact request that triggered a response. Required when a response signature uses `;req`.

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md)>>

Structured Field top-level types, indexed by lowercase HTTP field name.
