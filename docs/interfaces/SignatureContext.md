# Interface: SignatureContext

Options shared by signature-base creation, signing, and verification.

## Contents

- [Extended by](#extended-by)
- [Properties](#properties)
  - [fieldValues?](#fieldvalues)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extended by

- [`SignOptions`](SignOptions.md)
- [`VerifyOptions`](VerifyOptions.md)
- [`SignatureBaseOptions`](SignatureBaseOptions.md)
- [`RequestedSignOptions`](RequestedSignOptions.md)

## Properties

### fieldValues?

> `readonly` `optional` **fieldValues?**: [`FieldValues`](../type-aliases/FieldValues.md)

Adapter for raw field occurrences and trailers.

***

### request?

> `readonly` `optional` **request?**: [`SignableRequest`](../type-aliases/SignableRequest.md)

The exact request that triggered a response. Required when a response signature uses `;req`.

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md)>>

Structured Field top-level types, indexed by lowercase HTTP field name.
