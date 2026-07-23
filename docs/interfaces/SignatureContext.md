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

> `readonly` `optional` **request?**: `Request`

The exact request that triggered a response. Required when a response signature uses `;req`.

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md) ∣ [`StructuredFieldDefinition`](StructuredFieldDefinition.md)>>

Structured Field definitions, indexed by lowercase HTTP field name.

A top-level type string is shorthand for an RFC 8941 definition. Use a definition object to opt
an application field into the RFC 9651 grammar.
