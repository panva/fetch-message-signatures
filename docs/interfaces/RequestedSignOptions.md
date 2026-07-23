# Interface: RequestedSignOptions

Options for fulfilling an `Accept-Signature` member.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [signer](#signer)
  - [fieldValues?](#fieldvalues)
  - [now?](#now)
  - [parameters?](#parameters)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extends

- [`SignatureContext`](SignatureContext.md)

## Properties

### signer

> `readonly` **signer**: [`SignerFactory`](../type-aliases/SignerFactory.md)

***

### fieldValues?

> `readonly` `optional` **fieldValues?**: [`FieldValues`](../type-aliases/FieldValues.md)

Adapter for raw field occurrences and trailers.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`fieldValues`](SignatureContext.md#fieldvalues)

***

### now?

> `readonly` `optional` **now?**: `number` ∣ `Date`

***

### parameters?

> `readonly` `optional` **parameters?**: [`SignatureParameters`](../type-aliases/SignatureParameters.md)

Values that satisfy requested parameters and any additional parameters selected by the signer.
An `expires` request requires an explicit `expires` value here.

***

### request?

> `readonly` `optional` **request?**: `Request`

The exact request that triggered a response. Required when a response signature uses `;req`.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`request`](SignatureContext.md#request)

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md) ∣ [`StructuredFieldDefinition`](StructuredFieldDefinition.md)>>

Structured Field definitions, indexed by lowercase HTTP field name.

A top-level type string is shorthand for an RFC 8941 definition. Use a definition object to opt
an application field into the RFC 9651 grammar.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`structuredFields`](SignatureContext.md#structuredfields)
