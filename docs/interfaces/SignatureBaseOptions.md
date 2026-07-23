# Interface: SignatureBaseOptions

Options for direct signature-base creation.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [components](#components)
  - [fieldValues?](#fieldvalues)
  - [parameters?](#parameters)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extends

- [`SignatureContext`](SignatureContext.md)

## Properties

### components

> `readonly` **components**: readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[]

***

### fieldValues?

> `readonly` `optional` **fieldValues?**: [`FieldValues`](../type-aliases/FieldValues.md)

Adapter for raw field occurrences and trailers.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`fieldValues`](SignatureContext.md#fieldvalues)

***

### parameters?

> `readonly` `optional` **parameters?**: [`SignatureParameters`](../type-aliases/SignatureParameters.md)

***

### request?

> `readonly` `optional` **request?**: `Request`

The exact request that triggered a response. Required when a response signature uses `;req`.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`request`](SignatureContext.md#request)

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md)>>

Structured Field top-level types, indexed by lowercase HTTP field name.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`structuredFields`](SignatureContext.md#structuredfields)
