# Interface: SignatureBaseOptions

Options for direct signature-base creation.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [components](#components)
  - [parameters?](#parameters)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extends

- [`SignatureContext`](SignatureContext.md)

## Properties

### components

> `readonly` **components**: readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[]

***

### parameters?

> `readonly` `optional` **parameters?**: [`SignatureParameters`](../type-aliases/SignatureParameters.md)

***

### request?

> `readonly` `optional` **request?**: [`SignableRequest`](../type-aliases/SignableRequest.md)

The exact request that triggered a response. Required when a response signature uses `;req`.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`request`](SignatureContext.md#request)

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md)>>

Structured Field top-level types, indexed by lowercase HTTP field name.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`structuredFields`](SignatureContext.md#structuredfields)
