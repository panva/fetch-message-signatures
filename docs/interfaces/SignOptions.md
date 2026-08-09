# Interface: SignOptions

Sender options.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [components](#components)
  - [signer](#signer)
  - [fieldValues?](#fieldvalues)
  - [label?](#label)
  - [now?](#now)
  - [parameters?](#parameters)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extends

- [`SignatureContext`](SignatureContext.md)

## Properties

### components

> `readonly` **components**: readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[]

***

### signer

> `readonly` **signer**: [`SignerFactory`](../type-aliases/SignerFactory.md)

***

### fieldValues?

> `readonly` `optional` **fieldValues?**: [`FieldValues`](../type-aliases/FieldValues.md)

Adapter for raw field occurrences and trailers.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`fieldValues`](SignatureContext.md#fieldvalues)

***

### label?

> `readonly` `optional` **label?**: `string`

***

### now?

> `readonly` `optional` **now?**: `number` ∣ `Date`

Injectable clock used for the default `created` parameter.

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
