# Interface: VerifiedSignature

A successfully verified signature.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [algorithm](#algorithm)
  - [components](#components)
  - [label](#label)
  - [parameters](#parameters)
  - [signature](#signature)

## Extends

- [`MessageSignature`](MessageSignature.md)

## Properties

### algorithm

> `readonly` **algorithm**: `string`

***

### components

> `readonly` **components**: readonly [`MessageComponent`](MessageComponent.md)\[]

#### Inherited from

[`MessageSignature`](MessageSignature.md).[`components`](MessageSignature.md#components)

***

### label

> `readonly` **label**: `string`

#### Inherited from

[`MessageSignature`](MessageSignature.md).[`label`](MessageSignature.md#label)

***

### parameters

> `readonly` **parameters**: readonly readonly \[`string`, [`StructuredFieldBareItem`](../type-aliases/StructuredFieldBareItem.md)]\[]

#### Inherited from

[`MessageSignature`](MessageSignature.md).[`parameters`](MessageSignature.md#parameters)

***

### signature

> `readonly` **signature**: `Uint8Array`

#### Inherited from

[`MessageSignature`](MessageSignature.md).[`signature`](MessageSignature.md#signature)
