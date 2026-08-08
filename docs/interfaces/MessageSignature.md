# Interface: MessageSignature

A parsed HTTP message signature.

## Contents

- [Extended by](#extended-by)
- [Properties](#properties)
  - [components](#components)
  - [label](#label)
  - [parameters](#parameters)
  - [signature](#signature)

## Extended by

- [`SignatureFields`](SignatureFields.md)
- [`VerifiedSignature`](VerifiedSignature.md)

## Properties

### components

> `readonly` **components**: readonly [`MessageComponent`](MessageComponent.md)\[]

***

### label

> `readonly` **label**: `string`

***

### parameters

> `readonly` **parameters**: readonly readonly \[`string`, [`StructuredFieldBareItem`](../type-aliases/StructuredFieldBareItem.md)]\[]

***

### signature

> `readonly` **signature**: `Uint8Array`
