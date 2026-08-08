# Interface: SignatureFieldsOptions

Options for serializing a signature that was produced elsewhere into its two HTTP fields.

## Contents

- [Properties](#properties)
  - [components](#components)
  - [signature](#signature)
  - [label?](#label)
  - [parameters?](#parameters)

## Properties

### components

> `readonly` **components**: readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[]

***

### signature

> `readonly` **signature**: `Uint8Array`

The signature over the corresponding signature base.

***

### label?

> `readonly` `optional` **label?**: `string`

***

### parameters?

> `readonly` `optional` **parameters?**: [`SignatureParameters`](../type-aliases/SignatureParameters.md)
