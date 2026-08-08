# Interface: SignatureFields

The result of creating one signature, ready to be added to the corresponding HTTP fields.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [components](#components)
  - [label](#label)
  - [parameters](#parameters)
  - [signature](#signature)
  - [signatureField](#signaturefield)
  - [signatureInput](#signatureinput)

## Extends

- [`MessageSignature`](MessageSignature.md)

## Properties

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

***

### signatureField

> `readonly` **signatureField**: `string`

A one-member `Signature` Structured Field Dictionary.

***

### signatureInput

> `readonly` **signatureInput**: `string`

A one-member `Signature-Input` Structured Field Dictionary.
