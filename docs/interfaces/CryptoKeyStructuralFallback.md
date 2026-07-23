# Interface: CryptoKeyStructuralFallback

Used as [CryptoKey](../type-aliases/CryptoKey.md) when the host runtime's `crypto` global is not exposed on `typeof
globalThis`, including when it is absent from ambient types or declared with `const` or `let`. It
stays structurally compatible with host `CryptoKey` declarations.

## Contents

- [Properties](#properties)
  - [algorithm](#algorithm)
  - [extractable](#extractable)
  - [type](#type)
  - [usages](#usages)

## Properties

### algorithm

> `readonly` **algorithm**: `object`

#### name

> **name**: `string`

***

### extractable

> `readonly` **extractable**: `boolean`

***

### type

> `readonly` **type**: `string`

***

### usages

> `readonly` **usages**: `string`\[]
