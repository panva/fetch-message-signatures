# Interface: Verifier

A verifier implementation returned by a [VerifierFactory](../type-aliases/VerifierFactory.md).

`verify()` may return the result directly or a Promise of it, so a synchronous cryptographic
library needs no wrapper. Web Cryptography is asynchronous, so every verifier this package builds
returns a Promise.

## Contents

- [Methods](#methods)
  - [verify()](#verify)
- [Properties](#properties)
  - [alg](#alg)
  - [type](#type)

## Methods

### verify()

> **verify**(`data`, `signature`): `boolean` ∣ `Promise`<`boolean`>

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `data` | `Uint8Array` |
| `signature` | `Uint8Array` |

#### Returns

`boolean` ∣ `Promise`<`boolean`>

## Properties

### alg

> `readonly` **alg**: `string`

The algorithm selected by configuration or key metadata.

***

### type

> `readonly` **type**: `"verifier"`
