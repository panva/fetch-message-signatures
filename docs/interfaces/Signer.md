# Interface: Signer

A Promise-based signer implementation returned by a synchronous factory.

Synchronous cryptographic libraries can be adapted by declaring `sign` as an `async` method.

## Contents

- [Methods](#methods)
  - [sign()](#sign)
- [Properties](#properties)
  - [alg](#alg)
  - [type](#type)

## Methods

### sign()

> **sign**(`data`): `Promise`<`Uint8Array`<`ArrayBufferLike`>>

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `data` | `Uint8Array` |

#### Returns

`Promise`<`Uint8Array`<`ArrayBufferLike`>>

## Properties

### alg

> `readonly` **alg**: `string`

The algorithm selected by configuration or key metadata.

***

### type

> `readonly` **type**: `"signer"`
