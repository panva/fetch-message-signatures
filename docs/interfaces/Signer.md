# Interface: Signer

A signer implementation returned by a [SignerFactory](../type-aliases/SignerFactory.md).

`sign()` may return the signature bytes directly or a Promise of them, so a synchronous
cryptographic library needs no wrapper. Web Cryptography is asynchronous, so every signer this
package builds returns a Promise.

## Contents

- [Methods](#methods)
  - [sign()](#sign)
- [Properties](#properties)
  - [alg](#alg)
  - [type](#type)

## Methods

### sign()

> **sign**(`data`): `Uint8Array`<`ArrayBufferLike`> ∣ `Promise`<`Uint8Array`<`ArrayBufferLike`>>

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `data` | `Uint8Array` |

#### Returns

`Uint8Array`<`ArrayBufferLike`> ∣ `Promise`<`Uint8Array`<`ArrayBufferLike`>>

## Properties

### alg

> `readonly` **alg**: `string`

The algorithm selected by configuration or key metadata.

***

### type

> `readonly` **type**: `"signer"`
