# Interface: Verifier

A Promise-based verifier implementation returned by a [VerifierFactory](../type-aliases/VerifierFactory.md).

## Contents

- [Methods](#methods)
  - [verify()](#verify)
- [Properties](#properties)
  - [alg](#alg)
  - [type](#type)

## Methods

### verify()

> **verify**(`data`, `signature`): `Promise`<`boolean`>

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `data` | `Uint8Array` |
| `signature` | `Uint8Array` |

#### Returns

`Promise`<`boolean`>

## Properties

### alg

> `readonly` **alg**: `string`

The algorithm selected by configuration or key metadata.

***

### type

> `readonly` **type**: `"verifier"`
