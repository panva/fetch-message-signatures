# Interface: SignedFetchOptions

Options for a Fetch-compatible function that signs requests and optionally verifies responses.

## Contents

- [Properties](#properties)
  - [sign](#sign)
  - [fetch?](#fetch)
  - [verify?](#verify)

## Properties

### sign

> `readonly` **sign**: `Omit`<[`SignOptions`](SignOptions.md), `"request"`>

***

### fetch?

> `readonly` `optional` **fetch?**: (`input`, `init?`) => `Promise`<`Response`>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `input` | `URL` ∣ `RequestInfo` |
| `init?` | `RequestInit` |

#### Returns

`Promise`<`Response`>

***

### verify?

> `readonly` `optional` **verify?**: `Omit`<[`VerifyOptions`](VerifyOptions.md), `"request"`>
