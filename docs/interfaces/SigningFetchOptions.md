# Interface: SigningFetchOptions

Options for a Fetch-compatible function that signs requests.

## Contents

- [Properties](#properties)
  - [sign](#sign)
  - [fetch?](#fetch)

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
