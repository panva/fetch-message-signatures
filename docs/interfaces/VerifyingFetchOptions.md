# Interface: VerifyingFetchOptions

Options for a Fetch-compatible function that verifies responses against their requests.

## Contents

- [Properties](#properties)
  - [verify](#verify)
  - [fetch?](#fetch)

## Properties

### verify

> `readonly` **verify**: `Omit`<[`VerifyOptions`](VerifyOptions.md), `"request"`>

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
