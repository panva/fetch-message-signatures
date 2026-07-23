# Function: createSigningFetch()

> **createSigningFetch**(`options`): (`input`, `init?`) => `Promise`<`Response`>

Creates a Fetch-compatible function that signs every outgoing request.

Automatic redirects are changed to manual redirects because Fetch cannot re-sign each redirected
request and could otherwise forward stale signature fields to a different origin.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `options` | [`SigningFetchOptions`](../interfaces/SigningFetchOptions.md) |

## Returns

> (`input`, `init?`): `Promise`<`Response`>

[MDN Reference](https://developer.mozilla.org/docs/Web/API/Window/fetch)

### Parameters

| Parameter | Type |
| :------ | :------ |
| `input` | `URL` ∣ `RequestInfo` |
| `init?` | `RequestInit` |

### Returns

`Promise`<`Response`>
