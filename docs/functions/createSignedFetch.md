# Function: createSignedFetch()

> **createSignedFetch**(`options`): (`input`, `init?`) => `Promise`<`Response`>

Creates a Fetch-compatible function that signs every outgoing request and, when configured,
verifies every returned response against that exact request.

Automatic redirects are changed to manual redirects because Fetch cannot re-sign each redirected
request and could otherwise forward stale signature fields to a different origin.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `options` | [`SignedFetchOptions`](../interfaces/SignedFetchOptions.md) |

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
