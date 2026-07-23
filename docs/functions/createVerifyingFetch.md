# Function: createVerifyingFetch()

> **createVerifyingFetch**(`options`): (`input`, `init?`) => `Promise`<`Response`>

Creates a Fetch-compatible function that verifies every response against its exact request.

Automatic redirects are changed to manual redirects because Fetch does not expose the request
that produced a response after following a redirect.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `options` | [`VerifyingFetchOptions`](../interfaces/VerifyingFetchOptions.md) |

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
