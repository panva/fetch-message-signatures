# Function: createVerifyingFetch()

> **createVerifyingFetch**(`options`): (`input`, `init?`) => `Promise`<`Response`>

Drop-in `fetch` that verifies responses only. Requests are sent unsigned.

Use this when the peer signs what it returns but does not require a signature from you. To sign
outgoing requests as well, use [createSignedFetch](createSignedFetch.md). To sign without verifying, use
[createSigningFetch](createSigningFetch.md).

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

## Example

Verify every response without signing anything on the way out. The wrapper passes the exact
request it sent as the related request, which is what makes `;req` components verifiable.

```ts
declare const verifier: FetchSig.VerifierFactory

const verifyingFetch = FetchSig.createVerifyingFetch({
  verify: {
    verifier,
    policy: {
      requiredComponents: [
        '@status',
        FetchSig.component('@method', [['req', true]]),
        FetchSig.component('@path', [['req', true]]),
      ],
      requiredParameters: ['created', 'keyid'],
      algorithms: ['ed25519'],
      maxAge: 60,
    },
  },
})

// Rejects rather than resolving when the response is unsigned or the signature does not verify.
const response = await verifyingFetch('https://api.example/orders')

// The body is untouched by verification, and its integrity is not implied by it: check
// Content-Digest separately if the response covers one.
const orders = await response.json()
```
