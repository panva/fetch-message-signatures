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

## Examples

Drop-in replacement for `fetch` that signs on the way out. Use this one, rather than
[createSignedFetch](createSignedFetch.md), when a bundler should be able to drop the verification code.

```ts
declare const privateKey: CryptoKey

const signingFetch = FetchSig.createSigningFetch({
  sign: {
    signer: FetchSig.ed25519Signer(privateKey),
    components: ['@method', '@authority', '@path'],
    parameters: [
      ['alg', 'ed25519'],
      ['keyid', 'client-key'],
    ],
  },
})

// Takes the same arguments as fetch.
const response = await signingFetch('https://api.example/orders', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: '{}',
})
```

Components and parameters are copied when the wrapper is created and cannot be changed
afterwards. Key material can still rotate, because the signer factory runs once per signature.

```ts
declare const keys: { current: CryptoKey }
declare const upstreamFetch: typeof fetch

const signingFetch = FetchSig.createSigningFetch({
  sign: {
    signer: () => FetchSig.ed25519Signer(keys.current)(),
    components: ['@method', '@authority', '@path'],
    parameters: [['alg', 'ed25519']],
  },
  // Delegate to something other than the global fetch, such as an instrumented client.
  fetch: upstreamFetch,
})
```
