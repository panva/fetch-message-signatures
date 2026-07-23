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

## Example

Both directions in one wrapper. Prefer this over nesting [createSigningFetch](createSigningFetch.md) inside
[createVerifyingFetch](createVerifyingFetch.md), which would verify against a different request object and can
reconstruct a streaming request an extra time.

```ts
declare const privateKey: CryptoKey
declare const verifier: FetchSig.VerifierFactory

const signedFetch = FetchSig.createSignedFetch({
  sign: {
    signer: FetchSig.ed25519Signer(privateKey),
    components: ['@method', '@authority', '@path'],
    parameters: [['keyid', 'client-key']],
  },
  verify: {
    verifier,
    policy: {
      // The response is bound to the request this wrapper signed.
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

const response = await signedFetch('https://api.example/orders')
```
