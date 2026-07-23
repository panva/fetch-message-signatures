# Function: signRequested()

## Call Signature

> **signRequested**(`message`, `request`, `options`): `Promise`<`Request`>

Fulfills and appends one parsed `Accept-Signature` request.

Appending passes the source body to a new Fetch message without explicitly cloning or buffering
it. The source body's observable state is runtime-dependent. Consume the returned message and do
not rely on the source message afterward. Use [createRequestedSignature](createRequestedSignature.md) and construct the
final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` |
| `request` | [`SignatureRequest`](../interfaces/SignatureRequest.md) |
| `options` | [`RequestedSignOptions`](../interfaces/RequestedSignOptions.md) |

### Returns

`Promise`<`Request`>

### Example

A server-side handler that answers `Accept-Signature` on the request it just received.

```ts
declare const signer: FetchSig.SignerFactory

async function handle(request: Request): Promise<Response> {
  const response = new Response('{"ok":true}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })

  const [signatureRequest] = FetchSig.getSignatureRequests(request)
  if (signatureRequest === undefined) {
    return response
  }

  return FetchSig.signRequested(response, signatureRequest, {
    signer,
    request,
    parameters: [['keyid', 'server-key']],
  })
}
```

## Call Signature

> **signRequested**(`message`, `request`, `options`): `Promise`<`Response`>

Fulfills and appends one parsed `Accept-Signature` request.

Appending passes the source body to a new Fetch message without explicitly cloning or buffering
it. The source body's observable state is runtime-dependent. Consume the returned message and do
not rely on the source message afterward. Use [createRequestedSignature](createRequestedSignature.md) and construct the
final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Response` |
| `request` | [`SignatureRequest`](../interfaces/SignatureRequest.md) |
| `options` | [`RequestedSignOptions`](../interfaces/RequestedSignOptions.md) |

### Returns

`Promise`<`Response`>

### Example

A server-side handler that answers `Accept-Signature` on the request it just received.

```ts
declare const signer: FetchSig.SignerFactory

async function handle(request: Request): Promise<Response> {
  const response = new Response('{"ok":true}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })

  const [signatureRequest] = FetchSig.getSignatureRequests(request)
  if (signatureRequest === undefined) {
    return response
  }

  return FetchSig.signRequested(response, signatureRequest, {
    signer,
    request,
    parameters: [['keyid', 'server-key']],
  })
}
```

## Call Signature

> **signRequested**(`message`, `request`, `options`): `Promise`<`Request` ∣ `Response`>

Fulfills and appends one parsed `Accept-Signature` request.

Appending passes the source body to a new Fetch message without explicitly cloning or buffering
it. The source body's observable state is runtime-dependent. Consume the returned message and do
not rely on the source message afterward. Use [createRequestedSignature](createRequestedSignature.md) and construct the
final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `request` | [`SignatureRequest`](../interfaces/SignatureRequest.md) |
| `options` | [`RequestedSignOptions`](../interfaces/RequestedSignOptions.md) |

### Returns

`Promise`<`Request` ∣ `Response`>

### Example

A server-side handler that answers `Accept-Signature` on the request it just received.

```ts
declare const signer: FetchSig.SignerFactory

async function handle(request: Request): Promise<Response> {
  const response = new Response('{"ok":true}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })

  const [signatureRequest] = FetchSig.getSignatureRequests(request)
  if (signatureRequest === undefined) {
    return response
  }

  return FetchSig.signRequested(response, signatureRequest, {
    signer,
    request,
    parameters: [['keyid', 'server-key']],
  })
}
```
