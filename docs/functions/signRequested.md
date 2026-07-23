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
