# Function: signRequested()

## Call Signature

> **signRequested**(`message`, `request`, `options`): `Promise`<`Request`>

Fulfills and appends one parsed `Accept-Signature` request.

Appending transfers or reuses the source body stream. Consume the returned message and do not
treat the source message as independently readable afterward. Use [createRequestedSignature](createRequestedSignature.md)
and construct the final message explicitly when both bodies must remain readable.

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

Appending transfers or reuses the source body stream. Consume the returned message and do not
treat the source message as independently readable afterward. Use [createRequestedSignature](createRequestedSignature.md)
and construct the final message explicitly when both bodies must remain readable.

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

Appending transfers or reuses the source body stream. Consume the returned message and do not
treat the source message as independently readable afterward. Use [createRequestedSignature](createRequestedSignature.md)
and construct the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `request` | [`SignatureRequest`](../interfaces/SignatureRequest.md) |
| `options` | [`RequestedSignOptions`](../interfaces/RequestedSignOptions.md) |

### Returns

`Promise`<`Request` ∣ `Response`>
