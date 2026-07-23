# Function: createRequestedSignature()

> **createRequestedSignature**(`message`, `request`, `options`): `Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>

Fulfills one parsed `Accept-Signature` request without modifying the target Fetch message.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `request` | [`SignatureRequest`](../interfaces/SignatureRequest.md) |
| `options` | [`RequestedSignOptions`](../interfaces/RequestedSignOptions.md) |

## Returns

`Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>
