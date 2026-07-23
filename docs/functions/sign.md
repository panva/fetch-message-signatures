# Function: sign()

## Call Signature

> **sign**(`message`, `options`): `Promise`<`Request`>

Creates and appends one HTTP message signature.

Appending transfers or reuses the source body stream. Consume the returned message and do not
treat the source message as independently readable afterward. Use [createSignature](createSignature.md) and
construct the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

### Returns

`Promise`<`Request`>

## Call Signature

> **sign**(`message`, `options`): `Promise`<`Response`>

Creates and appends one HTTP message signature.

Appending transfers or reuses the source body stream. Consume the returned message and do not
treat the source message as independently readable afterward. Use [createSignature](createSignature.md) and
construct the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Response` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

### Returns

`Promise`<`Response`>

## Call Signature

> **sign**(`message`, `options`): `Promise`<`Request` ∣ `Response`>

Creates and appends one HTTP message signature.

Appending transfers or reuses the source body stream. Consume the returned message and do not
treat the source message as independently readable afterward. Use [createSignature](createSignature.md) and
construct the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

### Returns

`Promise`<`Request` ∣ `Response`>
