# Function: createSignature()

> **createSignature**(`message`, `options`): `Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>

Creates one HTTP message signature without modifying or cloning the Fetch message.

The returned one-member field values can be attached while constructing a message or passed to
[appendSignature](appendSignature.md). A `created` timestamp is added by default; pass `created: false` in
`parameters` to explicitly omit it.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

## Returns

`Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>
