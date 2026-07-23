# Function: createSignatureBase()

> **createSignatureBase**(`message`, `options`): `string`

Creates the RFC 9421 signature base for a Fetch `Request` or `Response`.

Unlike [createSignature](createSignature.md), this low-level function does not add a default `created`
parameter.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`SignatureBaseOptions`](../interfaces/SignatureBaseOptions.md) |

## Returns

`string`
