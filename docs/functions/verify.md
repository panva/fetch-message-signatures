# Function: verify()

> **verify**(`message`, `options`): `Promise`<[`VerifiedSignature`](../interfaces/VerifiedSignature.md)>

Verifies and applies explicit application policy to one HTTP message signature.

The function throws on parse, policy, context, key-selection, algorithm, or cryptographic
failure. When multiple signatures are present, callers must select a label explicitly.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`VerifyOptions`](../interfaces/VerifyOptions.md) |

## Returns

`Promise`<[`VerifiedSignature`](../interfaces/VerifiedSignature.md)>
