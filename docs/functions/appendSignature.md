# Function: appendSignature()

## Call Signature

> **appendSignature**(`headers`, `fields`): `Headers`

Adds one signature to `Headers` and returns a new `Headers` object.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Headers` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Headers`

## Call Signature

> **appendSignature**(`headers`, `fields`): `Request`

Adds one signature to a `Request` and returns a new `Request`.

The returned message transfers or reuses the source body stream. Consume the returned request and
do not treat the source request as independently readable afterward. Use [createSignature](createSignature.md)
and construct the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Request` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Request`

## Call Signature

> **appendSignature**(`headers`, `fields`): `Response`

Adds one signature to a `Response` and returns a new `Response`.

The returned message transfers or reuses the source body stream. Consume the returned response
and do not treat the source response as independently readable afterward. Use
[createSignature](createSignature.md) and construct the final message explicitly when both bodies must remain
readable.

Fetch does not provide a way to clone a network response while changing its immutable headers.
The returned response preserves status, status text, headers, and body, but Fetch-managed
metadata such as `url`, `redirected`, and `type` cannot be preserved.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Response` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Response`

## Call Signature

> **appendSignature**(`headers`, `fields`): `Request` ∣ `Response` ∣ `Headers`

Adds one signature to `Headers` and returns a new `Headers` object.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Request` ∣ `Response` ∣ `Headers` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Request` ∣ `Response` ∣ `Headers`
