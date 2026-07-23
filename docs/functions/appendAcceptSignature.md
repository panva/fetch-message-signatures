# Function: appendAcceptSignature()

## Call Signature

> **appendAcceptSignature**(`message`, `requests`): `Request`

Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message.

On a request, the field asks for signatures on the response. On a response, it asks for
signatures on the client's next request.

The returned message transfers or reuses the source body stream. Consume the returned message and
do not treat the source message as independently readable afterward. Use
[createAcceptSignature](createAcceptSignature.md) and construct the final message explicitly when both bodies must
remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

### Returns

`Request`

## Call Signature

> **appendAcceptSignature**(`message`, `requests`): `Response`

Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message.

On a request, the field asks for signatures on the response. On a response, it asks for
signatures on the client's next request.

The returned message transfers or reuses the source body stream. Consume the returned message and
do not treat the source message as independently readable afterward. Use
[createAcceptSignature](createAcceptSignature.md) and construct the final message explicitly when both bodies must
remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Response` |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

### Returns

`Response`

## Call Signature

> **appendAcceptSignature**(`message`, `requests`): `Request` ∣ `Response`

Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message.

On a request, the field asks for signatures on the response. On a response, it asks for
signatures on the client's next request.

The returned message transfers or reuses the source body stream. Consume the returned message and
do not treat the source message as independently readable afterward. Use
[createAcceptSignature](createAcceptSignature.md) and construct the final message explicitly when both bodies must
remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

### Returns

`Request` ∣ `Response`
