# Function: createAcceptSignature()

> **createAcceptSignature**(`requests`): `string`

Serializes one or more signature requests as an `Accept-Signature` Structured Field Dictionary.

Use [appendAcceptSignature](appendAcceptSignature.md) when the sender message is available so component applicability
can also be checked against the type of the requested target message.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

## Returns

`string`
