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

## Example

`created: true` asks for a timestamp without dictating it. A parameter given a value, such as
`keyid`, is a value the signer must reproduce exactly.

```ts
const value = FetchSig.createAcceptSignature([
  {
    label: 'response',
    components: [
      '@status',
      'content-type',
      FetchSig.component('@method', [['req', true]]),
      FetchSig.component('@path', [['req', true]]),
    ],
    parameters: [
      ['created', true],
      ['keyid', 'server-key'],
    ],
  },
])

// response=("@status" "content-type" "@method";req "@path";req);created;keyid="server-key"
console.log(value)
```
