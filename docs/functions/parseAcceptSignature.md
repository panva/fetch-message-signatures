# Function: parseAcceptSignature()

> **parseAcceptSignature**(`value`): readonly [`SignatureRequest`](../interfaces/SignatureRequest.md)\[]

Parses an `Accept-Signature` field value into its labeled signature requests.

Validates component identifiers and the value types of requested signature metadata parameters,
where `created` and `expires` carry no value because the signer chooses the timestamps. It does
not check the requested components against a message; use [getSignatureRequests](getSignatureRequests.md) when the
message is available.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `string` |

## Returns

readonly [`SignatureRequest`](../interfaces/SignatureRequest.md)\[]

## Example

A requested `created` carries no value, because the signer chooses the timestamp. A requested
`keyid` carries the value the signer is being asked to use.

```ts
const [request] = FetchSig.parseAcceptSignature(
  'response=("@status" "content-type" "@method";req);created;keyid="server-key"',
)

// response
console.log(request!.label)

// [ '@status', 'content-type', '@method' ]
console.log(request!.components.map(({ name }) => name))

// [ [ 'created', true ], [ 'keyid', 'server-key' ] ]
console.log(request!.parameters)
```
