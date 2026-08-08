# Function: createRequestedSignature()

> **createRequestedSignature**(`message`, `request`, `options`): `Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>

Fulfills one parsed `Accept-Signature` request without modifying the target Fetch message.

Signs exactly the requested label and covered components, and processes every requested signature
metadata parameter: a requested `created` defaults to the signing clock, a requested `expires` or
`keyid` must be supplied here, and a requested parameter this implementation does not define must
be supplied here with the same value. Additional parameters may be supplied and are appended.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `request` | [`SignatureRequest`](../interfaces/SignatureRequest.md) |
| `options` | [`RequestedSignOptions`](../interfaces/RequestedSignOptions.md) |

## Returns

`Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>

## Example

The label and covered components come from the request. The values that cannot be chosen from the
request alone come from the signer. Here `keyid` was requested and so must be selected
explicitly, and `expires` is a local policy decision rather than something the peer dictates.

```ts
declare const incomingRequest: Request
declare const response: Response
declare const signer: FetchSig.SignerFactory

const [signatureRequest] = FetchSig.getSignatureRequests(incomingRequest)
if (signatureRequest === undefined) {
  throw new Error('No signature request')
}

const fields = await FetchSig.createRequestedSignature(response, signatureRequest, {
  signer,
  request: incomingRequest,
  parameters: [
    ['keyid', 'server-key'],
    ['expires', 1_735_689_660],
  ],
  now: 1_735_689_600,
})

// response=("@status" "content-type" "@method";req "@path";req)
//   ;created=1735689600;keyid="server-key";expires=1735689660
console.log(fields.signatureInput)
```
