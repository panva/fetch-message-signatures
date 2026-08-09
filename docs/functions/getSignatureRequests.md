# Function: getSignatureRequests()

> **getSignatureRequests**(`message`): readonly [`SignatureRequest`](../interfaces/SignatureRequest.md)\[]

Parses every signature request carried by a message and checks that each requested component
applies to the message that would be signed.

The target message is the other direction: `Accept-Signature` on a request asks for a signature
on the response, and on a response it asks for a signature on the client's next request. Returns
an empty array when the message carries no `Accept-Signature` field.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | [`SignableRequest`](../type-aliases/SignableRequest.md) ∣ [`SignableResponse`](../type-aliases/SignableResponse.md) |

## Returns

readonly [`SignatureRequest`](../interfaces/SignatureRequest.md)\[]

## Example

A server decides which request it is willing to fulfill. The parsed request is untrusted input,
so check the label and the coverage against local policy before signing anything.

```ts
declare const incomingRequest: Request
declare const response: Response
declare const signer: FetchSig.SignerFactory

const [signatureRequest] = FetchSig.getSignatureRequests(incomingRequest)
if (signatureRequest === undefined || signatureRequest.label !== 'response') {
  throw new Error('No supported signature request')
}

const signed = await FetchSig.signRequested(response, signatureRequest, {
  signer,
  request: incomingRequest,
  parameters: [['keyid', 'server-key']],
})
```
