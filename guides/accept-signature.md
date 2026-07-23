# `Accept-Signature`

`Accept-Signature` lets one party describe signatures it wants the other party to create. A request
field asks for a signature on the response. A response field asks for a signature on a subsequent
request.

Negotiation does not weaken recipient policy. The verifier must still decide whether the resulting
coverage, metadata, algorithm, and key are acceptable.

## Request a signed response

```ts
const request = FetchSig.appendAcceptSignature(new Request('https://api.example/orders/123'), [
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

console.log(request.headers.get('accept-signature'))
```

`appendAcceptSignature()` checks component applicability based on message direction and returns a
new message. `createAcceptSignature()` returns only the serialized field value, which is useful when
a framework owns field placement.

When a resource supports this request-side negotiation, make its responses uncacheable or add
`Accept-Signature` to `Vary`. Otherwise, a shared cache can serve a response carrying a signature
created for a different request. Configure caching before signing so any cache-control fields that
your profile covers are part of the signature.

For an `Accept-Signature` request, `created` and `expires` are bare Boolean true, meaning that the
sender selects a timestamp. Parameters such as `alg`, `keyid`, `nonce`, and `tag` carry the
requested value.

## Read signature requests

```ts
declare const request: Request

const requests = FetchSig.getSignatureRequests(request)
for (const signatureRequest of requests) {
  console.log(signatureRequest.label, signatureRequest.components)
}
```

`getSignatureRequests()` reads the message's `accept-signature` field and validates that its
components apply to the message that would be signed. `parseAcceptSignature()` parses a standalone
field value without message-direction validation.

The parsed request is untrusted input. Decide which request member to support, enforce local
coverage requirements, and constrain key and algorithm selection before fulfilling it.

## Fulfill one request

```ts
declare const incomingRequest: Request
declare const response: Response
declare const signer: FetchSig.SignerFactory

const [signatureRequest] = FetchSig.getSignatureRequests(incomingRequest)
if (signatureRequest === undefined || signatureRequest.label !== 'response') {
  throw new Error('No supported signature request')
}

const signedResponse = await FetchSig.signRequested(response, signatureRequest, {
  signer,
  request: incomingRequest,
  parameters: [['keyid', 'server-key']],
})
```

`createRequestedSignature()` is the pure equivalent that returns one-member signature fields.
`signRequested()` appends them to a new target message.

The fulfillment helpers require the application to supply values that cannot be chosen from the
request alone:

- requested `created` defaults to the current time, or `now` when supplied;
- requested `expires` requires an explicit expiration timestamp;
- requested `keyid` requires explicit key selection and must equal the requested value; and
- every unknown extension parameter must be explicitly supplied with the same value, proving that
  the application processed its semantics.

An `expires` request does not specify a duration. Choose the timestamp from local policy, not from
the request. The recipient still applies its own age, expiration, and replay policy.

Additional parameters may be supplied. `['created', false]` omits the normal default only when the
request did not require `created`.

## Multiple requests

`Accept-Signature` is a Structured Field Dictionary and can carry multiple labeled members.
Application code chooses which member or members it is willing to fulfill. Labels associate the
request with the resulting signature field, but remain unsigned and must not be treated as an
identity or authorization role.
