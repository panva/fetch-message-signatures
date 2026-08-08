# Function: appendAcceptSignature()

## Call Signature

> **appendAcceptSignature**(`message`, `requests`): `Request`

Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message.

On a request, the field asks for signatures on the response. On a response, it asks for
signatures on the client's next request.

The returned message passes the source body to a new Fetch message without explicitly cloning or
buffering it. The source body's observable state is runtime-dependent. Consume the returned
message and do not rely on the source message afterward. Use [createAcceptSignature](createAcceptSignature.md) and
construct the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

### Returns

`Request`

### Examples

Ask the server to sign its response. Because the field is on a request, the requested components
are checked against a response, which is why the request components carry `req`.

```ts
const request = FetchSig.appendAcceptSignature(
  new Request('https://api.example/orders/123'),
  [
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
  ],
)

// response=("@status" "content-type" "@method";req "@path";req);created;keyid="server-key"
console.log(request.headers.get('accept-signature'))
```

On a response the field asks the client to sign its next request, so the requested components are
checked against a request and `req` is not allowed.

```ts
const response = FetchSig.appendAcceptSignature(new Response('', { status: 401 }), [
  {
    label: 'client',
    components: ['@method', '@authority', '@path'],
    parameters: [['nonce', 'e4c7f2a1']],
  },
])

// client=("@method" "@authority" "@path");nonce="e4c7f2a1"
console.log(response.headers.get('accept-signature'))
```

## Call Signature

> **appendAcceptSignature**(`message`, `requests`): `Response`

Adds `Accept-Signature` requests to a `Response` and returns a new `Response`.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Response` |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

### Returns

`Response`

## Call Signature

> **appendAcceptSignature**(`message`, `requests`): `Request` ∣ `Response`

Adds `Accept-Signature` requests to a message whose type is not known statically.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `requests` | readonly [`SignatureRequestInput`](../interfaces/SignatureRequestInput.md)\[] |

### Returns

`Request` ∣ `Response`
