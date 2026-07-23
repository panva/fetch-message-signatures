# Function: createSignature()

> **createSignature**(`message`, `options`): `Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>

Creates one HTTP message signature without modifying or cloning the Fetch message.

The returned one-member field values can be attached while constructing a message or passed to
[appendSignature](appendSignature.md). A `created` timestamp is added by default; pass `created: false` in
`parameters` to explicitly omit it.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

## Returns

`Promise`<[`SignatureFields`](../interfaces/SignatureFields.md)>

## Examples

Reach for this instead of [sign](sign.md) when a framework owns message construction, or when the
source message's body must stay readable: nothing here touches the message or its body.

```ts
declare const signer: FetchSig.SignerFactory

const request = new Request('https://api.example/orders', { method: 'POST', body: '{}' })

const fields = await FetchSig.createSignature(request, {
  signer,
  label: 'application',
  components: ['@method', '@target-uri'],
  now: 1_735_689_600,
})

// application=("@method" "@target-uri");created=1735689600
console.log(fields.signatureInput)

// application=:<base64 signature bytes>:
console.log(fields.signatureField)

// The source request is untouched, so its body is still readable here.
const headers = FetchSig.appendSignature(request.headers, fields)
```

`created` is added for you. Suppress it with `['created', false]`, or place it yourself to
control where it lands in the signed parameter order.

```ts
declare const message: Request
declare const signer: FetchSig.SignerFactory

const withoutCreated = await FetchSig.createSignature(message, {
  signer,
  components: ['@method'],
  parameters: [
    ['created', false],
    ['keyid', 'client-key'],
  ],
})

// sig1=("@method");keyid="client-key"
console.log(withoutCreated.signatureInput)

const createdLast = await FetchSig.createSignature(message, {
  signer,
  components: ['@method'],
  parameters: [
    ['keyid', 'client-key'],
    ['created', 1_735_689_600],
  ],
})

// sig1=("@method");keyid="client-key";created=1735689600
console.log(createdLast.signatureInput)
```
