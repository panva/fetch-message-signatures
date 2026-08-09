# Function: createSignatureBase()

> **createSignatureBase**(`message`, `options`): `string`

Creates the RFC 9421 signature base for a signable request or response.

Unlike [createSignature](createSignature.md), this low-level function does not add a default `created`
parameter.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | [`SignableRequest`](../type-aliases/SignableRequest.md) ∣ [`SignableResponse`](../type-aliases/SignableResponse.md) |
| `options` | [`SignatureBaseOptions`](../interfaces/SignatureBaseOptions.md) |

## Returns

`string`

## Example

The signature base is the exact ASCII string handed to cryptography: one line per covered
component, then the `@signature-params` line. Compare it byte for byte with a peer implementation
before suspecting the cryptography.

```ts
const request = new Request('https://example.com/items?limit=10', {
  method: 'POST',
  headers: { 'example-field': '  value  ' },
})

const base = FetchSig.createSignatureBase(request, {
  components: [
    '@method',
    '@authority',
    '@path',
    FetchSig.component('@query-param', [['name', 'limit']]),
    'example-field',
  ],
  parameters: [
    ['created', 1_735_689_600],
    ['keyid', 'interop-key'],
  ],
})

// "@method": POST
// "@authority": example.com
// "@path": /items
// "@query-param";name="limit": 10
// "example-field": value
// "@signature-params": ("@method" "@authority" "@path" "@query-param";name="limit"
//   "example-field");created=1735689600;keyid="interop-key"
console.log(base)
```
