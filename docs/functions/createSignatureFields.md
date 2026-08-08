# Function: createSignatureFields()

> **createSignatureFields**(`options`): [`SignatureFields`](../interfaces/SignatureFields.md)

Serializes a signature produced outside this package into its `Signature-Input` and `Signature`
fields.

This is the second half of [createSignatureBase](createSignatureBase.md), for a caller who signs the base bytes
themselves. Together the two cover what [createSignature](createSignature.md) does in one step, without its
`Promise`, so a synchronous signing library can be used where awaiting is not possible. Pass the
same `components` and `parameters` to both calls: they are what the signature commits to, and the
fields describe the base that was actually signed only if the two agree.

Neither function adds a default `created` timestamp, which [createSignature](createSignature.md) does, so
supplying one is the caller's job.

The signature bytes are copied, so a later mutation of the caller's array cannot change the
returned fields.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `options` | [`SignatureFieldsOptions`](../interfaces/SignatureFieldsOptions.md) |

## Returns

[`SignatureFields`](../interfaces/SignatureFields.md)

The signature together with the two field values it serializes to.

## Example

Signing with a synchronous library, in a context that cannot await.

```ts
declare function signSynchronously(data: Uint8Array): Uint8Array
declare const request: Request

const components = ['@method', '@authority', '@path']
const parameters = [
  ['created', 1_735_689_600],
  ['keyid', 'client-key'],
  ['alg', 'ed25519'],
] as const

const base = FetchSig.createSignatureBase(request, { components, parameters })
const fields = FetchSig.createSignatureFields({
  signature: signSynchronously(new TextEncoder().encode(base)),
  components,
  parameters,
})

const signed = FetchSig.appendSignature(request, fields)
```
