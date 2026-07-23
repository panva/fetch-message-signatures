# Function: appendSignature()

## Call Signature

> **appendSignature**(`headers`, `fields`): `Headers`

Adds one signature to `Headers` and returns a new `Headers` object.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Headers` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Headers`

### Example

Existing signatures are kept, so several parties can sign the same message under distinct labels.
A label that is already present is rejected rather than overwritten.

```ts
declare const request: Request
declare const applicationSigner: FetchSig.SignerFactory
declare const auditSigner: FetchSig.SignerFactory

const application = await FetchSig.createSignature(request, {
  label: 'application',
  signer: applicationSigner,
  components: ['@method', '@authority', '@path'],
})
let headers = FetchSig.appendSignature(request.headers, application)

const audit = await FetchSig.createSignature(new Request(request, { headers }), {
  label: 'audit',
  signer: auditSigner,
  components: ['@method', '@target-uri'],
})
headers = FetchSig.appendSignature(headers, audit)

// application=("@method" "@authority" "@path");created=…, audit=("@method" "@target-uri");created=…
console.log(headers.get('signature-input'))
```

## Call Signature

> **appendSignature**(`headers`, `fields`): `Request`

Adds one signature to a `Request` and returns a new `Request`.

The returned message passes the source body to a new Fetch message without explicitly cloning or
buffering it. The source body's observable state is runtime-dependent. Consume the returned
request and do not rely on the source request afterward. Use [createSignature](createSignature.md) and construct
the final message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Request` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Request`

## Call Signature

> **appendSignature**(`headers`, `fields`): `Response`

Adds one signature to a `Response` and returns a new `Response`.

The returned message passes the source body to a new Fetch message without explicitly cloning or
buffering it. The source body's observable state is runtime-dependent. Consume the returned
response and do not rely on the source response afterward. Use [createSignature](createSignature.md) and
construct the final message explicitly when both bodies must remain readable.

Fetch does not provide a way to clone a network response while changing its immutable headers.
The returned response preserves status, status text, headers, and body, but Fetch-managed
metadata such as `url`, `redirected`, and `type` cannot be preserved.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Response` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Response`

## Call Signature

> **appendSignature**(`headers`, `fields`): `Request` ∣ `Response` ∣ `Headers`

Adds one signature to `Headers` and returns a new `Headers` object.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `headers` | `Request` ∣ `Response` ∣ `Headers` |
| `fields` | [`SignatureFields`](../interfaces/SignatureFields.md) |

### Returns

`Request` ∣ `Response` ∣ `Headers`

### Example

Existing signatures are kept, so several parties can sign the same message under distinct labels.
A label that is already present is rejected rather than overwritten.

```ts
declare const request: Request
declare const applicationSigner: FetchSig.SignerFactory
declare const auditSigner: FetchSig.SignerFactory

const application = await FetchSig.createSignature(request, {
  label: 'application',
  signer: applicationSigner,
  components: ['@method', '@authority', '@path'],
})
let headers = FetchSig.appendSignature(request.headers, application)

const audit = await FetchSig.createSignature(new Request(request, { headers }), {
  label: 'audit',
  signer: auditSigner,
  components: ['@method', '@target-uri'],
})
headers = FetchSig.appendSignature(headers, audit)

// application=("@method" "@authority" "@path");created=…, audit=("@method" "@target-uri");created=…
console.log(headers.get('signature-input'))
```
