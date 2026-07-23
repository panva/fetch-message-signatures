# Function: sign()

## Call Signature

> **sign**(`message`, `options`): `Promise`<`Request`>

Creates and appends one HTTP message signature.

Appending passes the source body to a new Fetch message without explicitly cloning or buffering
it. The source body's observable state is runtime-dependent. Consume the returned message and do
not rely on the source message afterward. Use [createSignature](createSignature.md) and construct the final
message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

### Returns

`Promise`<`Request`>

### Examples

Sign a request. Cover everything the recipient will base a decision on: the method so a `GET`
cannot be replayed as a `POST`, the destination, and the fields that change how the body is
interpreted.

```ts
declare const signer: FetchSig.SignerFactory

const unsigned = new Request('https://api.example/orders?account=123', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'content-digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
  },
  body: '',
})

const signed = await FetchSig.sign(unsigned, {
  signer,
  components: [
    '@method',
    '@authority',
    '@path',
    FetchSig.component('@query-param', [['name', 'account']]),
    'content-type',
    'content-digest',
  ],
  parameters: [
    ['alg', 'ed25519'],
    ['keyid', 'https://issuer.example/keys/current'],
    ['tag', 'order'],
  ],
  now: 1_735_689_600,
})

// sig1=("@method" "@authority" "@path" "@query-param";name="account" "content-type"
//   "content-digest");created=1735689600;alg="ed25519"
//   ;keyid="https://issuer.example/keys/current";tag="order"
console.log(signed.headers.get('signature-input'))

// Send the returned request; the source request must not be reused.
await fetch(signed)
```

Sign a response and bind it to the exact request that produced it. Request components need the
`req` parameter, and that request has to be supplied.

```ts
declare const signer: FetchSig.SignerFactory
declare const request: Request
declare const response: Response

const signed = await FetchSig.sign(response, {
  signer,
  request,
  components: [
    '@status',
    'content-type',
    FetchSig.component('@method', [['req', true]]),
    FetchSig.component('@authority', [['req', true]]),
    FetchSig.component('@path', [['req', true]]),
  ],
  parameters: [['keyid', 'https://issuer.example/keys/current']],
})
```

## Call Signature

> **sign**(`message`, `options`): `Promise`<`Response`>

Creates and appends one HTTP message signature.

Appending passes the source body to a new Fetch message without explicitly cloning or buffering
it. The source body's observable state is runtime-dependent. Consume the returned message and do
not rely on the source message afterward. Use [createSignature](createSignature.md) and construct the final
message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Response` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

### Returns

`Promise`<`Response`>

### Examples

Sign a request. Cover everything the recipient will base a decision on: the method so a `GET`
cannot be replayed as a `POST`, the destination, and the fields that change how the body is
interpreted.

```ts
declare const signer: FetchSig.SignerFactory

const unsigned = new Request('https://api.example/orders?account=123', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'content-digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
  },
  body: '',
})

const signed = await FetchSig.sign(unsigned, {
  signer,
  components: [
    '@method',
    '@authority',
    '@path',
    FetchSig.component('@query-param', [['name', 'account']]),
    'content-type',
    'content-digest',
  ],
  parameters: [
    ['alg', 'ed25519'],
    ['keyid', 'https://issuer.example/keys/current'],
    ['tag', 'order'],
  ],
  now: 1_735_689_600,
})

// sig1=("@method" "@authority" "@path" "@query-param";name="account" "content-type"
//   "content-digest");created=1735689600;alg="ed25519"
//   ;keyid="https://issuer.example/keys/current";tag="order"
console.log(signed.headers.get('signature-input'))

// Send the returned request; the source request must not be reused.
await fetch(signed)
```

Sign a response and bind it to the exact request that produced it. Request components need the
`req` parameter, and that request has to be supplied.

```ts
declare const signer: FetchSig.SignerFactory
declare const request: Request
declare const response: Response

const signed = await FetchSig.sign(response, {
  signer,
  request,
  components: [
    '@status',
    'content-type',
    FetchSig.component('@method', [['req', true]]),
    FetchSig.component('@authority', [['req', true]]),
    FetchSig.component('@path', [['req', true]]),
  ],
  parameters: [['keyid', 'https://issuer.example/keys/current']],
})
```

## Call Signature

> **sign**(`message`, `options`): `Promise`<`Request` ∣ `Response`>

Creates and appends one HTTP message signature.

Appending passes the source body to a new Fetch message without explicitly cloning or buffering
it. The source body's observable state is runtime-dependent. Consume the returned message and do
not rely on the source message afterward. Use [createSignature](createSignature.md) and construct the final
message explicitly when both bodies must remain readable.

### Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`SignOptions`](../interfaces/SignOptions.md) |

### Returns

`Promise`<`Request` ∣ `Response`>

### Examples

Sign a request. Cover everything the recipient will base a decision on: the method so a `GET`
cannot be replayed as a `POST`, the destination, and the fields that change how the body is
interpreted.

```ts
declare const signer: FetchSig.SignerFactory

const unsigned = new Request('https://api.example/orders?account=123', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'content-digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
  },
  body: '',
})

const signed = await FetchSig.sign(unsigned, {
  signer,
  components: [
    '@method',
    '@authority',
    '@path',
    FetchSig.component('@query-param', [['name', 'account']]),
    'content-type',
    'content-digest',
  ],
  parameters: [
    ['alg', 'ed25519'],
    ['keyid', 'https://issuer.example/keys/current'],
    ['tag', 'order'],
  ],
  now: 1_735_689_600,
})

// sig1=("@method" "@authority" "@path" "@query-param";name="account" "content-type"
//   "content-digest");created=1735689600;alg="ed25519"
//   ;keyid="https://issuer.example/keys/current";tag="order"
console.log(signed.headers.get('signature-input'))

// Send the returned request; the source request must not be reused.
await fetch(signed)
```

Sign a response and bind it to the exact request that produced it. Request components need the
`req` parameter, and that request has to be supplied.

```ts
declare const signer: FetchSig.SignerFactory
declare const request: Request
declare const response: Response

const signed = await FetchSig.sign(response, {
  signer,
  request,
  components: [
    '@status',
    'content-type',
    FetchSig.component('@method', [['req', true]]),
    FetchSig.component('@authority', [['req', true]]),
    FetchSig.component('@path', [['req', true]]),
  ],
  parameters: [['keyid', 'https://issuer.example/keys/current']],
})
```
