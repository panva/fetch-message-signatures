# Sender guide

A sender selects the parts of a Fetch message that are covered, supplies signature metadata, and
provides a cryptographic signer. Signing creates two Structured Field Dictionaries:
`Signature-Input`, which describes the signature base, and `Signature`, which carries the signature
bytes.

## Choose coverage first

Coverage is an application protocol decision. Start from what the recipient will authorize, then
cover every message property that can change that decision.

For a request that creates an order, a useful baseline might include:

- `@method`, so a signed `GET` cannot be replayed as `POST`;
- `@authority`, `@path`, and relevant `@query-param` components, so the signature is bound to its
  destination;
- fields that affect interpretation or authorization, such as `content-type` or an idempotency key;
  and
- `content-digest` when there is a body.

Covering `content-digest` authenticates the digest field. The sender must calculate the digest over
the right representation of the body, and the recipient must independently compare it with the
received body using RFC 9530 parsing and a locally accepted digest algorithm. The signature's
cryptographic algorithm allowlist and the `Content-Digest` hash algorithm allowlist are separate
policy decisions.

## Sign a request

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
})

console.log(signed.headers.get('signature-input'))
console.log(signed.headers.get('signature'))
```

`sign()` uses the label `sig1` unless `label` is supplied. It adds `created` using the current UNIX
time unless the ordered parameter list contains `['created', false]`. Use `now` to make tests and
fixtures deterministic.

The `alg` parameter is optional. If it is present, it must be a registered HTTP Message Signature
algorithm identifier and must equal the signer's `alg`. The recipient still chooses the algorithm
from trusted configuration; an `alg` value received from the wire is only a claim.

## Sign a response and bind it to its request

A response can cover `@status`, response fields, and components of the request that caused it. Add
the `req` parameter to every request component and supply the exact related `Request`.

```ts
declare const signer: FetchSig.SignerFactory
declare const request: Request
declare const response: Response

const signedResponse = await FetchSig.sign(response, {
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

The related request is contextual data, not something the package looks up. Keep the actual request
that was sent—including its final URL and fields—and pass that same request during response
verification.

## Create fields without cloning a message

`createSignature()` is the transport-neutral operation. It signs the supplied message and returns
the field values without changing the message or touching its body:

```ts
declare const request: Request
declare const signer: FetchSig.SignerFactory

const fields = await FetchSig.createSignature(request, {
  signer,
  label: 'application',
  components: ['@method', '@target-uri'],
  now: 1_735_689_600,
})

const headers = FetchSig.appendSignature(request.headers, fields)
```

This split is useful when a framework owns the response construction, when signature fields belong
in a transport-specific section, or when the application needs a custom body-stream strategy.

`appendSignature()` always returns a new `Headers`, `Request`, or `Response`. Existing signatures
are retained, and the new label must not collide with an existing label. The supplied fields are
parsed and checked before they are appended.

## Multiple signatures

Use distinct labels when independent parties or policies sign the same message:

```ts
declare const request: Request
declare const applicationSigner: FetchSig.SignerFactory
declare const auditSigner: FetchSig.SignerFactory

const applicationFields = await FetchSig.createSignature(request, {
  label: 'application',
  signer: applicationSigner,
  components: ['@method', '@authority', '@path'],
})
const withApplication = FetchSig.appendSignature(request, applicationFields)

const auditFields = await FetchSig.createSignature(withApplication, {
  label: 'audit',
  signer: auditSigner,
  components: ['@method', '@target-uri'],
})
const signed = FetchSig.appendSignature(withApplication, auditFields)
```

A label only pairs members of `Signature-Input` and `Signature`. RFC 9421 does not include the label
inside the signature base, so never use a label such as `admin` as evidence of who signed.

## Signed Fetch

`createSignedFetch()` wraps a Fetch implementation, signs every outgoing request, and can verify
each response against the exact signed request:

```ts
declare const signer: FetchSig.SignerFactory
declare const verifier: FetchSig.VerifierFactory

const signedFetch = FetchSig.createSignedFetch({
  sign: {
    signer,
    components: ['@method', '@authority', '@path'],
    parameters: [['keyid', 'client-key']],
  },
  verify: {
    verifier,
    policy: {
      requiredComponents: [
        '@status',
        FetchSig.component('@method', [['req', true]]),
        FetchSig.component('@path', [['req', true]]),
      ],
      requiredParameters: ['created', 'keyid'],
      algorithms: ['ed25519'],
      maxAge: 60,
    },
  },
})

const response = await signedFetch('https://api.example/orders')
```

Automatic redirects are changed to manual redirects. Follow a redirect in application code only
after validating it, construct the next request, remove stale signature fields, and sign again.

## Lower-level signature bases

`createSignatureBase()` returns the exact ASCII input to cryptography and does not add a default
`created` parameter:

```ts
const request = new Request('https://api.example/items?limit=10')

const base = FetchSig.createSignatureBase(request, {
  components: ['@method', '@authority', FetchSig.component('@query-param', [['name', 'limit']])],
  parameters: [['created', 1_735_689_600]],
})
```

It is useful for protocol diagnostics and interoperability fixtures. Prefer `sign()` or
`createSignature()` in application code so the signature bytes and serialized metadata are produced
together.

## Next steps

- Implement a [cryptographic provider](cryptography.md).
- Understand [component canonicalization](components.md).
- Account for [Fetch body and transport behavior](fetch.md).
- Give recipients an explicit [verification policy](recipient.md).
