# Recipient guide

Verification combines application policy, trusted key and algorithm selection, and cryptographic
verification. `verify()` requires all three; it cannot be configured to accept any cryptographically
valid signature.

## Resolve a trusted verifier

The verifier factory receives parsed, unauthenticated metadata. Treat every value, including
`keyid`, `alg`, `tag`, and the covered component list, as attacker-controlled until verification
succeeds.

```ts
declare const trustedKeys: ReadonlyMap<string, CryptoKey>

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = signature.parameters.find(([name]) => name === 'keyid')?.[1]
  if (typeof keyid !== 'string') {
    throw new Error('A key identifier is required')
  }

  const key = trustedKeys.get(keyid)
  if (key === undefined) {
    throw new Error('Unknown signing key')
  }

  if (
    context.message instanceof Request &&
    new URL(context.message.url).origin !== 'https://api.example'
  ) {
    throw new Error('Key is not authorized for this origin')
  }

  return {
    type: 'verifier',
    alg: 'ed25519',
    async verify(data, signatureBytes) {
      return crypto.subtle.verify('Ed25519', key, signatureBytes, data)
    },
  }
}
```

The factory is synchronous. Resolve keys from a local trust store or pre-populated cache. If key
discovery requires network I/O, perform and validate that discovery before calling `verify()`; never
fetch an arbitrary URL merely because it appeared in an unverified `keyid`.

`context.message` is the target message. `context.request` is the related request when the target is
a response. Use this context to prevent a valid key from being accepted outside its authorized
tenant, origin, route, or message direction.

## Define explicit policy

```ts
declare const request: Request
declare const verifier: FetchSig.VerifierFactory

const verified = await FetchSig.verify(request, {
  verifier,
  policy: {
    requiredComponents: ['@method', '@authority', '@path', 'content-type', 'content-digest'],
    requiredParameters: ['created', 'keyid', 'nonce'],
    algorithms: ['ed25519'],
    maxAge: 60,
    clockSkew: 5,
    async validate(signature, context) {
      const nonce = signature.parameters.find(([name]) => name === 'nonce')?.[1]
      if (typeof nonce !== 'string') {
        throw new Error('A nonce is required')
      }
      await claimNonceOnce(nonce, context.message)
    },
  },
})

declare function claimNonceOnce(nonce: string, message: Request | Response): Promise<void>

console.log(verified.algorithm)
```

`requiredComponents` matches the complete component identifier, including parameters.
`requiredParameters` checks presence. `algorithms` is a non-empty allowlist checked against the
trusted verifier's algorithm, whether or not the signature carries `alg`.

Timestamp checks work as follows:

- `created` and `expires`, when present, must be integer UNIX timestamps;
- `created` cannot be later than `now + clockSkew`;
- `expires` cannot be earlier than `now - clockSkew` or earlier than `created`; and
- `maxAge` requires `created` and rejects a signature older than `maxAge + clockSkew`.

`policy.validate` runs only after cryptographic verification. It is the right place for atomic nonce
claiming, verified `tag` semantics, key-to-message authorization that depends on authenticated
metadata, and application-specific field validation.

## Verify a response

Pass the exact request that caused the response whenever covered components have `req`:

```ts
declare const signedRequest: Request
declare const response: Response
declare const verifier: FetchSig.VerifierFactory

await FetchSig.verify(response, {
  request: signedRequest,
  verifier,
  policy: {
    requiredComponents: [
      '@status',
      FetchSig.component('@method', [['req', true]]),
      FetchSig.component('@authority', [['req', true]]),
      FetchSig.component('@path', [['req', true]]),
    ],
    requiredParameters: ['created', 'keyid'],
    algorithms: ['ed25519'],
    maxAge: 60,
  },
})
```

Do not reconstruct the related request from assumptions if a proxy, redirect, or Fetch normalization
could have changed it. Preserve the request object that was actually sent.

To verify every response without signing outgoing requests, use the verification-only Fetch wrapper:

```ts
declare const verifier: FetchSig.VerifierFactory

const verifyingFetch = FetchSig.createVerifyingFetch({
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

const response = await verifyingFetch('https://api.example/orders')
```

The wrapper forces manual redirects because Fetch does not expose the exact request that produced a
response after following a redirect. Use `createSignedFetch()` rather than nesting directional
wrappers when requests must also be signed.

## Select among multiple signatures

When a message has more than one signature, verification requires an explicit label:

```ts
declare const message: Request
declare const verifier: FetchSig.VerifierFactory

const signatures = FetchSig.getSignatures(message)
for (const signature of signatures) {
  console.log(signature.label, signature.parameters)
}

await FetchSig.verify(message, {
  label: 'application',
  verifier,
  policy: {
    requiredComponents: ['@method', '@authority', '@path'],
    requiredParameters: ['created'],
    algorithms: ['ed25519'],
  },
})
```

Select labels from trusted local configuration. A received label is not authenticated and must not
stand for a role or identity by itself.

## Parsing is not verification

`parseSignatureInput()`, `parseSignature()`, and `getSignatures()` are inspection and routing tools.
Their output is not authenticated. Parsing successfully proves only that the fields satisfy the
expected syntax and structure.

`verify()` throws for malformed fields, missing context, policy rejection, key-selection errors,
algorithm mismatches, and cryptographic failure. Treat every thrown error as authentication failure
at a protocol boundary. Detailed error text can be useful in private diagnostics but generally
should not be reflected to an untrusted peer.
