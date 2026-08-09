# Recipient guide

Verification combines application policy, trusted key and algorithm selection, and cryptographic
verification. `verify()` requires all three. It cannot be configured to accept any cryptographically
valid signature.

## Resolve a trusted verifier

The verifier factory receives parsed, unauthenticated metadata. Treat every value, including
`keyid`, `alg`, `tag`, and the covered component list, as attacker-controlled until verification
succeeds.

```ts
declare const trustedKeys: ReadonlyMap<string, CryptoKey>

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = FetchSig.getSignatureParameter(signature, 'keyid')
  if (typeof keyid !== 'string') {
    throw new FetchSig.VerificationError('unknown_key', 'A key identifier is required')
  }

  const key = trustedKeys.get(keyid)
  if (key === undefined) {
    throw new FetchSig.VerificationError('unknown_key', 'Unknown signing key')
  }

  // A request snapshot is the variant carrying `method` and `url`.
  if (
    'method' in context.message &&
    new URL(context.message.url).origin !== 'https://api.example'
  ) {
    throw new FetchSig.VerificationError('unknown_key', 'Signing key is not valid for this message')
  }

  return {
    alg: 'ed25519',
    async verify(data, signatureBytes) {
      return crypto.subtle.verify('Ed25519', key, signatureBytes, data)
    },
  }
}
```

The factory may return a Promise, so a key that has to be fetched or refreshed on rotation can be
awaited there. Resolve it through a local trust store, a cache, or a discovery endpoint fixed by
configuration. Never fetch an arbitrary URL merely because it appeared in an unverified `keyid`. The
original message is compared with the operation snapshot after the factory settles, so a change
while a key is being fetched is rejected rather than verified.

`context.message` is a package-owned immutable snapshot of the target message. `context.request` is
the related-request snapshot when the target is a response. Header and trailer names are lowercase,
their values are frozen occurrence arrays, and every verifier and policy callback for the operation
sees the same snapshot values. Use this context to prevent a valid key from being accepted outside
its authorized tenant, origin, route, or message direction.

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
      const nonce = FetchSig.getSignatureParameter(signature, 'nonce')
      if (typeof nonce !== 'string') {
        throw new Error('A nonce is required')
      }
      await claimNonceOnce(nonce, context.message)
    },
  },
})

declare function claimNonceOnce(nonce: string, message: FetchSig.MessageSnapshot): Promise<void>

console.log(verified.algorithm)
```

`requiredComponents` matches the complete component identifier, including parameters, and ignores
parameter order. Every entry must be covered, so a rule that is not a plain conjunction belongs in
`validate`. [`includesComponent()`](../docs/functions/includesComponent.md) performs the same
identifier match there, against `signature.components`:

```ts
const requireTargetBinding: FetchSig.VerificationPolicy['validate'] = (signature, context) => {
  const covered = signature.components
  if (
    !FetchSig.includesComponent(covered, '@authority') &&
    !FetchSig.includesComponent(covered, '@target-uri')
  ) {
    throw new Error('The signature must cover @authority or @target-uri')
  }
  if (
    context.message.headers['signature-agent'] !== undefined &&
    !FetchSig.includesComponent(covered, 'signature-agent')
  ) {
    throw new Error('An unsigned signature-agent field is not accepted')
  }
}
```

Comparing `component.name` by hand instead would accept `"@authority";req` for a rule that means
`"@authority"`.

The `signature-agent` rule above is the other shape, because it asks whether a field is bound at
all. [`findComponents()`](../docs/functions/findComponents.md) matches a name whatever parameters it
carries, which `includesComponent()` deliberately does not, and returns the identifiers it found.
Read their parameters before concluding the field is protected: a `key` parameter covers one
Dictionary member and leaves that field's other members free to change in transit.

`requiredParameters` checks presence only. `algorithms` must be a non-empty array of non-empty
strings and is checked against the trusted verifier's algorithm, whether or not the signature
carries `alg`. Verification also fails when a signature's `alg` disagrees with the algorithm the
verifier factory selected. All three arrays are required, and either of the first two may be empty.
The policy shape is validated before any message is processed, so `createVerifyingFetch()` and
`createSignedFetch()` reject an invalid policy when they are created.

Timestamp checks work as follows:

- `created` and `expires`, when present, must be integer UNIX timestamps
- `created` cannot be later than `now + clockSkew`
- `expires` cannot be earlier than `now - clockSkew` or earlier than `created`
- `maxAge` is optional. When set it requires `created` and rejects a signature older than
  `maxAge + clockSkew`
- `clockSkew` defaults to `0`

The clock is read again after cryptographic verification and after `policy.validate`, so a signature
that expires while an asynchronous callback is running is still rejected.

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

The wrapper changes automatic redirect following to manual handling because Fetch does not expose
the exact request that produced a response after following a redirect. Use `createSignedFetch()`
rather than nesting directional wrappers when requests must also be signed.

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

`getSignatures()` and `verify()` require the `Signature` and `Signature-Input` fields to pair up
across the whole message: both present or both absent, no repeated label, and identical label sets.
A field that is present but empty counts as absent, because RFC 9651 gives every Dictionary field a
default empty value.

This is stricter than RFC 9421, which only requires the _selected_ signature to have a matching
`Signature-Input` member. The stricter reading treats a message whose signature fields disagree as
malformed rather than partially usable, at the cost that one unusable member makes the other
signatures on that message unverifiable too. Note the consequence at a trust boundary: anything that
can add a field line to the message, including an intermediary, can append an unpaired member such
as `Signature: rogue=:AA==:` and make every legitimate signature on that message fail to verify.
That is a denial of service, not a forgery, but reject or strip unexpected signature members at the
edge if availability under that condition matters.

Invalid configuration and provider contracts throw a `TypeError`. Verification failures throw
`VerificationError`; branch on its stable `code`, never its diagnostic `message`:

| Code                     | Meaning                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------- |
| `signature_missing`      | The message carries no HTTP message signature.                                                       |
| `signature_malformed`    | Its fields, covered components, timestamps, or message context cannot form a valid signature base.   |
| `policy_rejected`        | Required coverage, parameters, or algorithms are absent or disallowed, or custom policy rejected it. |
| `signature_time_invalid` | The signature is not yet valid, has expired, or exceeds `maxAge`.                                    |
| `unknown_key`            | A verifier factory explicitly reported that the claimed key is unknown.                              |
| `algorithm_unsupported`  | A verifier factory explicitly reported that it cannot verify the selected algorithm.                 |
| `signature_mismatch`     | The cryptographic verifier returned `false`.                                                         |
| `verification_failed`    | Key resolution, the verifier provider, or message-stability checking failed operationally.           |

Verifier-provider and `policy.validate` exceptions are wrapped as their stage's code and preserved
as `cause`. A verifier factory can explicitly signal `unknown_key` or `algorithm_unsupported` by
throwing a `VerificationError`; that signal is itself preserved as `cause`. Other factory exceptions
use `verification_failed`, so an unavailable key service is not misreported as an unknown key.

Treat every verification error as authentication failure at a protocol boundary. Codes are useful
for private recovery and diagnostics, but detailed error text generally should not be reflected to
an untrusted peer.
