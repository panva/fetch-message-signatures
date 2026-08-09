# Security guidance

HTTP Message Signatures authenticate selected message components. They do not automatically
authenticate the whole request or response and do not define what a verified signature authorizes.

## Coverage follows authorization

Set `policy.requiredComponents` from the values the application actually uses for routing,
authentication, authorization, content interpretation, and replay handling. A request will commonly
need `@method`, `@authority`, `@path`, relevant query parameters, and fields that select a tenant,
account, representation, or idempotency context. A response will commonly need `@status` and may
need request components with `req` to bind it to the request. A signature that covers only the
sender's chosen components can be valid yet insufficient for the operation.

## Metadata and key selection

Until verification succeeds, signature labels, `keyid`, `alg`, `tag`, `nonce`, covered component
identifiers, and message values are attacker-controlled. A label cannot carry a role because it is
an unsigned dictionary key. Resolve `keyid` only against trusted, scoped configuration. If `alg` is
present, require it to agree with the configured key and a local algorithm allowlist.

A cryptographically valid key can still be invalid for a message. Bind keys to the issuer or tenant,
request or response use, origin, authority, route, method, application protocol, and key lifecycle
as appropriate. The verifier factory receives the message and related request for this purpose.
`policy.validate` can apply authorization that depends on authenticated signature parameters.

## Freshness and replay

Require `created` and set a bounded `maxAge` for online protocols. Add only as much `clockSkew` as
deployment clocks require. When a sender supplies `expires`, verification rejects an already expired
signature, but the recipient should still bound age rather than accepting an arbitrarily long
lifetime.

Timestamps alone do not prevent replay within their validity window. For non-idempotent or valuable
operations, require a nonce and atomically claim it after cryptographic verification. Scope the
nonce record to the issuer/key and protocol context, give it an expiry, and ensure concurrent
requests cannot both claim it.

`policy.validate` runs after cryptographic verification and supports asynchronous, stateful replay
checks.

## Body integrity

This package does not read bodies or implement
[HTTP Digest Fields](https://www.rfc-editor.org/info/rfc9530/). A body-bearing protocol must require
`content-digest` in signature coverage, but covering that component only signs the field value.
Independently parse and validate `Content-Digest` under RFC 9530, select the digest algorithm from a
local allowlist, compute it over the intended received representation, and compare the result with
the authenticated value. Define where content coding, decompression, JSON normalization, and
framework parsing occur relative to digest calculation.

## Fetch representation

Intermediaries can normalize URLs, combine fields, alter content coding, add or remove whitespace,
or rewrite requests. A signature only survives such a hop if the value the verifier derives is
identical to the one the signer derived, so verification has to run at a layer that still sees the
representation the sender signed. Fetch also omits some wire details, including original header
lines, trailers, the exact request target, and the HTTP version. Do not cover components whose
source value is unavailable at the layer doing the verifying.

Retain the exact request that was sent when a response signature covers request components. Handle
redirects manually, authorize each target, and re-sign each redirected request instead of forwarding
stale signature fields.

Signing and verification capture the target message and related request in a package-owned,
immutable snapshot. Verifier and policy callbacks receive that snapshot, including frozen header and
trailer occurrence arrays, rather than the caller's mutable message object. The package compares the
source with the snapshot after application callbacks run and rejects observable changes. After
`verify()` returns, continue processing the same stable message state: do not mutate covered fields
or hand the source to code that can change them before the authenticated values are consumed.

## Transport, resources, and failures

Signatures provide integrity and authentication of covered components, not confidentiality. TLS
protects keys and sensitive metadata from observation, constrains active traffic manipulation, and
authenticates the transport endpoint. HTTP message signatures complement TLS. They are not a
replacement for it.

Reject oversized signature fields and excessive header counts at the HTTP server or gateway before
application parsing. Bound header bytes, signature and `Accept-Signature` counts, covered
components, parameters, key lookup work, and replay-state storage. Key selection must not start
unbounded or attacker-directed network work.

At a trust boundary, parse errors, missing policy requirements, unknown keys, algorithm rejection,
expired signatures, and invalid cryptographic signatures are all authentication failures. Return a
uniform external failure instead of verifier or key-store details. Log enough private context to
diagnose failures, but consider that signature metadata and covered field values can contain
sensitive information.
