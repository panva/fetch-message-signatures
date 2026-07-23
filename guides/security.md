# Security guidance

HTTP Message Signatures authenticate selected message components. They do not automatically
authenticate the whole request or response and do not define what a verified signature authorizes.

## Make authorization drive coverage

For every operation, identify the properties used by routing, authentication, authorization, content
interpretation, and replay handling. Require all of them in `policy.requiredComponents`.

Common request coverage includes:

- `@method`;
- `@authority`;
- `@path` and relevant `@query-param` components;
- fields used for tenant, account, content negotiation, idempotency, or authorization; and
- `content-digest` for a request body.

Common response coverage includes:

- `@status`;
- fields used to interpret or cache the response;
- `content-digest` for a response body; and
- request components with `req` to bind the response to the request.

Avoid accepting a signature merely because it covers whatever the sender happened to list. A valid
signature with insufficient coverage can still be replayed or transplanted into a different
operation.

## Treat metadata as untrusted until verification

Before verification, these are attacker-controlled:

- signature labels;
- `keyid`, `alg`, `tag`, and `nonce`;
- covered component identifiers; and
- every message field and derived value.

Use `keyid` only as an index into a trusted, scoped key configuration. Never give signature labels
roles such as `administrator`: the label is not in the signature base.

If `alg` is present, it is a claim that must agree with trusted key configuration and the
recipient's algorithm allowlist. Do not let it choose an unsafe algorithm or reinterpret a key.

## Bind keys to message context

A cryptographically valid key may still be wrong for a particular message. The verifier factory
receives the target message and related request context so it can enforce boundaries such as:

- issuer or tenant;
- request versus response use;
- origin, authority, route, or HTTP method;
- key usage and lifecycle state; and
- expected application protocol.

Repeat authorization checks using authenticated metadata in `policy.validate` when the decision
depends on signature parameters.

## Enforce freshness and replay policy

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

## Validate body integrity separately

This package does not read bodies or implement
[HTTP Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html). A secure body-bearing protocol
typically:

1. computes `Content-Digest` over the specified body representation;
2. includes `content-digest` in required signature coverage;
3. verifies the message signature; and
4. independently parses and validates `Content-Digest` according to RFC 9530;
5. selects a digest only from a local allowlist of acceptable algorithms; and
6. computes that digest over the received content and compares it with the authenticated value.

Signing the field does not make an unknown, deprecated, or locally disallowed digest algorithm
acceptable. A receiver that relies on a digest for security is only as strong as the weakest
algorithm it accepts. Skipping the independent RFC 9530 validation authenticates only a digest
string, not the body. Define whether transformations such as content coding, decompression, JSON
normalization, or framework parsing occur before or after digest calculation.

## Preserve the signed representation

Intermediaries can normalize URLs, combine fields, alter content coding, add or remove whitespace,
or rewrite requests. Verify at a layer that sees the representation the sender intended to sign, or
define and test the transformations between those layers.

For responses that cover request components, retain the exact request that was sent. Do not bind a
response to a newly reconstructed approximation.

Signing and verification reject observable message changes while asynchronous providers or policy
callbacks are running. After `verify()` returns, continue processing the same stable message state:
do not mutate covered headers or hand the message to code that can change them before the
authenticated values are consumed.

## Use TLS

Signatures provide integrity and authentication of covered components, not confidentiality. TLS
protects keys and sensitive metadata from observation, constrains active traffic manipulation, and
authenticates the transport endpoint. HTTP message signatures complement TLS; they are not a
replacement for it.

## Bound resource use

Reject oversized signature fields and excessive header counts at the HTTP server or gateway before
application parsing. Bound:

- total header bytes;
- number of signatures and `Accept-Signature` requests;
- number of covered components and parameters;
- key lookup work; and
- replay-state storage.

Do not fetch arbitrary network resources during the synchronous verifier-selection path.

## Handle failures uniformly

At a trust boundary, parse errors, missing policy requirements, unknown keys, algorithm rejection,
expired signatures, and invalid cryptographic signatures are all authentication failures.

Avoid returning detailed verifier or key-store errors to an attacker. Log enough private context to
diagnose failures, but consider that signature metadata and covered field values can contain
sensitive information.

## Deployment checklist

- Required components match the exact operation being authorized.
- Body-bearing messages require `content-digest`, independently validate it under RFC 9530, and use
  a local digest-algorithm allowlist.
- Algorithms are explicitly allowlisted.
- Key lookup is scoped and does not trust `keyid` as a network location.
- Key use is authorized for the target request or response.
- `created`, age, skew, and expiration policy are bounded.
- Replay-sensitive operations atomically claim a nonce.
- Response signatures cover `@status` and appropriate request components with `req`.
- Negotiated signed responses are uncacheable or send `Vary: Accept-Signature`.
- Redirects are handled manually and every redirected request is re-signed.
- Reverse proxy, URL, repeated-field, trailer, and body transformations are tested end to end.
- TLS and ordinary HTTP platform defenses remain enabled.
