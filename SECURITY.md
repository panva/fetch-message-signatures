# Security policy

## Supported versions

Security fixes are made for the latest published version. Users should update to the newest release
before reporting an issue or relying on a fix.

| Version        | Supported |
| :------------- | :-------- |
| Latest release | Yes       |
| Older releases | No        |

Until the first stable release, the API and security policy can change between minor versions.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it with a
[private GitHub security advisory](https://github.com/panva/fetch-message-signatures/security/advisories/new).

Include, when possible:

- the affected `fetch-message-signatures` version and runtime;
- a minimal reproduction with all real keys, secrets, and message data removed;
- the security property that is bypassed;
- expected impact and required attacker capabilities; and
- any suggested mitigation.

Please allow time to investigate and coordinate a fix before public disclosure. If the problem is in
a cryptographic provider, runtime, HTTP stack, or another dependency rather than this package, the
report may need to be coordinated with that project.

## Security model

`fetch-message-signatures` implements HTTP Message Signatures as defined by RFC 9421 on the Fetch
`Request`, `Response`, `Headers`, and `fetch` interfaces. It:

- parses and serializes signature-related Structured Fields;
- derives covered message components and constructs signature bases;
- delegates signing, verification, and key selection to application-provided factories;
- applies explicit recipient verification policy; and
- detects observable mutation while an asynchronous signing or verification operation is pending.

The package provides key-pair generators and signer/verifier adapters backed by Web Cryptography for
ECDSA P-256, ECDSA P-384, and Ed25519. It does not provide persistent key management, trust anchors,
key discovery, authorization rules, replay storage, body digest verification, HTTP transport
security, or confidentiality.

### Trust boundaries

Before cryptographic verification succeeds, signature labels, parameters such as `keyid` and `alg`,
covered component identifiers, and all message fields are attacker-controlled. A verifier factory
must treat `keyid` only as an index into trusted, scoped configuration. It must not fetch an
attacker-selected URL or select an algorithm merely because the message names it.

A valid cryptographic signature proves integrity only for the listed components under the selected
key. It does not by itself prove that:

- the key is authorized for this origin, tenant, route, method, or operation;
- security-relevant components were covered;
- the message is fresh or has not been replayed;
- a request or response body matches a signed digest field; or
- the verified principal is authorized to perform an application action.

Applications must enforce those properties through key configuration, `VerificationPolicy`, and
authorization logic.

### Required coverage and authorization

Recipients must define `policy.requiredComponents` from the values actually used for routing,
authentication, authorization, content interpretation, and replay protection. Common request
coverage includes `@method`, `@authority`, `@path`, relevant query parameters, and security-relevant
fields. Common response coverage includes `@status` and, when appropriate, request components with
the `req` parameter.

Do not accept a signature simply because every component chosen by its sender verifies. Signature
labels are unsigned dictionary keys and must never carry roles or authorization meaning.

### Freshness and replay

For online protocols, require `created`, bound `maxAge`, and allow only necessary `clockSkew`.
Timestamps limit a replay window but do not prevent replay inside it. Replay-sensitive operations
should require a nonce and atomically claim it after cryptographic verification, scoped to the
issuer, key, and application context.

### Message bodies

This package does not read bodies and does not implement RFC 9530 Digest Fields. For a body-bearing
message, applications commonly need to:

1. require signature coverage of `content-digest`;
2. parse and validate the digest field independently;
3. allowlist an acceptable digest algorithm; and
4. compute and compare the digest over the intended received representation.

Authenticating the text of a digest field without checking the body does not authenticate the body.

### Fetch and HTTP representation

Fetch presents a normalized message rather than all HTTP wire details. Intermediaries and runtimes
can combine repeated fields, rewrite URLs, transform content coding, or hide protocol metadata.
Fetch does not generally expose original header lines, trailers, an exact request target, or the
HTTP version. Components that depend on those values require an appropriate transport adapter or
must not be used.

Verify at a layer that sees the representation intended by the sender. Retain the exact related
request when verifying response signatures that cover request components. Redirected requests must
be authorized and re-signed; stale signature fields must not be forwarded to a new target.

### Cryptographic providers

Provider implementations are part of the trusted computing base. They must implement the exact
algorithm and signature encoding named by RFC 9421, keep keys appropriately protected, use a
cryptographic verification primitive, and perform constant-time comparison where required. Provider
exceptions and detailed key-store errors should not be exposed to unauthenticated callers.

### Transport and resource limits

HTTP message signatures provide integrity and authentication for covered values, not
confidentiality. Use TLS and normal HTTP platform defenses.

Bound total header size, signature count, covered component count, parameter count, key lookup work,
and replay-state growth before accepting untrusted traffic. Avoid unbounded network work during key
selection.

For deployment guidance and a concrete checklist, see [Security guidance](guides/security.md).

## What is generally not a vulnerability

The following are normally application or protocol-design responsibilities unless
`fetch-message-signatures` documents or enforces a property incorrectly:

- failure to require a security-relevant component;
- accepting a trusted key outside its intended application scope;
- replay within a policy that has no nonce or replay store;
- failure to independently validate a body digest;
- disclosure of unsigned or unencrypted message content;
- a Fetch or intermediary normalization that the deployment did not account for; or
- weakness in a custom cryptographic provider.

Reports showing that the implementation accepts a signature base or Structured Field contrary to an
applicable specification, bypasses configured verification policy, or misattributes a verified
message are in scope.
