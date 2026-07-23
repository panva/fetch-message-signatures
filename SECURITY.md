# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it with a
[private GitHub security advisory](https://github.com/panva/fetch-message-signatures/security/advisories/new).

Include the affected version and runtime, a minimal reproduction with real keys and message data
removed, the security property that is bypassed, and the expected impact and attacker capabilities.

Please allow time to investigate and coordinate a fix before public disclosure. If the problem is in
a cryptographic provider, runtime, HTTP stack, or another dependency rather than this package, the
report may need to be coordinated with that project.

## Supported versions

Security fixes are made for the latest published version. Users should update before reporting an
issue or relying on a fix.

| Version        | Supported |
| :------------- | :-------- |
| Latest release | Yes       |
| Older releases | No        |

Until the first stable release, the API and security policy can change between minor versions.

## Security model and scope

`fetch-message-signatures` implements HTTP Message Signatures as defined by RFC 9421 on the Fetch
`Request`, `Response`, `Headers`, and `fetch` interfaces. It parses and serializes the
signature-related Structured Fields, derives covered components, constructs signature bases,
delegates signing, verification, and key selection to application-provided factories, applies
recipient verification policy, and detects observable mutation during asynchronous operations.

The package provides key-pair generators and signer/verifier adapters backed by Web Cryptography for
ECDSA P-256, ECDSA P-384, and Ed25519. It does not provide persistent key management, trust anchors,
key discovery, authorization rules, replay storage, body digest verification, HTTP transport
security, or confidentiality.

Before verification, signature labels, parameters such as `keyid` and `alg`, covered component
identifiers, and all message values are untrusted. Signature labels are unsigned dictionary keys.
The verifier factory must resolve `keyid` through trusted, scoped configuration rather than use it
as a network location. An incoming `alg` value must agree with the configured key and the
recipient's algorithm policy; it cannot choose the algorithm by itself.

A valid cryptographic signature proves integrity only for the listed components under the selected
key. Coverage requirements, key authorization, freshness, replay prevention, body digest validation,
and application authorization remain application policy. In particular, signing `content-digest`
authenticates the field value, not the body. Applications that rely on body integrity must
independently validate the field under RFC 9530, allowlist acceptable digest algorithms, and compare
the digest of the intended received representation.

Fetch exposes a normalized message, not every HTTP wire detail. A deployment must account for
intermediary and runtime transformations and for unavailable values such as original header lines,
trailers, the exact request target, or the HTTP version. See the
[security guidance](guides/security.md) for coverage, replay, Fetch representation, transport, and
deployment controls.

Provider implementations are part of the trusted computing base. They must implement the exact
algorithm and signature encoding named by RFC 9421, keep keys appropriately protected, use a
cryptographic verification primitive, and perform constant-time comparison where required. Provider
exceptions and detailed key-store errors should not be exposed to unauthenticated callers.

## Vulnerability boundaries

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
