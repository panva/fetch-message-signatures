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
delegates signing, verification, and key selection to application-provided factories, and applies
recipient verification policy.

While an application-provided signer, verifier, field adapter, or policy callback is suspended, the
message can change underneath it. The package rebuilds the signature base around each of those calls
and rejects the operation if it no longer matches, so a signature is never produced over, or
accepted for, a message state that was never observed as a whole. This covers everything a signature
base is derived from, including the related request. It does not cover message bodies, which the
package never reads.

The package provides key-pair generators and signer/verifier adapters backed by Web Cryptography for
ECDSA P-256, ECDSA P-384, Ed25519, and RSA. It does not provide persistent key management, trust
anchors, key discovery, authorization rules, replay storage, body digest verification, HTTP
transport security, or confidentiality.

Before verification, signature labels, parameters such as `keyid` and `alg`, covered component
identifiers, and all message values are untrusted. Signature labels are unsigned dictionary keys.
The verifier factory must resolve `keyid` through trusted, scoped configuration rather than use it
as a network location. An incoming `alg` value must agree with the configured key and the
recipient's algorithm policy. It cannot choose the algorithm by itself.

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

- failure to require a security-relevant component
- accepting a trusted key outside its intended application scope
- replay within a policy that has no nonce or replay store
- failure to independently validate a body digest
- disclosure of unsigned or unencrypted message content
- a Fetch or intermediary normalization that the deployment did not account for
- weakness in a custom cryptographic provider

Two classes of report are outside the package's control entirely.

Modification of the JavaScript intrinsics by code sharing the realm, including prototype pollution
of `Object.prototype`, is out of scope. The package assumes that `Object`, `Array`, `Map`, `URL`,
`TextEncoder`, and the Fetch interfaces behave as specified. An attacker who can change them can
already alter any computation in the process, so no defense inside a single module is meaningful.
Reports of this kind are only in scope where the package itself introduces the pollution.

Absolute resource limits are a deployment responsibility. The package does not bound the size or
number of fields, signatures, covered components, or metadata parameters it will process. Those
belong at the HTTP server or gateway, as described in the
[security guidance](guides/security.md#transport-resources-and-failures). What the package does own
is algorithmic complexity: parsing, canonicalization, and signature base generation are intended to
stay linear in the size of the message, because a peer controls that size and reaches this code
before any signature has been checked.

Reports showing any of the following are in scope:

- the implementation accepts a signature base or Structured Field contrary to an applicable
  specification, or produces one that a conforming implementation would reject
- configured verification policy is bypassed, or a verified signature is misattributed to the wrong
  message, key, algorithm, or label
- a value derived from an unauthenticated message escapes as authenticated, or authenticated state
  can be mutated by an application callback after it has been checked
- work grows superlinearly with the size of an attacker-supplied message
