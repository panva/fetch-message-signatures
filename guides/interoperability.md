# Interoperability

HTTP Message Signature interoperability is mostly about reproducing the exact signature base.
Cryptography should be tested only after both implementations agree on the bytes being signed.

## Start with published fixtures

Useful first candidates are:

1. the worked examples in [RFC 9421 Appendix B][rfc-appendix], which publish messages, signature
   inputs, bases, and signatures;
2. the [HTTP Working Group Structured Field test corpus][sf-tests], for the canonicalization layer;
   and
3. an independent RFC 9421 implementation that exposes its signature base or supports deterministic
   keys and timestamps.

The RFC fixtures are particularly useful because they distinguish component derivation and
Structured Field serialization failures from provider failures.

## Candidate matrix

These are candidates for future cross-implementation tests, not implementations against which this
package has already been certified.

| Candidate                                              | Runtime          | Useful interop surface                                                                       | First proposed exercise                                               |
| ------------------------------------------------------ | ---------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| [`pyauth/http-message-signatures`][pyauth]             | Python           | RFC 9421 request signing and verification with explicit key resolvers                        | Exchange deterministic HMAC request fields in both directions         |
| [`lestrrat-go/htmsig`][htmsig]                         | Go               | Request/response signing and verification plus `httptest` client/server examples             | Run the local live-HTTP scenario with a Go endpoint                   |
| [`yaronf/httpsign`][httpsign]                          | Go               | Client/server integration and a project suite covering the RFC vectors                       | Compare every common Appendix B base and supported algorithm          |
| [`@misskey-dev/node-http-message-signatures`][misskey] | JavaScript       | Web Cryptography, browser/Node targets, request signing and verification, and digest helpers | Cross-verify Ed25519 Fetch requests without adapting across languages |
| [Cloudflare's research endpoint][cloudflare]           | Live HTTP        | Profile-specific Ed25519 verifier using the RFC Appendix B.1.4 public key                    | Run an opt-in black-box smoke test against a real network stack       |
| [RFC Appendix B][rfc-appendix]                         | Language-neutral | Published messages, signature bases, keys, and signatures                                    | Keep as the mandatory baseline and regression oracle                  |

Capabilities and defaults differ. Before adding a test, pin the peer version, read its current
algorithm and component support, and record any message-model adapter needed. In particular, do not
claim an `Accept-Signature` interop result unless both sides implement that operation.

## What is tested today

The repository currently runs these interoperability-oriented tests:

| Layer                        | Current automated coverage                                                                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| RFC 9421 Appendix B.2        | Exact bases for every B.2 example; published RSA-PSS, ECDSA P-256, HMAC-SHA256, and Ed25519 signatures are verified, and deterministic sender output is checked where possible |
| RFC 9421 Appendices B.3–B.4  | TLS-terminating proxy context, allowed transformations of uncovered values, and rejection after covered-value or repeated-field changes                                        |
| Built-in crypto providers    | Generated-key round trips for both ECDSA algorithms and Ed25519; ECDSA P-384 is cross-verified in both directions with Node's independent crypto API                           |
| Local HTTP transport         | A real ephemeral loopback server verifies a signed request, checks its body digest, fulfills `Accept-Signature`, signs a request-bound response, and has the client verify it  |
| Negative end-to-end behavior | Covered request and response mutations, body substitution, corrupted signature bytes, wrong related-request binding, and a missing response signature                          |

The body-digest check in the local transport test demonstrates that content verification is
independent from signature verification; it is not a general RFC 9530 implementation.

The published RSA-PSS and HMAC-SHA256 vectors are verified with test-only providers. They validate
RFC interoperability without exposing RSA or HMAC implementations from the package.

No row in the candidate matrix has yet been exercised as a pinned, automated peer-to-peer test, and
the Cloudflare endpoint is not contacted by the default test suite. The next interop increment is to
add one version-pinned peer adapter, compare signature-base bytes first, then verify sender output
in both directions. Candidate-specific setup belongs outside the zero-dependency runtime module.

## Test in layers

### Signature-base fixtures

Fix all nondeterminism:

- use a literal URL, method, status, and field set;
- set `now` or an explicit `created`;
- specify ordered component and parameter tuples; and
- capture the exact related request for a response.

Compare the UTF-8 bytes of `createSignatureBase()` with the peer implementation before invoking
cryptography.

```ts
const request = new Request('https://example.com/items?limit=10', {
  method: 'POST',
  headers: { 'example-field': 'value' },
})

const base = FetchSig.createSignatureBase(request, {
  components: [
    '@method',
    '@authority',
    '@path',
    FetchSig.component('@query-param', [['name', 'limit']]),
    'example-field',
  ],
  parameters: [
    ['created', 1_735_689_600],
    ['keyid', 'interop-key'],
  ],
})
```

When bases differ, compare each serialized component line and the final `@signature-params` line. Do
not normalize whitespace or reorder parameters in the captured value.

### Sender-to-recipient fixtures

Have implementation A emit literal `Signature-Input` and `Signature` field values, then have
implementation B verify them against the same target message and key. Reverse the direction.

Include:

- every supported algorithm used by the deployment;
- signatures with and without `alg`;
- multiple labels;
- a response bound to its request with `req`;
- Structured Field `sf` and `key` components;
- repeated fields through `bs`;
- non-ASCII and percent-encoded URL cases; and
- malformed cases that both implementations must reject.

### Live HTTP tests

An in-memory Fetch object cannot reveal transformations performed by a network stack. Run sender and
recipient implementations across an ephemeral local server and assert:

- the field values observed at the server;
- the signature base reconstructed at each endpoint;
- request-body digest verification;
- a signed response bound to the received request;
- repeated-header behavior in the chosen HTTP version;
- manual redirect and re-sign behavior; and
- failure after a covered method, URL, status, or field is changed.

Keep transport observations separate from RFC expectations. A Fetch implementation may combine field
lines or normalize the URL before `fetch-message-signatures` sees it.

## Suggested fixture format

A shared JSON fixture can carry:

```json
{
  "name": "request with query parameter",
  "target": {
    "kind": "request",
    "url": "https://example.com/items?limit=10",
    "method": "POST",
    "headers": [["example-field", "value"]]
  },
  "components": [
    "@method",
    "@authority",
    "@path",
    { "name": "@query-param", "parameters": [["name", "limit"]] }
  ],
  "parameters": [
    ["created", 1735689600],
    ["keyid", "interop-key"]
  ],
  "signatureBase": "\"@method\": POST\n\"@authority\": example.com\n…",
  "signatureInput": "sig1=(…);created=1735689600;keyid=\"interop-key\"",
  "signature": "sig1=:base64:"
}
```

Store header fields as ordered pairs rather than a JSON object when occurrence order matters. Store
the signature base as text and compare its encoded bytes as well.

## Diagnose common mismatches

| Symptom                                         | Likely area                                                    |
| ----------------------------------------------- | -------------------------------------------------------------- |
| Same component values, different final line     | Component or signature parameter order/type                    |
| Difference only in a field value                | Field combination, whitespace, `sf`, `key`, `bs`, or `tr`      |
| Difference only in a URL component              | Percent encoding, explicit port, empty query, or proxy rewrite |
| Bases match but signatures differ               | Key, algorithm parameters, hashing, or signature encoding      |
| Request verifies in memory but not on server    | Fetch or intermediary transformation                           |
| Response verifies without `req` but not with it | Related request is not the exact sent request                  |

Log bases only in controlled test environments: they can contain authenticated secrets or personal
data from covered fields.

[rfc-appendix]: https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B
[sf-tests]: https://github.com/httpwg/structured-field-tests
[pyauth]: https://github.com/pyauth/http-message-signatures
[htmsig]: https://github.com/lestrrat-go/htmsig
[httpsign]: https://github.com/yaronf/httpsign
[misskey]: https://github.com/misskey-dev/node-http-message-signatures
[cloudflare]: https://http-message-signatures-example.research.cloudflare.com/
