# Fetch behavior and limitations

RFC 9421 models protocol-layer HTTP messages. Fetch exposes normalized URLs and fields while hiding
some wire details.

## Message immutability and bodies

The append helpers return new objects so they can work with Fetch messages whose headers have an
immutable guard:

- appending to `Headers` copies the headers;
- appending to a `Request` constructs a new request with updated headers; and
- appending to a `Response` constructs a new response with updated headers.

The Request and Response helpers pass the source body stream to a new Fetch message without calling
`clone()` or buffering it in the package. The Fetch implementation decides whether this disturbs,
transfers, or leaves the source body readable. Node.js, Deno, and Bun do not expose the source
body's state identically. Do not rely on that state after constructing the signed message; consume
the returned message instead.

When both copies must remain independently readable, choose an application-specific strategy:

1. clone or buffer the body under an explicit size limit;
2. use `createSignature()` to obtain only the fields;
3. construct the final message with the chosen body; and
4. place the returned field values in its headers.

The pure creation functions do not inspect, consume, or hash a body.

Signing and verification snapshot observable headers and reconstruct the signature base around
asynchronous provider calls. They reject if the target message, related request, raw field adapter,
or trailer context changes during the operation. Keep those inputs stable until the Promise settles;
a `fieldValues` adapter must return a deterministic view of the same message.

## Response metadata

Fetch has no general operation that clones a network `Response` while replacing immutable headers. A
reconstructed signed response preserves its status, status text, headers, and body. It cannot
preserve Fetch-managed `url`, `redirected`, or `type` metadata. Opaque and error responses have
status zero and cannot be reconstructed by the append helpers.

If this metadata matters, create signature fields separately and add them in the server or framework
layer that constructs the original response.

## Redirects

A redirect can change the method, URL, authority, path, body, and fields after a request was signed.
Forwarding stale signature fields can also disclose them to another origin.

`createSigningFetch()`, `createVerifyingFetch()`, and `createSignedFetch()` change
`redirect: 'follow'` to `redirect: 'manual'`. Signing wrappers cannot re-sign a redirected request,
and verification wrappers cannot observe the exact request that produced a response after Fetch
follows a redirect. To follow safely:

1. inspect and authorize the redirect target;
2. construct the next request according to Fetch redirect semantics;
3. remove old `signature-input` and `signature` fields;
4. select coverage for the new message; and
5. sign the new request.

There is no generic way for a Fetch wrapper to do all of this without application redirect policy.

## Repeated field lines

`Headers` normally combines repeated field lines. RFC 9421's `bs` parameter signs each occurrence
separately, so `bs` requires a `fieldValues` adapter with the original occurrence list.

The exception is `set-cookie` in runtimes that expose `Headers.getSetCookie()`. In those runtimes
the implementation can retrieve the occurrences directly.

Header combination performed by a browser, reverse proxy, HTTP library, or server can affect the
value used in a signature base. Interoperability tests should exercise the complete path, not only
in-memory objects.

## Trailers

Fetch does not generally expose HTTP trailers. A component with `tr` requires a `fieldValues`
adapter supplied by a transport integration.

Standard Fetch also cannot discover trailer-carried `Signature-Input` and `Signature` fields. The
adapter covers component value derivation, not transport of the signature fields themselves.

The adapter must expose header and trailer occurrences separately. If the same field name occurs in
both sections, branch on `context.trailers` and never return a combined list: RFC 9421 requires the
two values to be signed separately. Trailer coverage is not recommended unless both endpoints and
every relevant intermediary preserve access to the trailer values as sent.

## Structured Fields

Fetch returns field values as strings without a schema. For the `sf` parameter, configure the
top-level Structured Field type:

```ts
declare const request: Request

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('priority', [['sf', true]])],
  structuredFields: { priority: 'dictionary' },
})
```

`signature`, `signature-input`, and `accept-signature` are known Dictionaries. For application
fields, configure the top-level type as `'dictionary'`, `'list'`, or `'item'`.

## URL-derived components

Derived request components come from `Request.url`. `@authority` lowercases the host, omits the
scheme's default port even if it was explicit in the input URL, and retains a non-default port.

In particular, `@request-target` is an origin-form path and query derived from the URL. RFC 9421
marks this component **NOT RECOMMENDED** when HTTP versions other than HTTP/1.1 might be in use.
Since Fetch does not expose the HTTP version or original request-target form, use this component
only when an HTTP/1.1-specific integration guarantees that the derived origin-form value is the
protocol-layer request target.

Fetch does not expose:

- the exact request-target octets received on the wire;
- all HTTP request-target forms;
- the HTTP version;
- proxy rewrites that happened before the Fetch object was created; or
- later rewrites that happen after Fetch sends it.

Place signing and verification on the correct side of URL normalization and reverse-proxy rewriting,
and test non-ASCII paths, percent encoding, explicit ports, and query delimiters.

## Browser security boundaries

Browser CORS processing can prevent script from sending or observing fields. Signature-related
request fields may trigger a preflight, and response fields require `Access-Control-Expose-Headers`.
Service workers, extensions, and browser-managed fields can alter the message outside the
application's control. Page JavaScript cannot verify an opaque response because its status and
headers are hidden.

## Fetch wrapper behavior

The package exposes independent wrappers for each direction:

- `createSigningFetch()` signs each outgoing request;
- `createVerifyingFetch()` verifies each response against the exact request it sent without adding a
  signature; and
- `createSignedFetch()` signs each request and can verify the response against that exact signed
  request.

Use the directional factory when only one operation is required so a bundler can omit the opposite
pipeline. Use `createSignedFetch()` when both operations are required; nesting the directional Fetch
wrappers can bind verification to a different request object or reconstruct a streaming request an
extra time.

All three accept the normal Fetch input and init arguments, construct a request from them, and force
manual redirects when needed. A signing wrapper then replaces that request with the newly signed
request. Their signing and verification configuration is copied when the wrapper is created. Keep
changing key material behind the provider factories or create a new wrapper when policy changes.

After successful verification, the wrapper returns the response unchanged. It does not consume the
response body and does not validate a body digest.
