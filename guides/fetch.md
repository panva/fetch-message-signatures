# Fetch behavior and limitations

RFC 9421 models protocol-layer HTTP messages. Fetch exposes normalized URLs and fields while hiding
some wire details.

## Message immutability and bodies

The append helpers return new objects so they can work with Fetch messages whose headers have an
immutable guard:

- appending to `Headers` copies the headers
- appending to a `Request` constructs a new request with updated headers
- appending to a `Response` constructs a new response with updated headers

The Request and Response helpers pass the source body stream to a new Fetch message without calling
`clone()` or buffering it in the package. The Fetch implementation decides whether this disturbs,
transfers, or leaves the source body readable. Node.js, Deno, and Bun do not expose the source
body's state identically. Do not rely on that state after constructing the signed message. Consume
the returned message instead.

When both copies must remain independently readable, choose an application-specific strategy:

1. clone or buffer the body under an explicit size limit
2. use `createSignature()` to obtain only the fields
3. construct the final message with the chosen body
4. place the returned field values in its headers

The pure creation functions do not inspect, consume, or hash a body.

Signing and verification snapshot observable headers and reconstruct the signature base around
asynchronous provider calls. They reject if the target message, related request, raw field adapter,
or trailer context changes during the operation. Keep those inputs stable until the Promise settles.
A `fieldValues` adapter must return a deterministic view of the same message.

## Response metadata

Fetch has no general operation that clones a network `Response` while replacing immutable headers. A
reconstructed signed response preserves its status, status text, headers, and body. It cannot
preserve Fetch-managed `url`, `redirected`, or `type` metadata, nor runtime-specific metadata such
as Cloudflare Workers' `cf` and `webSocket` properties.

The `Response` constructor only accepts statuses in the 200-599 range, so the append helpers reject
any other status with an explanatory error. Opaque and error responses have status zero, and
informational responses are below 200. `@status` itself accepts the full 100-599 range, so an
informational response can be signed with `createSignature()` even though `appendSignature()` cannot
rebuild it.

Statuses 204, 205, and 304 are Fetch's null body statuses, and its constructor rejects a body for
them. Whether a network response with such a status exposes a body at all is runtime-dependent:
Node.js and Deno report `body` as `null`, while browsers and Bun expose a stream. The append helpers
therefore drop the body for those three statuses rather than passing it on, so the same call
succeeds on every runtime and produces the empty body the status requires.

If this metadata matters, create signature fields separately and add them in the server or framework
layer that constructs the original response.

## Redirects

A redirect can change the method, URL, authority, path, body, and fields after a request was signed.
Forwarding stale signature fields can also disclose them to another origin.

`createSigningFetch()`, `createVerifyingFetch()`, and `createSignedFetch()` change
`redirect: 'follow'` to `redirect: 'manual'`. An explicitly configured `redirect: 'manual'` or
`redirect: 'error'` is left as the caller set it. Signing wrappers cannot re-sign a redirected
request, and verification wrappers cannot observe the exact request that produced a response after
Fetch follows a redirect. To follow safely:

1. inspect and authorize the redirect target
2. construct the next request according to Fetch redirect semantics
3. remove old `signature-input` and `signature` fields
4. select coverage for the new message
5. sign the new request

There is no generic way for a Fetch wrapper to do all of this without application redirect policy.

## Repeated field lines

`Headers` normally combines repeated field lines. RFC 9421's `bs` parameter signs each occurrence
separately, so `bs` requires a `fieldValues` adapter with the original occurrence list.

The exception is `set-cookie` in runtimes that expose `Headers.getSetCookie()`. In those runtimes
the implementation can retrieve the occurrences directly. That covers Node.js, Deno, Bun, and
Cloudflare Workers, but not browsers: a browser strips `set-cookie` from requests and hides it on
responses, so the field reads as absent there and `set-cookie` coverage needs a `fieldValues`
adapter or a signing point outside the browser.

An intermediary is allowed to recombine repeated field lines with any amount of whitespace around
the commas. That changes the combined value, and therefore the signature base, without changing what
the field means. RFC 9421 §2.1 gives two ways out: cover only fields that appear once in the
message, or cover a List or Dictionary field with `sf`, so both endpoints sign its canonical
serialization rather than the whitespace they happened to receive.

Cloudflare Workers deviates from Fetch here, in a way that affects any field carrying a non-ASCII
octet. Fetch models a field value as a byte sequence and exposes it through the WebIDL `ByteString`
type, so each received byte must surface as one code unit in `U+0000`-`U+00FF`. Cloudflare Workers
instead UTF-8 decodes received values: the bytes `c3 a9` arrive as the single code unit `U+00E9`
rather than as `U+00C3 U+00A9`, and a byte that is not valid UTF-8 is replaced with `U+FFFD`,
destroying it. Node.js, Deno, Bun, and browsers all behave as the specification requires. This is
tracked as [workerd#6927](https://github.com/cloudflare/workerd/issues/6927).

Because the received octets cannot be recovered from the decoded string, supply `fieldValues` with
the raw octets when a non-ASCII field value has to be signed on Cloudflare Workers. ASCII field
values, which is what RFC 9110 recommends and what nearly all fields use, are unaffected.

Cloudflare Workers also accepts a field value containing code units above `U+00FF`, storing `'☃'` as
`U+2603` where the `ByteString` conversion is required to throw a `TypeError`
([workerd#4792](https://github.com/cloudflare/workerd/issues/4792)). Such a value has no byte
sequence for the signature base to canonicalize, so treat a field value as writable only when every
code unit is at most `U+00FF`, as the other runtimes enforce for you.

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

A target URI with no authority, such as a `data:` or `blob:` URL, has neither the authority that
`@authority` names nor the absolute path that `@path` and `@request-target` name. Those three
components fail rather than deriving an empty authority or a relative path. Every URI scheme RFC
9421 applies to has an authority, so this only affects messages that were never HTTP requests.

A target URI carrying credentials is rejected. RFC 9110 forbids the userinfo subcomponent in an
`http` or `https` URI. Node.js and browsers refuse to construct such a `Request` at all, while Deno,
Bun, and Cloudflare Workers accept it and would otherwise place the password in the signature base
and in anything that logs or exchanges it.

`@method` is taken from `Request.method` verbatim, because RFC 9421 treats the method as
case-sensitive and performs no case transformation. The `Request` constructor is not neutral here:
Node.js, Deno, and browsers preserve a lowercase method such as `patch`, while Bun and Cloudflare
Workers normalize it to `PATCH`, and Bun replaces an unrecognized method with `GET`. The method has
already been changed by the time this package sees it, so use the canonical uppercase spelling when
a signature has to reproduce across runtimes.

Fetch does not expose:

- the exact request-target octets received on the wire
- all HTTP request-target forms
- the HTTP version
- proxy rewrites that happened before the Fetch object was created
- later rewrites that happen after Fetch sends it

Every derived value above comes from `Request.url` as the Fetch implementation normalized it, not
from the octets on the wire. A reverse proxy that rewrites the target between signer and verifier
therefore gives the two sides different values for the same message, and neither side can tell from
its Fetch object that this happened. Signing and verifying on the same side of such a rewrite is a
deployment property that this package cannot detect.

## Browser security boundaries

Browser CORS processing can prevent script from sending or observing fields. Signature-related
request fields may trigger a preflight, and response fields require `Access-Control-Expose-Headers`.
Service workers, extensions, and browser-managed fields can alter the message outside the
application's control. Page JavaScript cannot verify an opaque response because its status and
headers are hidden.

A `no-cors` request cannot carry any of these fields. Fetch gives such a request's headers the
`request-no-cors` guard, and `Signature`, `Signature-Input`, and `Accept-Signature` are not
CORS-safelisted, so a browser drops them without an error. `sign()`, `appendSignature()`,
`appendAcceptSignature()`, and the signing wrappers therefore reject a request whose mode is
`no-cors`, rather than resolving normally and handing back a message that is not actually signed.
`createVerifyingFetch()` adds no signature fields and has no mode check, so it does not reject one
solely because the mode is `no-cors`. A cross-origin one still cannot be dispatched from a browser:
the wrapper changes `follow` to `manual`, and Fetch returns a network error for a cross-origin
`no-cors` request whose redirect mode is not `follow`. Left on `follow`, that request would have
produced an opaque response with no visible status, headers, or body, which cannot be verified
either. A same-origin `no-cors` request reaches none of that. Node.js, Deno, and Bun do not apply
the guard, and Cloudflare Workers does not expose `Request.mode` at all, so the rejection is only
reachable where the mode can be observed.

Manual redirects behave differently in a browser. For a non-navigation request, a browser answers
`redirect: 'manual'` with an opaque-redirect response: type `opaqueredirect`, status zero, no
headers, and no body. Page JavaScript therefore cannot read `Location`, cannot verify the response,
and cannot perform the manual redirect procedure above. Node.js, Bun, and Cloudflare Workers instead
return the real 3xx response with its fields. Applications that run in a browser and expect
redirects should handle them before the wrapper, or use a target that does not redirect.

## Fetch wrapper behavior

The package exposes independent wrappers for each direction:

- `createSigningFetch()` signs each outgoing request
- `createVerifyingFetch()` verifies each response against the exact request it sent without adding a
  signature
- `createSignedFetch()` signs each request and can verify the response against that exact signed
  request

Use the directional factory when only one operation is required so a bundler can omit the opposite
pipeline. Use `createSignedFetch()` when both operations are required. Nesting the directional Fetch
wrappers can bind verification to a different request object or reconstruct a streaming request an
extra time.

All three accept the normal Fetch input and init arguments, construct a request from them, and force
manual redirects when needed. A signing wrapper then replaces that request with the newly signed
request.

Reconstructing a request resets some of it. The Fetch constructor sets the referrer to `client` and
the referrer policy to the empty string whenever the initializer is not empty, so every
reconstruction in this package restores both from the source request, so a caller that suppressed
the `Referer` field keeps it suppressed. Initializer members that select a transport rather than a
message, such as `dispatcher` on Node.js, `client` on Deno, `cf` on Cloudflare Workers, and `proxy`,
`tls`, and `unix` on Bun, are forwarded to the underlying implementation rather than dropped, so a
required proxy or client certificate is not silently bypassed. Whether a given option would have
survived the reconstruction on its own varies by runtime, so it is forwarded either way. A data
property is captured when the wrapper is called, matching what `fetch()` itself reads, so reusing
and reassigning one initializer cannot change the transport of a request already in flight. Wrapper
initializers must be object literals or null-prototype objects with own enumerable data properties.
Inherited, non-enumerable, accessor, callable, class-based, and Proxy initializers are unsupported;
the wrappers reject every shape they can identify before signing. Other standard members are not
forwarded, because the signed request already carries them and forwarding `headers` would replace
the signature fields.

A signing wrapper also observes the request's `AbortSignal` while signing is still pending, so a
slow or stalled signer does not leave `fetch()` hanging with no way to give up. When the abort wins,
the transport is never reached. When a verifying wrapper rejects, it cancels the response body on a
best-effort basis before rethrowing, because the caller never receives the response and would
otherwise have no way to release the stream. `verify()` called directly does not do this: its caller
still owns the response. Their signing and verification configuration is copied when the wrapper is
created. Keep changing key material behind the provider factories or create a new wrapper when
policy changes.

After successful verification, the wrapper returns the response unchanged. It does not consume the
response body and does not validate a body digest.
