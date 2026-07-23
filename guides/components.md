# Components and Structured Fields

The covered component list defines the input to a message signature. Its order is significant. Every
component identifier is serialized as a Structured Field String with optional parameters.

Plain strings are shorthand for unparameterized identifiers. `component()` is the convenient and
type-safe way to construct a parameterized identifier:

```ts
const components: FetchSig.ComponentIdentifier[] = [
  '@method',
  FetchSig.component('@query-param', [['name', 'page']]),
  FetchSig.component('example-dictionary', [['key', 'member']]),
]
```

HTTP field names are normalized to lowercase. Derived component names begin with `@`, are
case-sensitive, and must be one of the supported RFC 9421 components.

## Derived components

| Component               | Target   | Fetch source                                                        |
| ----------------------- | -------- | ------------------------------------------------------------------- |
| `@method`               | Request  | `Request.method`                                                    |
| `@target-uri`           | Request  | `Request.url` without a fragment                                    |
| `@authority`            | Request  | Lowercase URL host; non-default port retained, default port omitted |
| `@scheme`               | Request  | Lowercase URL scheme                                                |
| `@request-target`       | Request  | URL-derived origin-form path plus query; see the warning below      |
| `@path`                 | Request  | URL path, defaulting to `/`                                         |
| `@query`                | Request  | `?` plus the query, or `?` when absent                              |
| `@query-param;name="…"` | Request  | Exactly one matching decoded-and-reencoded query parameter          |
| `@status`               | Response | Unfiltered three-digit numeric response status, without reason text |

`@authority` follows URL authority normalization. For example, an explicit `:443` on an `https` URL
or `:80` on an `http` URL is omitted, while a non-default port such as `:8443` is retained. Fetch
derives this from `Request.url`, so deployments must account for authority rewrites by reverse
proxies.

RFC 9421 marks `@request-target` as **NOT RECOMMENDED** when an HTTP version other than HTTP/1.1
might be used. Fetch neither exposes the HTTP version nor the request-target form received on the
wire; this implementation can derive only the origin-form path and query from `Request.url`. Use it
only in a profile confined to an HTTP/1.1 context where that derived value is authoritative.
Otherwise, cover `@target-uri` or an appropriate combination of `@authority`, `@path`, and `@query`.

`@query-param` requires a Structured Field String `name` parameter. The name is the RFC's
percent-encoded query parameter name. The component rejects a missing name or a name that occurs
more than once.

In a response signature, request-derived components require `req`:

```ts
const responseCoverage = [
  '@status',
  FetchSig.component('@method', [['req', true]]),
  FetchSig.component('@target-uri', [['req', true]]),
]
```

`req` cannot be applied to request signatures or to `@status`.

## HTTP field components

An unparameterized field component combines the field occurrences exposed by Fetch and normalizes
optional whitespace:

```ts
const request = new Request('https://api.example/', { headers: { 'x-example': '  one, two  ' } })

const base = FetchSig.createSignatureBase(request, { components: ['x-example'] })
```

Field component parameters change that processing:

| Parameter      | Meaning                                                                       |
| -------------- | ----------------------------------------------------------------------------- |
| `sf`           | Parse and canonically serialize the complete value as a Structured Field.     |
| `key="member"` | Select and serialize one member from a Structured Field Dictionary.           |
| `bs`           | Serialize each original field occurrence as a Structured Field Byte Sequence. |
| `tr`           | Read the component from trailers rather than headers.                         |
| `req`          | Read the component from the related request of a response.                    |

Flag parameters must be bare Boolean true. `bs` is incompatible with `sf` and `key`.

## Structured Field canonicalization

For application-defined Structured Fields, supply their top-level type and grammar when using `sf`:

```ts
const request = new Request('https://api.example/', { headers: { priority: 'u=3, i' } })

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('priority', [['sf', true]])],
  structuredFields: { priority: { type: 'dictionary', version: 'rfc9651' } },
})
```

The package knows that `signature`, `signature-input`, and `accept-signature` are RFC 8941
Dictionaries. Other fields require one of these mappings:

- `'dictionary'`, `'list'`, or `'item'` selects that top-level type with RFC 8941 grammar; or
- `{ type: 'dictionary' | 'list' | 'item', version: 'rfc8941' | 'rfc9651' }` selects both
  explicitly.

Canonicalization parses the field and serializes its structured value; malformed input is rejected.
Select `rfc9651` only for a field whose defining specification uses that grammar.

The `key` parameter parses the field as a Dictionary and signs one member. Without a mapping it uses
RFC 8941; a mapping can select the dictionary grammar version:

```ts
const request = new Request('https://api.example/', {
  headers: { 'example-dictionary': 'a=1, b="two"' },
})

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('example-dictionary', [['key', 'b']])],
  structuredFields: { 'example-dictionary': { type: 'dictionary', version: 'rfc9651' } },
})
```

## Repeated fields and trailers

Fetch normally combines repeated field lines and does not expose trailers. Supply `fieldValues` when
`bs`, `tr`, or an authoritative transport representation is needed:

```ts
declare const request: Request

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('x-list', [['bs', true]])],
  fieldValues(message, name, context) {
    if (name === 'x-list' && !context.trailers) {
      return ['first', 'second']
    }
    return undefined
  },
})
```

The adapter must return field occurrences in wire order. It receives the actual source message,
lowercase field name, and flags indicating trailers and related-request access. Returning
`undefined` or an empty array means absent. Values containing disallowed control characters or
newlines are rejected.

`Headers.getSetCookie()`, where available, provides occurrences for `set-cookie`; other `bs`
components require an adapter.

Standard Fetch has no API for trailer-carried `Signature-Input` and `Signature` fields themselves. A
transport integration must extract those fields and present them through an appropriate message
representation before using the signature parser or verifier.

If a name occurs in both the header and trailer sections, the adapter must keep the two occurrence
lists separate and branch on `context.trailers`; RFC 9421 forbids combining same-name header and
trailer values for signing. Trailer coverage is **NOT RECOMMENDED** unless the signer knows the
verifier can access the trailer values exactly as sent.

## Signature metadata

Signature parameters are ordered Structured Field parameters. Known parameters are:

| Parameter | Type    | Purpose                                    |
| --------- | ------- | ------------------------------------------ |
| `created` | Integer | Creation time as UNIX seconds              |
| `expires` | Integer | Expiration time as UNIX seconds            |
| `nonce`   | String  | Application replay token                   |
| `alg`     | String  | Registered HTTP signature algorithm signal |
| `keyid`   | String  | Application key-selection hint             |
| `tag`     | String  | Application signature purpose              |

Extension parameters can use the Structured Field types defined by RFC 8941: Strings, Integers,
Booleans, byte sequences, Tokens, and Decimals:

```ts
const parameters: FetchSig.SignatureParameters = [
  ['example-token', FetchSig.token('example/value')],
  ['example-decimal', FetchSig.decimal(1)],
  ['example-bytes', new Uint8Array([1, 2, 3])],
]
```

Plain JavaScript strings are Structured Field Strings. Plain integral numbers are Integers.
`decimal()` preserves Decimal type for integral values such as `1.0`. `Date` is accepted as a
signing input and converted to the RFC 9421 Integer timestamp form used by `created` and `expires`.

Covered application fields processed with `;sf` or `;key` can use Date and Display String values
from [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html) only when their mapping explicitly
selects `version: 'rfc9651'`. These types are intentionally not accepted as `Signature-Input`,
`Signature`, or `Accept-Signature` metadata: RFC 9421 defines those fields using RFC 8941, and RFC
9651 Section 2.4 does not retroactively add new types to older field definitions.

Use ordered tuple arrays whenever another implementation must reproduce the exact serialization.
