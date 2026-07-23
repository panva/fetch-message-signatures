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
or `:80` on an `http` URL is omitted, while a non-default port such as `:8443` is retained.

RFC 9421 marks `@request-target` as **NOT RECOMMENDED** when an HTTP version other than HTTP/1.1
might be used. This implementation derives its origin-form path and query from `Request.url`. Use it
only when an HTTP/1.1-specific integration makes that value authoritative. Otherwise, cover
`@target-uri` or the needed combination of `@authority`, `@path`, and `@query`.

All URL-derived components reflect the Fetch object rather than an original wire representation. See
[Fetch behavior and limitations](./fetch.md#url-derived-components) for proxy rewrites, URL
normalization, and values that Fetch does not expose.

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

For application-defined Structured Fields, supply their top-level type when using `sf`:

```ts
const request = new Request('https://api.example/', { headers: { priority: 'u=3, i' } })

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('priority', [['sf', true]])],
  structuredFields: { priority: 'dictionary' },
})
```

`signature`, `signature-input`, and `accept-signature` are known Dictionaries. For other fields, map
the lowercase field name to `'dictionary'`, `'list'`, or `'item'`. Malformed input is rejected.

The `key` parameter establishes that the field is a Dictionary and signs one member, so it does not
require a `structuredFields` mapping:

```ts
const request = new Request('https://api.example/', {
  headers: { 'example-dictionary': 'a=1, b="two"' },
})

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('example-dictionary', [['key', 'b']])],
})
```

## Raw field values

Supply `fieldValues` when a component needs original field occurrences, trailer values, or another
authoritative transport representation:

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
newlines are rejected. Keep header and trailer occurrences separate by branching on
`context.trailers`. Runtimes with `Headers.getSetCookie()` can provide `set-cookie` occurrences
without an adapter.

The [Fetch guide](./fetch.md#repeated-field-lines) covers repeated-field combination, trailer
access, and transport of trailer-carried signature fields.

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

Extension parameters can use Strings, Integers, Booleans, Byte Sequences, Tokens, Decimals, Dates,
and Display Strings:

```ts
const parameters: FetchSig.SignatureParameters = [
  ['example-token', FetchSig.token('example/value')],
  ['example-decimal', FetchSig.decimal(1)],
  ['example-bytes', new Uint8Array([1, 2, 3])],
  ['example-date', FetchSig.date(1_659_578_233)],
  ['example-display', FetchSig.displayString('snowman ☃')],
]
```

Plain JavaScript strings are Structured Field Strings. Plain integral numbers are Integers.
`decimal()` preserves Decimal type for integral values such as `1.0`. `Date` is accepted as a
signing input and converted to the RFC 9421 Integer timestamp form used by `created` and `expires`.
Use `date()` when the value must retain the Structured Field Date type, and `displayString()` when
the value must retain the Display String type. The known RFC 9421 parameters in the table above
still require their specified types.

The wrapper is what distinguishes a Structured Field Date from an Integer on the wire:

```ts
const instant = new Date(1_659_578_233_000)

const parameters: FetchSig.SignatureParameters = [
  ['integer-time', instant],
  ['structured-date', FetchSig.date(instant)],
]

// ;integer-time=1659578233;structured-date=@1659578233
```

`displayString()` rejects unpaired UTF-16 surrogates. Serialization encodes Unicode as UTF-8 and
uses lowercase percent encoding for bytes outside safe ASCII. Display Strings are intended for text
shown to users. Prefer a regular Structured Field String when Unicode display text is unnecessary.

Use ordered tuple arrays whenever another implementation must reproduce the exact serialization.
