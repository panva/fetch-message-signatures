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

[`includesComponent()`](../docs/functions/includesComponent.md) tests one identifier against a list
of them, normalizing both sides the same way:

```ts
declare const components: FetchSig.ComponentIdentifier[]

FetchSig.includesComponent(components, '@method') // true
FetchSig.includesComponent(components, 'Example-Dictionary') // false, the covered one has a key
```

It matches the complete identifier, parameters included, so it distinguishes `"@authority"` from
`"@authority";req`. Use it on a covered component list about to be signed, or on the `components` of
a parsed signature.

To ask the looser question, whether a field is covered at all,
[`findComponents()`](../docs/functions/findComponents.md) returns every identifier that resolves to
one name:

```ts
declare const signature: FetchSig.MessageSignature

const covered = FetchSig.findComponents(signature.components, 'example-dictionary')
```

It returns the identifiers rather than a boolean because covering a field is not one thing. A `key`
parameter covers a single Dictionary member and leaves the rest of that field unprotected, `req`
takes the value from the related request, and `bs` and `tr` change which bytes are covered. A rule
that treats any match as "this field is protected" is weaker than it reads, so decide from the
parameters whether the match is the one the rule meant.

## Derived components

| Component               | Target   | Fetch source                                                                |
| ----------------------- | -------- | --------------------------------------------------------------------------- |
| `@method`               | Request  | `Request.method`                                                            |
| `@target-uri`           | Request  | `Request.url` without a fragment                                            |
| `@authority`            | Request  | Lowercase URL host, retaining a non-default port and omitting a default one |
| `@scheme`               | Request  | Lowercase URL scheme                                                        |
| `@request-target`       | Request  | URL-derived origin-form path plus query, with the warning below             |
| `@path`                 | Request  | URL path, defaulting to `/`                                                 |
| `@query`                | Request  | `?` plus the query, or `?` when absent                                      |
| `@query-param;name="…"` | Request  | Exactly one matching decoded-and-reencoded query parameter                  |
| `@status`               | Response | Unfiltered three-digit numeric response status, without reason text         |

`@authority` follows URL authority normalization. For example, an explicit `:443` on an `https` URL
or `:80` on an `http` URL is omitted, while a non-default port such as `:8443` is retained.

`@authority`, `@path`, and `@request-target` require a target URI that has an authority, which every
scheme RFC 9421 applies to does. A URL without one, such as `data:` or `blob:`, fails rather than
producing an empty authority or a relative path. A target URI carrying credentials is rejected
outright. See [Fetch behavior](./fetch.md#url-derived-components).

RFC 9421 marks `@request-target` as **NOT RECOMMENDED** when an HTTP version other than HTTP/1.1
might be used. This implementation derives its origin-form path and query from `Request.url`. Use it
only when an HTTP/1.1-specific integration makes that value authoritative. Otherwise, cover
`@target-uri` or the needed combination of `@authority`, `@path`, and `@query`.

All URL-derived components reflect the Fetch object rather than an original wire representation. See
[Fetch behavior and limitations](./fetch.md#url-derived-components) for proxy rewrites, URL
normalization, and values that Fetch does not expose.

`@query-param` requires a Structured Field String `name` parameter holding the _encoded_ parameter
name. Encoding follows RFC 9421: the query string is parsed with the URL Standard's
`application/x-www-form-urlencoded` parser, and each decoded name and value is re-encoded with that
standard's `application/x-www-form-urlencoded` percent-encode set. So `+` in the query decodes to a
space and re-encodes to `%20`, not back to `+`, matching the worked example in RFC 9421 §2.2.8. The
characters `!`, `'`, `(`, `)`, and `~` are percent-encoded, while `*`, `-`, `.`, and `_` are not.

```ts
const request = new Request('https://api.example/p?bar=with+plus+whitespace')

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('@query-param', [['name', 'bar']])],
})

// "@query-param";name="bar": with%20plus%20whitespace
// "@signature-params": ("@query-param";name="bar")
console.log(base)
```

A parameter that is absent fails signature base generation. A parameter name that occurs more than
once must not be signed at all, so it is rejected rather than resolved to one of its values. Cover
`@query` instead when repeated names are expected.

The `@signature-params` component is never listed. It is appended automatically as the last line of
the signature base, and RFC 9421 forbids naming it as a covered component.

The same component identifier, including its parameters, must not be covered twice. Because
Structured Field parameters are an ordered map keyed by name, this package compares parameter sets
rather than their serialized order, so `"x";sf;tr` and `"x";tr;sf` count as the same identifier. It
also rejects two identifiers that select the same Dictionary member of the same field, such as
`"x";key="a"` and `"x";key="a";sf`, which RFC 9421 §2.1.2 requires.

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

// "x-example": one, two
// "@signature-params": ("x-example")
console.log(base)
```

The surrounding whitespace is gone because RFC 9421 strips leading and trailing whitespace from each
field line. The internal `, ` is part of the value and is left alone.

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
const request = new Request('https://api.example/', { headers: { priority: 'u=3,  i' } })

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('priority', [['sf', true]])],
  structuredFields: { priority: 'dictionary' },
})

// "priority";sf: u=3, i
// "@signature-params": ("priority";sf)
console.log(base)
```

Re-serialization is what makes `sf` worth using: the sender sent `u=3,  i` with two spaces, and both
endpoints sign the single canonical form `u=3, i`, so an intermediary that adjusts internal
whitespace cannot break the signature.

`signature`, `signature-input`, and `accept-signature` are known Dictionaries. For other fields, map
the lowercase field name to `'dictionary'`, `'list'`, or `'item'`. Malformed input is rejected.

The `key` parameter establishes that the field is a Dictionary and signs one member, so it does not
require a `structuredFields` mapping:

```ts
const request = new Request('https://api.example/', {
  headers: { 'example-dictionary': 'a=1, b="two", c=(a  b), d' },
})

const base = FetchSig.createSignatureBase(request, {
  components: [
    FetchSig.component('example-dictionary', [['key', 'b']]),
    FetchSig.component('example-dictionary', [['key', 'c']]),
    FetchSig.component('example-dictionary', [['key', 'd']]),
  ],
})

// "example-dictionary";key="b": "two"
// "example-dictionary";key="c": (a b)
// "example-dictionary";key="d": ?1
// "@signature-params": ("example-dictionary";key="b" "example-dictionary";key="c" …)
console.log(base)
```

Each member is serialized on its own: an Inner List keeps its parentheses, and a member with no
value is the Boolean `?1`. The Dictionary key itself is not part of the component value.

## Parsing and serializing Structured Fields

RFC 9421 is built on Structured Fields ([RFC 9651](https://www.rfc-editor.org/info/rfc9651/)), and
the same parser and serializer are exported for fields this package does not define:

```ts
const header = 'sig1="https://agent.example";type=directory, sig2="https://other.example"'

for (const [label, member] of FetchSig.parseStructuredField(header, 'dictionary')) {
  if (member.type !== 'item' || typeof member.value !== 'string') {
    throw new Error(`${label} must be a String`)
  }
  const type = member.parameters.find(([name]) => name === 'type')?.[1]
  // sig1 https://agent.example { type: 'token', value: 'directory' }
  console.log(label, member.value, type)
}
```

The top-level type is an argument because a Structured Field's type comes from its definition, not
from its syntax. Passing `'dictionary'`, `'list'`, or `'item'` as a literal narrows the return type
to `StructuredFieldDictionary`, `StructuredFieldList`, or `StructuredFieldItem`.

Values use the same model as signature metadata parameters: plain JavaScript values for the types
that cannot be confused for one another, and wrappers for the four that can.

| Structured Field type | JavaScript                          |
| --------------------- | ----------------------------------- |
| String                | `string`                            |
| Integer               | `number`, integral                  |
| Boolean               | `boolean`                           |
| Byte Sequence         | `Uint8Array`                        |
| Decimal               | `{ type: 'decimal', value }`        |
| Token                 | `{ type: 'token', value }`          |
| Date                  | `{ type: 'date', value }`           |
| Display String        | `{ type: 'display-string', value }` |

`serializeStructuredField()` takes the same shape back and validates every key, Token, Decimal,
Date, and Display String, so a value it rejects is one no conforming recipient would have accepted.

Dictionaries are ordered entries rather than a `Map`, because RFC 9651 defines them as ordered and
both the serialization and, for signed fields, the signature depend on that order.

A field value that arrived on an HTTP message is not automatically canonical. This parser sees the
octets it is given, so strip any surrounding whitespace the way an HTTP field line would before
handing a value to it.

## Raw field values

Supply a plain message descriptor when a component needs original field occurrences or trailer
values that Fetch does not expose. An array value is the occurrence list in wire order:

```ts
const request: FetchSig.SignableRequest = {
  method: 'GET',
  url: 'https://api.example/',
  headers: {
    // The two field lines as they appear on the wire, in order.
    'x-list': ['value, with, lots', 'of, commas'],
  },
}

const base = FetchSig.createSignatureBase(request, {
  components: [FetchSig.component('x-list', [['bs', true]])],
})

// "x-list";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:
// "@signature-params": ("x-list";bs)
console.log(base)
```

Two field lines produce two Byte Sequences. A single line reading `value, with, lots, of, commas`
would produce one Byte Sequence with a different value, which is exactly the collision that `bs`
prevents.

Descriptor values can be one string for one known occurrence, an array for repeated occurrences, or
`undefined` for an absent field. An empty array is also absent. Values containing disallowed control
characters or a newline that is not an obsolete line fold are rejected; an obsolete fold is
canonicalized to one space. Put trailer occurrences in the descriptor's separate optional `trailers`
record; never combine a same-name header and trailer. A related request supplied for `req`
components can use the same descriptor shape.

The package copies descriptor fields into the operation's immutable snapshot, lowercases their
names, and freezes every occurrence array. A Fetch `Headers` does not retain occurrence boundaries,
so it cannot satisfy `bs` even when its combined value happens to look like one field line. The
exception is `set-cookie` in runtimes with `Headers.getSetCookie()`.

Occurrences without `bs` are combined with a comma and a single space. `bs` instead wraps each
occurrence as a Structured Field Byte Sequence, taking one octet per JavaScript code unit, which is
the representation Fetch uses for field values. A value carrying a code unit above `U+00FF` cannot
be represented and is rejected.

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
const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
  components: ['@method'],
  parameters: [
    ['example-token', FetchSig.token('example/value')],
    ['example-decimal', FetchSig.decimal(1)],
    ['example-bytes', new Uint8Array([1, 2, 3])],
    ['example-date', FetchSig.date(1_659_578_233)],
    ['example-display', FetchSig.displayString('snowman ☃')],
  ],
})

// "@method": GET
// "@signature-params": ("@method");example-token=example/value;example-decimal=1.0
//   ;example-bytes=:AQID:;example-date=@1659578233;example-display=%"snowman %e2%98%83"
console.log(base)
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

const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
  components: ['@method'],
  parameters: [
    ['integer-time', instant],
    ['structured-date', FetchSig.date(instant)],
  ],
})

// "@signature-params": ("@method");integer-time=1659578233;structured-date=@1659578233
console.log(base)
```

`displayString()` rejects unpaired UTF-16 surrogates. Serialization encodes Unicode as UTF-8 and
uses lowercase percent encoding for bytes outside safe ASCII. Display Strings are intended for text
shown to users. Prefer a regular Structured Field String when Unicode display text is unnecessary.

Use ordered tuple arrays whenever another implementation must reproduce the exact serialization.
