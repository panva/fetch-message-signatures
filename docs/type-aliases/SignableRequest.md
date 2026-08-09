# Type Alias: SignableRequest

> **SignableRequest** = `Request` ∣ { `headers`: [`HeadersInput`](HeadersInput.md); `method`: `string`; `url`: `string`; `trailers?`: [`HeadersInput`](HeadersInput.md); }

A request this package can read components from.

A Fetch `Request` is the expected input, and is what the Fetch wrappers, [sign](../functions/sign.md),
[appendSignature](../functions/appendSignature.md), [signRequested](../functions/signRequested.md), and [appendAcceptSignature](../functions/appendAcceptSignature.md) require. The
second member exists for a server that never constructs one and holds only the values it read off
an incoming request. Such a caller uses [createSignature](../functions/createSignature.md) and attaches the returned field
values itself.

## Union Members

`Request`

***

### Type Literal

{ `headers`: [`HeadersInput`](HeadersInput.md); `method`: `string`; `url`: `string`; `trailers?`: [`HeadersInput`](HeadersInput.md); }

#### headers

> `readonly` **headers**: [`HeadersInput`](HeadersInput.md)

#### method

> `readonly` **method**: `string`

#### url

> `readonly` **url**: `string`

#### trailers?

> `readonly` `optional` **trailers?**: [`HeadersInput`](HeadersInput.md)

Trailer occurrences, when the transport exposes them.
