# Type Alias: SignableResponse

> **SignableResponse** = `Response` ∣ { `headers`: [`HeadersInput`](HeadersInput.md); `status`: `number`; `trailers?`: [`HeadersInput`](HeadersInput.md); }

A response this package can read components from.

A Fetch `Response` is the expected input. See [SignableRequest](SignableRequest.md) for when the second member
is useful.

## Union Members

`Response`

***

### Type Literal

{ `headers`: [`HeadersInput`](HeadersInput.md); `status`: `number`; `trailers?`: [`HeadersInput`](HeadersInput.md); }

#### headers

> `readonly` **headers**: [`HeadersInput`](HeadersInput.md)

#### status

> `readonly` **status**: `number`

#### trailers?

> `readonly` `optional` **trailers?**: [`HeadersInput`](HeadersInput.md)

Trailer occurrences, when the transport exposes them.
