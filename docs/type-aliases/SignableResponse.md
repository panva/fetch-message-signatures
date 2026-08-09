# Type Alias: SignableResponse

> **SignableResponse** = `Response` ∣ { `headers`: [`HeadersInput`](HeadersInput.md); `status`: `number`; }

A response this package can read components from.

A Fetch `Response` is the expected input. See [SignableRequest](SignableRequest.md) for when the second member
is useful.
