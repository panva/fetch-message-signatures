# Type Alias: NormalizedMessage

> **NormalizedMessage** = [`SignableRequest`](SignableRequest.md) ∣ [`SignableResponse`](SignableResponse.md) & `object`

A [SignableRequest](SignableRequest.md) or [SignableResponse](SignableResponse.md) whose fields use the host's `Headers`
representation. This is an application-processing view, not an occurrence-preserving view.

## Type Declaration

### headers

> `readonly` **headers**: `Headers`
