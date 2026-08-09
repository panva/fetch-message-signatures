# Type Alias: FieldValues

> **FieldValues** = (`message`, `name`, `context`) => `ReadonlyArray`<`string`> ∣ `undefined`

Supplies individual HTTP field occurrences in wire order.

Fetch combines most repeated field lines and does not expose trailers. Provide this adapter when
using the `tr` component parameter, when using `bs` with a `Headers` that does not expose the
occurrences, or when an application has a more authoritative representation of the HTTP message.
A descriptor record whose value is an array already retains the occurrences needed by `bs`.

If a field name occurs in both the header and trailer sections, return only the section selected
by `context.trailers`. RFC 9421 forbids combining same-name header and trailer values for
signature-base generation.

Returning `undefined` or an empty array indicates that the field is absent.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | [`SignableRequest`](SignableRequest.md) ∣ [`SignableResponse`](SignableResponse.md) |
| `name` | `string` |
| `context` | [`FieldValueContext`](../interfaces/FieldValueContext.md) |

## Returns

`ReadonlyArray`<`string`> ∣ `undefined`
