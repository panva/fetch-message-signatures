# Function: date()

> **date**(`value`): [`StructuredFieldDate`](../interfaces/StructuredFieldDate.md)

Creates a validated Structured Field Date.

Numbers are interpreted as integer UNIX seconds. JavaScript `Date` values are rounded down to
whole UNIX seconds. A JavaScript `Date` passed directly as a signature parameter is an RFC 9421
Integer timestamp. Wrap it with `date()` to select a Structured Field Date and serialize it with
the `@` prefix.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `number` ∣ `Date` |

## Returns

[`StructuredFieldDate`](../interfaces/StructuredFieldDate.md)

## Example

The same instant, as the Integer form RFC 9421 defines for `created` and `expires`, and as a
Structured Field Date. Only use the Date type for extension parameters.

```ts
const instant = new Date(1_659_578_233_000)

const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
  components: ['@method'],
  parameters: [
    ['created', instant],
    ['example-date', FetchSig.date(instant)],
  ],
})

// "@signature-params": ("@method");created=1659578233;example-date=@1659578233
console.log(base)
```
