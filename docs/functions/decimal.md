# Function: decimal()

> **decimal**(`value`): [`StructuredFieldDecimal`](../interfaces/StructuredFieldDecimal.md)

Creates a validated Structured Field Decimal.

Use this wrapper when an integral value must retain its Decimal type, such as `decimal(1)` for
the serialized value `1.0`.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `number` |

## Returns

[`StructuredFieldDecimal`](../interfaces/StructuredFieldDecimal.md)

## Example

A plain integral number is an Integer; the wrapper keeps it a Decimal. Values are rounded to
three fraction digits, half to even, as RFC 9651 requires.

```ts
const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
  components: ['@method'],
  parameters: [
    ['as-integer', 1],
    ['as-decimal', FetchSig.decimal(1)],
    ['rounded', FetchSig.decimal(1.23456)],
  ],
})

// "@signature-params": ("@method");as-integer=1;as-decimal=1.0;rounded=1.235
console.log(base)
```
