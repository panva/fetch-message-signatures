# Function: token()

> **token**(`value`): [`StructuredFieldToken`](../interfaces/StructuredFieldToken.md)

Creates a validated Structured Field Token, for use as an extension signature metadata parameter
value.

Plain JavaScript strings are Structured Field Strings, so this wrapper is how a value is marked
as a Token instead.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `string` |

## Returns

[`StructuredFieldToken`](../interfaces/StructuredFieldToken.md)

## Example

The wrapper is the difference between a quoted String and a bare Token on the wire.

```ts
const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
  components: ['@method'],
  parameters: [
    ['as-string', 'example/value'],
    ['as-token', FetchSig.token('example/value')],
  ],
})

// "@signature-params": ("@method");as-string="example/value";as-token=example/value
console.log(base)
```
