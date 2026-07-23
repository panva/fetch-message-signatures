# Function: parseSignatureInput()

> **parseSignatureInput**(`value`): readonly `Omit`<[`MessageSignature`](../interfaces/MessageSignature.md), `"signature"`>\[]

Parses a `Signature-Input` field value into its labeled covered component lists and signature
metadata parameters.

Rejects a repeated label, an unknown derived component, an inapplicable component parameter, a
duplicate covered component, and a known signature metadata parameter of the wrong Structured
Field type. It does not look at any message and does not verify anything.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `string` |

## Returns

readonly `Omit`<[`MessageSignature`](../interfaces/MessageSignature.md), `"signature"`>\[]

## Example

Inspect what a field value claims, for routing or diagnostics. Nothing here is authenticated.

```ts
const [signature] = FetchSig.parseSignatureInput(
  'sig1=("@method" "@path" "example-dictionary";key="a");created=1735689600;keyid="client-key"',
)

// sig1
console.log(signature!.label)

// [ '@method', '@path', 'example-dictionary' ]
console.log(signature!.components.map(({ name }) => name))

// [ [ 'created', 1735689600 ], [ 'keyid', 'client-key' ] ]
console.log(signature!.parameters)
```
