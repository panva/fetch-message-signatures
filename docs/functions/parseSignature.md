# Function: parseSignature()

> **parseSignature**(`value`): readonly `Readonly`<{ `label`: `string`; `signature`: `Uint8Array`; }>\[]

Parses a `Signature` field value into its labeled signature byte sequences.

Rejects a repeated label and a member that is not a Byte Sequence. It does not look at any
message and does not verify anything.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `string` |

## Returns

readonly `Readonly`<{ `label`: `string`; `signature`: `Uint8Array`; }>\[]

## Example

Decode the raw signature bytes carried under each label.

```ts
const signatures = FetchSig.parseSignature('sig1=:AQIDBA==:, sig2=:BQYHCA==:')

// sig1 Uint8Array(4) [ 1, 2, 3, 4 ]
// sig2 Uint8Array(4) [ 5, 6, 7, 8 ]
for (const { label, signature } of signatures) {
  console.log(label, signature)
}
```
