# Function: findComponents()

> **findComponents**(`components`, `name`): [`MessageComponent`](../interfaces/MessageComponent.md)\[]

Returns every component identifier in a list that resolves to one field or derived component
name, whatever parameters it carries.

This answers "is this field covered at all", which [includesComponent](includesComponent.md) deliberately does
not: that function matches the complete identifier, so it does not find `"example-dict";key="a"`
when asked for `"example-dict"`. The identifiers come back so that a caller can see how the field
was covered rather than only that it was.

Reading the parameters matters, because covering a field is not one thing:

- `key` covers **one member** of a Structured Field Dictionary. The other members of that field are
  not covered, so a peer can add, remove, or change them without breaking the signature.
- `req` covers the value from the related request rather than from the response.
- `bs` and `tr` change which bytes and which section the value is taken from.

A coverage rule that treats any match as "the field is protected" is therefore weaker than it
reads. Decide from the parameters whether the match is the one the rule meant.

The list is not required to be a valid covered component list, so an identifier that arrived on
the wire is matched rather than rejected. The name comes from the application and is validated.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `components` | readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[] | Identifiers to search, such as [MessageSignature.components](../interfaces/MessageSignature.md#components) or a covered component list an application is about to sign. |
| `name` | `string` | A field name, matched case-insensitively, or a case-sensitive derived component name. |

## Returns

[`MessageComponent`](../interfaces/MessageComponent.md)\[]

The matching identifiers in list order, normalized, or an empty array.

## Example

A conditional coverage rule, written so that a keyed identifier does not silently satisfy a rule
about the whole field.

```ts
declare const signature: FetchSig.MessageSignature
declare const message: Request

if (message.headers.has('signature-agent')) {
  const covered = FetchSig.findComponents(signature.components, 'signature-agent')
  if (covered.length === 0) {
    throw new Error('An unsigned signature-agent field is not accepted')
  }
  // Accept a single dictionary member only when the rule is about that member.
  if (covered.every(({ parameters }) => parameters.some(([name]) => name === 'key'))) {
    throw new Error('signature-agent must be covered as a whole field')
  }
}
```
