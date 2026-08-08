# Function: parseStructuredField()

## Call Signature

> **parseStructuredField**(`value`, `type`): [`StructuredFieldDictionary`](../type-aliases/StructuredFieldDictionary.md)

Parses an HTTP field value as one of the three RFC 9651 top-level Structured Field types.

The whole value must parse, so trailing content is rejected rather than ignored. A Dictionary
that repeats a key keeps the last occurrence, as RFC 9651 requires.

Values come back in the same model [MessageSignature](../interfaces/MessageSignature.md) parameters use: plain JavaScript
values for the unambiguous types, and wrappers for Token, Decimal, Date, and Display String. See
[StructuredFieldBareItem](../type-aliases/StructuredFieldBareItem.md).

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | `string` | The complete HTTP field value. |
| `type` | `"dictionary"` | The top-level type the field is defined to use. |

### Returns

[`StructuredFieldDictionary`](../type-aliases/StructuredFieldDictionary.md)

### Example

Reading a Dictionary field whose members are Strings with parameters.

```ts
const dictionary = FetchSig.parseStructuredField(
  'sig1="https://agent.example";type=directory, sig2="https://other.example"',
  'dictionary',
)

for (const [label, member] of dictionary) {
  if (member.type !== 'item' || typeof member.value !== 'string') {
    throw new Error(`${label} must be a String`)
  }
  const type = member.parameters.find(([name]) => name === 'type')?.[1]
  // sig1 https://agent.example { type: 'token', value: 'directory' }
  console.log(label, member.value, type)
}
```

## Call Signature

> **parseStructuredField**(`value`, `type`): [`StructuredFieldList`](../type-aliases/StructuredFieldList.md)

Parses an HTTP field value as one of the three RFC 9651 top-level Structured Field types.

The whole value must parse, so trailing content is rejected rather than ignored. A Dictionary
that repeats a key keeps the last occurrence, as RFC 9651 requires.

Values come back in the same model [MessageSignature](../interfaces/MessageSignature.md) parameters use: plain JavaScript
values for the unambiguous types, and wrappers for Token, Decimal, Date, and Display String. See
[StructuredFieldBareItem](../type-aliases/StructuredFieldBareItem.md).

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | `string` | The complete HTTP field value. |
| `type` | `"list"` | The top-level type the field is defined to use. |

### Returns

[`StructuredFieldList`](../type-aliases/StructuredFieldList.md)

### Example

Reading a Dictionary field whose members are Strings with parameters.

```ts
const dictionary = FetchSig.parseStructuredField(
  'sig1="https://agent.example";type=directory, sig2="https://other.example"',
  'dictionary',
)

for (const [label, member] of dictionary) {
  if (member.type !== 'item' || typeof member.value !== 'string') {
    throw new Error(`${label} must be a String`)
  }
  const type = member.parameters.find(([name]) => name === 'type')?.[1]
  // sig1 https://agent.example { type: 'token', value: 'directory' }
  console.log(label, member.value, type)
}
```

## Call Signature

> **parseStructuredField**(`value`, `type`): [`StructuredFieldItem`](../interfaces/StructuredFieldItem.md)

Parses an HTTP field value as one of the three RFC 9651 top-level Structured Field types.

The whole value must parse, so trailing content is rejected rather than ignored. A Dictionary
that repeats a key keeps the last occurrence, as RFC 9651 requires.

Values come back in the same model [MessageSignature](../interfaces/MessageSignature.md) parameters use: plain JavaScript
values for the unambiguous types, and wrappers for Token, Decimal, Date, and Display String. See
[StructuredFieldBareItem](../type-aliases/StructuredFieldBareItem.md).

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | `string` | The complete HTTP field value. |
| `type` | `"item"` | The top-level type the field is defined to use. |

### Returns

[`StructuredFieldItem`](../interfaces/StructuredFieldItem.md)

### Example

Reading a Dictionary field whose members are Strings with parameters.

```ts
const dictionary = FetchSig.parseStructuredField(
  'sig1="https://agent.example";type=directory, sig2="https://other.example"',
  'dictionary',
)

for (const [label, member] of dictionary) {
  if (member.type !== 'item' || typeof member.value !== 'string') {
    throw new Error(`${label} must be a String`)
  }
  const type = member.parameters.find(([name]) => name === 'type')?.[1]
  // sig1 https://agent.example { type: 'token', value: 'directory' }
  console.log(label, member.value, type)
}
```

## Call Signature

> **parseStructuredField**(`value`, `type`): [`StructuredFieldValue`](../type-aliases/StructuredFieldValue.md)

Parses an HTTP field value as one of the three RFC 9651 top-level Structured Field types.

The whole value must parse, so trailing content is rejected rather than ignored. A Dictionary
that repeats a key keeps the last occurrence, as RFC 9651 requires.

Values come back in the same model [MessageSignature](../interfaces/MessageSignature.md) parameters use: plain JavaScript
values for the unambiguous types, and wrappers for Token, Decimal, Date, and Display String. See
[StructuredFieldBareItem](../type-aliases/StructuredFieldBareItem.md).

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | `string` | The complete HTTP field value. |
| `type` | [`StructuredFieldType`](../type-aliases/StructuredFieldType.md) | The top-level type the field is defined to use. |

### Returns

[`StructuredFieldValue`](../type-aliases/StructuredFieldValue.md)

### Example

Reading a Dictionary field whose members are Strings with parameters.

```ts
const dictionary = FetchSig.parseStructuredField(
  'sig1="https://agent.example";type=directory, sig2="https://other.example"',
  'dictionary',
)

for (const [label, member] of dictionary) {
  if (member.type !== 'item' || typeof member.value !== 'string') {
    throw new Error(`${label} must be a String`)
  }
  const type = member.parameters.find(([name]) => name === 'type')?.[1]
  // sig1 https://agent.example { type: 'token', value: 'directory' }
  console.log(label, member.value, type)
}
```
