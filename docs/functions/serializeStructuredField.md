# Function: serializeStructuredField()

## Call Signature

> **serializeStructuredField**(`value`, `type`): `string`

Serializes a Structured Field value into an HTTP field value.

Every key, Token, Decimal, Date, and Display String is validated, so a value this rejects is one
no conforming recipient would have accepted.

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | [`StructuredFieldDictionary`](../type-aliases/StructuredFieldDictionary.md) | The value to serialize, in the shape [parseStructuredField](parseStructuredField.md) returns. |
| `type` | `"dictionary"` | The top-level type the field is defined to use. |

### Returns

`string`

### Example

```ts
const field = FetchSig.serializeStructuredField(
  [
    [
      'sig1',
      {
        type: 'item',
        value: 'https://agent.example',
        parameters: [['type', FetchSig.token('directory')]],
      },
    ],
  ],
  'dictionary',
)

// sig1="https://agent.example";type=directory
console.log(field)
```

## Call Signature

> **serializeStructuredField**(`value`, `type`): `string`

Serializes a Structured Field value into an HTTP field value.

Every key, Token, Decimal, Date, and Display String is validated, so a value this rejects is one
no conforming recipient would have accepted.

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | [`StructuredFieldList`](../type-aliases/StructuredFieldList.md) | The value to serialize, in the shape [parseStructuredField](parseStructuredField.md) returns. |
| `type` | `"list"` | The top-level type the field is defined to use. |

### Returns

`string`

### Example

```ts
const field = FetchSig.serializeStructuredField(
  [
    [
      'sig1',
      {
        type: 'item',
        value: 'https://agent.example',
        parameters: [['type', FetchSig.token('directory')]],
      },
    ],
  ],
  'dictionary',
)

// sig1="https://agent.example";type=directory
console.log(field)
```

## Call Signature

> **serializeStructuredField**(`value`, `type`): `string`

Serializes a Structured Field value into an HTTP field value.

Every key, Token, Decimal, Date, and Display String is validated, so a value this rejects is one
no conforming recipient would have accepted.

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | [`StructuredFieldItem`](../interfaces/StructuredFieldItem.md) | The value to serialize, in the shape [parseStructuredField](parseStructuredField.md) returns. |
| `type` | `"item"` | The top-level type the field is defined to use. |

### Returns

`string`

### Example

```ts
const field = FetchSig.serializeStructuredField(
  [
    [
      'sig1',
      {
        type: 'item',
        value: 'https://agent.example',
        parameters: [['type', FetchSig.token('directory')]],
      },
    ],
  ],
  'dictionary',
)

// sig1="https://agent.example";type=directory
console.log(field)
```

## Call Signature

> **serializeStructuredField**(`value`, `type`): `string`

Serializes a Structured Field value into an HTTP field value.

Every key, Token, Decimal, Date, and Display String is validated, so a value this rejects is one
no conforming recipient would have accepted.

### Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `value` | [`StructuredFieldValue`](../type-aliases/StructuredFieldValue.md) | The value to serialize, in the shape [parseStructuredField](parseStructuredField.md) returns. |
| `type` | [`StructuredFieldType`](../type-aliases/StructuredFieldType.md) | The top-level type the field is defined to use. |

### Returns

`string`

### Example

```ts
const field = FetchSig.serializeStructuredField(
  [
    [
      'sig1',
      {
        type: 'item',
        value: 'https://agent.example',
        parameters: [['type', FetchSig.token('directory')]],
      },
    ],
  ],
  'dictionary',
)

// sig1="https://agent.example";type=directory
console.log(field)
```
