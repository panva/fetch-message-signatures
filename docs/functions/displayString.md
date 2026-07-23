# Function: displayString()

> **displayString**(`value`): [`StructuredFieldDisplayString`](../interfaces/StructuredFieldDisplayString.md)

Creates a validated Structured Field Display String.

The value must contain only Unicode scalar values. Serialization UTF-8 encodes characters that
are not safe ASCII and represents their bytes using lowercase percent encoding. Display Strings
are intended for text shown to users; use a regular Structured Field String when Unicode display
text is not required.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `string` |

## Returns

[`StructuredFieldDisplayString`](../interfaces/StructuredFieldDisplayString.md)
