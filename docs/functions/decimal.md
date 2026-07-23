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
