# Function: component()

> **component**(`name`, `parameters?`): [`ParameterizedComponent`](../interfaces/ParameterizedComponent.md)

Creates a component identifier while preserving the supplied parameter order.

HTTP field names are normalized to lowercase. Derived component names are case-sensitive.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `name` | `string` |
| `parameters` | [`ComponentParameters`](../type-aliases/ComponentParameters.md) |

## Returns

[`ParameterizedComponent`](../interfaces/ParameterizedComponent.md)
