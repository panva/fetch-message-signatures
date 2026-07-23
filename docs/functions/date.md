# Function: date()

> **date**(`value`): [`StructuredFieldDate`](../interfaces/StructuredFieldDate.md)

Creates a validated Structured Field Date.

Numbers are interpreted as integer UNIX seconds. JavaScript `Date` values are rounded down to
whole UNIX seconds. A JavaScript `Date` passed directly as a signature parameter is an RFC 9421
Integer timestamp. Wrap it with `date()` to select a Structured Field Date and serialize it with
the `@` prefix.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `value` | `number` ∣ `Date` |

## Returns

[`StructuredFieldDate`](../interfaces/StructuredFieldDate.md)
