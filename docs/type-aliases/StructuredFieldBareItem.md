# Type Alias: StructuredFieldBareItem

> **StructuredFieldBareItem** = `string` ∣ `number` ∣ `boolean` ∣ `Uint8Array` ∣ [`StructuredFieldToken`](../interfaces/StructuredFieldToken.md) ∣ [`StructuredFieldDecimal`](../interfaces/StructuredFieldDecimal.md) ∣ [`StructuredFieldDate`](../interfaces/StructuredFieldDate.md) ∣ [`StructuredFieldDisplayString`](../interfaces/StructuredFieldDisplayString.md)

A bare item value in an HTTP Structured Field.

Plain JavaScript values represent the types that cannot be confused for one another: `string` is
a String, an integral `number` is an Integer, `boolean` is a Boolean, and `Uint8Array` is a Byte
Sequence. The four types that would otherwise be ambiguous are wrapped, so a Token is never
mistaken for a String, nor a Decimal for an Integer.
