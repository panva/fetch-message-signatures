# Type Alias: ComponentParameters

> **ComponentParameters** = `ReadonlyArray`<[`ComponentParameter`](ComponentParameter.md)> ∣ `Readonly`<`Record`<`string`, [`ComponentParameterValue`](ComponentParameterValue.md)>>

Ordered parameters are recommended because their serialization order is covered by the signature.
Object property insertion order is preserved when a record is supplied.
