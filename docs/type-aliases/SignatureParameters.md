# Type Alias: SignatureParameters

> **SignatureParameters** = `ReadonlyArray`<[`SignatureParameter`](SignatureParameter.md)> ∣ `Readonly`<`Record`<`string`, [`SignatureParameterInput`](SignatureParameterInput.md)>>

Ordered parameters are recommended because their order is covered by the signature. Object
property insertion order is preserved when a record is supplied.
