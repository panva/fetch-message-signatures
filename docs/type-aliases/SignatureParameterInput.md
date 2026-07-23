# Type Alias: SignatureParameterInput

> **SignatureParameterInput** = [`SignatureParameterValue`](SignatureParameterValue.md) ∣ `Date` ∣ `undefined`

A signature metadata parameter input.

`Date` values are converted to integer UNIX timestamps. `false` is useful only for the `created`
parameter, where it explicitly disables the default creation timestamp.
