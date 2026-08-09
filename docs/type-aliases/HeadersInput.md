# Type Alias: HeadersInput

> **HeadersInput** = `Headers` ∣ `Readonly`<`Record`<`string`, `string` ∣ `ReadonlyArray`<`string`> ∣ `undefined`>>

HTTP fields supplied to a reading operation.

A Fetch `Headers` is used as it is. A plain record is what a server framework typically hands a
handler, so its own field object can be passed straight through. An array value is one field with
repeated occurrences, which RFC 9421 combines rather than concatenating with a bare comma.
