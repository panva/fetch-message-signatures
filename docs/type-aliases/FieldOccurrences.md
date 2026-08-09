# Type Alias: FieldOccurrences

> **FieldOccurrences** = `Readonly`<`Record`<`string`, `ReadonlyArray`<`string`>>>

Immutable HTTP field occurrences indexed by lowercase field name, in their received order.

A plain message descriptor preserves the occurrence boundaries it supplies. Fetch `Headers`
usually exposes only a combined value, except where the runtime provides `getSetCookie()`.
