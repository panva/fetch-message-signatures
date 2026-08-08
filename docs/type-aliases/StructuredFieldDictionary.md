# Type Alias: StructuredFieldDictionary

> **StructuredFieldDictionary** = `ReadonlyArray`\<readonly \[`string`, [`StructuredFieldMember`](StructuredFieldMember.md)]>

A Structured Field Dictionary as ordered entries.

Ordered rather than a `Map`, because RFC 9651 defines Dictionaries as ordered and both the
serialization and, for signed fields, the signature depend on that order.
