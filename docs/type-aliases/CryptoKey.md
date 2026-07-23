# Type Alias: CryptoKey

> **CryptoKey** = *typeof* `globalThis` *extends* `object` ? `Extract`<`R`, { `type`: `string`; }> : [`CryptoKeyStructuralFallback`](../interfaces/CryptoKeyStructuralFallback.md)

A Web Cryptography key, resolved from the host runtime.

The host's own `CryptoKey` type is aliased whenever one is declared, so keys flow freely to and
from Web Cryptography's `SubtleCrypto` APIs and this package never introduces a competing nominal
type. It is resolved through `globalThis` rather than named directly because not every supported
configuration declares a `CryptoKey` **type**: `@types/node` declares only the constructor value,
so a Node.js consumer compiling with `"lib": ["esnext"]` and no DOM lib would otherwise get a
type error from these declarations. Such a consumer gets [CryptoKeyStructuralFallback](../interfaces/CryptoKeyStructuralFallback.md)
instead, which is still checked.
