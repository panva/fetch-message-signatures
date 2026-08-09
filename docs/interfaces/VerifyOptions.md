# Interface: VerifyOptions

Recipient options.

## Contents

- [Extends](#extends)
- [Properties](#properties)
  - [policy](#policy)
  - [verifier](#verifier)
  - [label?](#label)
  - [request?](#request)
  - [structuredFields?](#structuredfields)

## Extends

- [`SignatureContext`](SignatureContext.md)

## Properties

### policy

> `readonly` **policy**: [`VerificationPolicy`](VerificationPolicy.md)

***

### verifier

> `readonly` **verifier**: [`VerifierFactory`](../type-aliases/VerifierFactory.md)

***

### label?

> `readonly` `optional` **label?**: `string`

The signature label to verify. Required when the message contains more than one signature.
Labels are not signed and MUST NOT be assigned application semantics.

***

### request?

> `readonly` `optional` **request?**: [`SignableRequest`](../type-aliases/SignableRequest.md)

The exact request that triggered a response. Required when a response signature uses `;req`.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`request`](SignatureContext.md#request)

***

### structuredFields?

> `readonly` `optional` **structuredFields?**: `Readonly`<`Record`<`string`, [`StructuredFieldType`](../type-aliases/StructuredFieldType.md)>>

Structured Field top-level types, indexed by lowercase HTTP field name.

#### Inherited from

[`SignatureContext`](SignatureContext.md).[`structuredFields`](SignatureContext.md#structuredfields)
