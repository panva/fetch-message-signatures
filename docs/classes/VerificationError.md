# Class: VerificationError

An HTTP message signature verification failure.

Branch on [code](#code), not `message`, which is diagnostic and may change. Failures originating in
a verifier factory, verifier implementation, or application policy preserve the original
exception as `cause`.

A verifier factory may throw this with `unknown_key` when a claimed key cannot be resolved, or
with `algorithm_unsupported` when it cannot verify the selected algorithm. Other factory
exceptions become `verification_failed`, so an unavailable key service is not mistaken for an
unknown key.

## Extends

- `Error`

## Constructors

### Constructor

> **new VerificationError**(`code`, `message`, `options?`): `VerificationError`

#### Parameters

| Parameter | Type |
| :------ | :------ |
| `code` | [`VerificationErrorCode`](../type-aliases/VerificationErrorCode.md) |
| `message` | `string` |
| `options?` | `ErrorOptions` |

#### Returns

`VerificationError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: [`VerificationErrorCode`](../type-aliases/VerificationErrorCode.md)
