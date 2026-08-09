# Function: getSignatureParameter()

> **getSignatureParameter**(`signature`, `name`): [`StructuredFieldBareItem`](../type-aliases/StructuredFieldBareItem.md) ∣ `undefined`

Returns one signature metadata parameter by name, or `undefined` when the signature omits it.

The parameters are an ordered list rather than an object, because RFC 9421 covers their order in
the signature base. This looks one up without having to reproduce that shape at the call site.

A parameter read here is unauthenticated when it comes from a [VerifierFactory](../type-aliases/VerifierFactory.md), which runs
before the signature has been checked. Treat `keyid` as a lookup key into trusted configuration,
and `alg` as a claim that [VerificationPolicy.algorithms](../interfaces/VerificationPolicy.md#algorithms) still has to allow.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `signature` | `Readonly`<[`MessageSignature`](../interfaces/MessageSignature.md)> |
| `name` | `string` |

## Returns

[`StructuredFieldBareItem`](../type-aliases/StructuredFieldBareItem.md) ∣ `undefined`

## Example

Select a trusted key by the `keyid` a signature claims.

```ts
declare const publicKeys: ReadonlyMap<string, CryptoKey>

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = FetchSig.getSignatureParameter(signature, 'keyid')
  if (typeof keyid !== 'string') {
    throw new FetchSig.VerificationError('unknown_key', 'A key identifier is required')
  }

  const publicKey = publicKeys.get(keyid)
  if (publicKey === undefined) {
    throw new FetchSig.VerificationError('unknown_key', 'Unknown signing key')
  }

  return FetchSig.ed25519Verifier(publicKey)(signature, context)
}
```
