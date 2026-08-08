# Function: ed25519Verifier()

> **ed25519Verifier**(`key`): [`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ed25519`.

The message is verified directly with Ed25519, without an external pre-hash. This fixed-key
factory does not perform `keyid` lookup or authorization. Select it from trusted application
configuration when more than one verification key can be used.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Web Cryptography's `CryptoKey` for an Ed25519 public key with `verify` usage. |

## Returns

[`SynchronousVerifierFactory`](../type-aliases/SynchronousVerifierFactory.md)

## Example

Compose the fixed-key factory into an application factory that selects a trusted key by `keyid`.
This is the shape to reach for whenever more than one key can sign.

```ts
declare const publicKeys: ReadonlyMap<string, CryptoKey>

const verifier: FetchSig.VerifierFactory = (signature, context) => {
  const keyid = FetchSig.getSignatureParameter(signature, 'keyid')
  if (typeof keyid !== 'string') {
    throw new Error('A key identifier is required')
  }

  const publicKey = publicKeys.get(keyid)
  if (publicKey === undefined) {
    throw new Error('Unknown signing key')
  }

  return FetchSig.ed25519Verifier(publicKey)(signature, context)
}
```
