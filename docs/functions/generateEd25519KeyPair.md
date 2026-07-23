# Function: generateEd25519KeyPair()

> **generateEd25519KeyPair**(`extractable?`): `Promise`<`CryptoKeyPair`>

Generates an Ed25519 key pair for the RFC 9421 `ed25519` algorithm.

The generated public key is represented by Web Cryptography's `CryptoKey` and is always
extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |

## Returns

`Promise`<`CryptoKeyPair`>

A randomly generated signing and verification key pair.

## Example

Publish the public key in a format a peer can import, and keep the private key non-extractable.

```ts
const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()

const signer = FetchSig.ed25519Signer(privateKey)
const jwk = await crypto.subtle.exportKey('jwk', publicKey)

// { kty: 'OKP', crv: 'Ed25519', x: '…' }
console.log(jwk)
```
