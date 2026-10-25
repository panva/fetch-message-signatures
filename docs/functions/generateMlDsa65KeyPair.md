# Function: generateMlDsa65KeyPair()

> **generateMlDsa65KeyPair**(`extractable?`): `Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

Generates an ML-DSA-65 key pair for the `ml-dsa-65` HTTP Message Signatures algorithm.

Requires a Web Cryptography implementation that supports `ML-DSA-65`. The generated public key is
represented by Web Cryptography's `CryptoKey` and is always extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |

## Returns

`Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

A randomly generated signing and verification key pair.

## Example

Generate a pair and turn it into the sender and recipient providers.

```ts
const { privateKey, publicKey } = await FetchSig.generateMlDsa65KeyPair()

const signer = FetchSig.mlDsa65Signer(privateKey)
const verifier = FetchSig.mlDsa65Verifier(publicKey)
```

## See

https://c2sp.org/httpsig-pq@v1.0.1
