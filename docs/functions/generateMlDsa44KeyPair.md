# Function: generateMlDsa44KeyPair()

> **generateMlDsa44KeyPair**(`extractable?`): `Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

Generates an ML-DSA-44 key pair for the `ml-dsa-44` HTTP Message Signatures algorithm.

Requires a Web Cryptography implementation that supports `ML-DSA-44`. The generated public key is
represented by Web Cryptography's `CryptoKey` and is always extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `extractable?` | `boolean` | Whether the private key can be exported. Defaults to `false`. |

## Returns

`Promise`<[`CryptoKeyPair`](../interfaces/CryptoKeyPair.md)>

A randomly generated signing and verification key pair.

## See

https://c2sp.org/httpsig-pq@v1.0.1
