# Function: generateEcdsaP384Sha384KeyPair()

> **generateEcdsaP384Sha384KeyPair**(`extractable?`): `Promise`<`CryptoKeyPair`>

Generates an ECDSA P-384 key pair for the RFC 9421 `ecdsa-p384-sha384` algorithm.

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

A complete P-384 round trip, signing then verifying the same request.

```ts
const { privateKey, publicKey } = await FetchSig.generateEcdsaP384Sha384KeyPair()

const signed = await FetchSig.sign(new Request('https://api.example/orders'), {
  signer: FetchSig.ecdsaP384Sha384Signer(privateKey),
  components: ['@method', '@authority', '@path'],
  parameters: [['alg', 'ecdsa-p384-sha384']],
})

const verified = await FetchSig.verify(signed, {
  verifier: FetchSig.ecdsaP384Sha384Verifier(publicKey),
  policy: {
    requiredComponents: ['@method', '@authority', '@path'],
    requiredParameters: ['created', 'alg'],
    algorithms: ['ecdsa-p384-sha384'],
    maxAge: 60,
  },
})

// sig1 ecdsa-p384-sha384
console.log(verified.label, verified.algorithm)
```
