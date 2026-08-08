# Function: verify()

> **verify**(`message`, `options`): `Promise`<[`VerifiedSignature`](../interfaces/VerifiedSignature.md)>

Verifies and applies explicit application policy to one HTTP message signature.

The function throws on parse, policy, context, key-selection, algorithm, or cryptographic
failure. When multiple signatures are present, callers must select a label explicitly.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | `Request` ∣ `Response` |
| `options` | [`VerifyOptions`](../interfaces/VerifyOptions.md) |

## Returns

`Promise`<[`VerifiedSignature`](../interfaces/VerifiedSignature.md)>

## Examples

Verification needs all three of a key-resolving verifier factory, an explicit policy, and the
cryptographic check. There is no mode that accepts any cryptographically valid signature.

```ts
declare const request: Request
declare const verifier: FetchSig.VerifierFactory

const verified = await FetchSig.verify(request, {
  verifier,
  policy: {
    // The exact components the application relies on, matched with their parameters.
    requiredComponents: ['@method', '@authority', '@path', 'content-digest'],
    requiredParameters: ['created', 'keyid', 'nonce'],
    algorithms: ['ed25519'],
    maxAge: 60,
    clockSkew: 5,
    async validate(signature, context) {
      // Runs only after the signature is cryptographically valid, so the nonce is authentic.
      const nonce = FetchSig.getSignatureParameter(signature, 'nonce')
      if (typeof nonce !== 'string') {
        throw new Error('A nonce is required')
      }
      await claimNonceOnce(nonce, context.message)
    },
  },
})

declare function claimNonceOnce(nonce: string, message: Request | Response): Promise<void>

// ed25519 [ [ 'created', 1735689600 ], [ 'keyid', 'client-key' ], [ 'nonce', '…' ] ]
console.log(verified.algorithm, verified.parameters)
```

Verify a response and bind it to the request that produced it. Without the related request, a
signature covering `;req` components cannot be reproduced and verification fails.

```ts
declare const sentRequest: Request
declare const response: Response
declare const verifier: FetchSig.VerifierFactory

await FetchSig.verify(response, {
  request: sentRequest,
  verifier,
  policy: {
    requiredComponents: [
      '@status',
      FetchSig.component('@method', [['req', true]]),
      FetchSig.component('@authority', [['req', true]]),
      FetchSig.component('@path', [['req', true]]),
    ],
    requiredParameters: ['created', 'keyid'],
    algorithms: ['ed25519'],
    maxAge: 60,
  },
})
```
