# Function: getSignatures()

> **getSignatures**(`message`): readonly [`MessageSignature`](../interfaces/MessageSignature.md)\[]

Parses and pairs every signature carried by a message, so that an application can choose which
label to verify.

Returns an empty array when the message carries neither field. Throws when the two fields do not
pair up: one present without the other, a repeated label, or a label in one field that is missing
from the other. Pairing is checked across the whole message, so one malformed member makes the
message unusable rather than yielding the remaining signatures.

This reports what a message claims. Nothing here is authenticated until [verify](verify.md) succeeds.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `message` | [`SignableRequest`](../type-aliases/SignableRequest.md) ∣ [`SignableResponse`](../type-aliases/SignableResponse.md) |

## Returns

readonly [`MessageSignature`](../interfaces/MessageSignature.md)\[]

## Example

Decide which label to verify, then verify it. Pick the label from trusted local configuration - a
label is an unsigned Dictionary key and cannot stand for a role or an identity.

```ts
declare const message: Request
declare const verifier: FetchSig.VerifierFactory

// application [ [ 'created', 1735689600 ], [ 'keyid', 'client-key' ] ]
// audit [ [ 'created', 1735689600 ], [ 'keyid', 'audit-key' ] ]
for (const signature of FetchSig.getSignatures(message)) {
  console.log(signature.label, signature.parameters)
}

await FetchSig.verify(message, {
  label: 'application',
  verifier,
  policy: {
    requiredComponents: ['@method', '@authority', '@path'],
    requiredParameters: ['created', 'keyid'],
    algorithms: ['ed25519'],
    maxAge: 60,
  },
})
```
