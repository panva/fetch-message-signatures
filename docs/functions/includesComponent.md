# Function: includesComponent()

> **includesComponent**(`components`, `identifier`): `boolean`

Reports whether a list of component identifiers contains one particular identifier.

Both sides are normalized first, so a string and the equivalent [component](component.md) call match, HTTP
field names compare case-insensitively, and component parameters are compared as an unordered
set. The complete identifier has to match: `"@authority"` and `FetchSig.component('@authority',
{req: true})` are different components, and only the exact one is found.

The list is not required to be a valid covered component list, so an identifier that arrived on
the wire returns `false` rather than throwing. The identifier being looked for comes from the
application and is validated.

Use this in a [VerificationPolicy.validate](../interfaces/VerificationPolicy.md#validate) callback for a coverage rule
[VerificationPolicy.requiredComponents](../interfaces/VerificationPolicy.md#requiredcomponents) cannot express, such as requiring one of two
components or requiring a component only when the message carries a particular field. Comparing
names alone would treat `"@authority"` and `"@authority";req` as the same component.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `components` | readonly [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md)\[] | Identifiers to search, such as [MessageSignature.components](../interfaces/MessageSignature.md#components) or a covered component list an application is about to sign. |
| `identifier` | [`ComponentIdentifier`](../type-aliases/ComponentIdentifier.md) | The identifier to look for. |

## Returns

`boolean`

## Examples

A rule that `requiredComponents` cannot express: the signature must bind the request target
through either `@authority` or `@target-uri`.

```ts
declare const request: Request
declare const verifier: FetchSig.VerifierFactory

await FetchSig.verify(request, {
  verifier,
  policy: {
    requiredComponents: ['@method', '@path'],
    requiredParameters: ['created', 'keyid'],
    algorithms: ['ed25519'],
    validate(signature) {
      const covered = signature.components
      if (
        !FetchSig.includesComponent(covered, '@authority') &&
        !FetchSig.includesComponent(covered, '@target-uri')
      ) {
        throw new Error('The signature must cover @authority or @target-uri')
      }
    },
  },
})
```

A conditional rule: whenever the message carries a `signature-agent` field, the signature has to
cover it, so that the field cannot be added or changed in transit.

```ts
declare const signature: FetchSig.MessageSignature
declare const message: Request

if (
  message.headers.has('signature-agent') &&
  !FetchSig.includesComponent(signature.components, 'signature-agent')
) {
  throw new Error('An unsigned signature-agent field is not accepted')
}
```
