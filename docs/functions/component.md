# Function: component()

> **component**(`name`, `parameters?`): [`ParameterizedComponent`](../interfaces/ParameterizedComponent.md)

Creates a component identifier while preserving the supplied parameter order.

HTTP field names are normalized to lowercase. Derived component names are case-sensitive.

## Parameters

| Parameter | Type |
| :------ | :------ |
| `name` | `string` |
| `parameters` | [`ComponentParameters`](../type-aliases/ComponentParameters.md) |

## Returns

[`ParameterizedComponent`](../interfaces/ParameterizedComponent.md)

## Examples

A plain string is shorthand for an identifier with no parameters, so `component()` is only needed
when a component carries parameters.

```ts
const request = new Request('https://api.example/orders?page=2', {
  headers: { 'example-dictionary': 'a=1, member="two"' },
})

const base = FetchSig.createSignatureBase(request, {
  components: [
    '@method',
    FetchSig.component('@query-param', [['name', 'page']]),
    FetchSig.component('Example-Dictionary', [['key', 'member']]),
  ],
})

// "@method": GET
// "@query-param";name="page": 2
// "example-dictionary";key="member": "two"
// "@signature-params": ("@method" "@query-param";name="page" "example-dictionary";key="member")
console.log(base)
```

Parameters combine, and their order is covered by the signature. Pass ordered tuples whenever
another implementation has to reproduce the exact serialization. An object is also accepted and
keeps its property insertion order.

```ts
const request = new Request('https://api.example/orders', {
  headers: { 'example-dictionary': 'a=1, member="two"' },
})
const response = new Response('', { status: 200 })

const base = FetchSig.createSignatureBase(response, {
  request,
  components: [
    '@status',
    FetchSig.component('example-dictionary', [
      ['key', 'member'],
      ['req', true],
    ]),
  ],
})

// "@status": 200
// "example-dictionary";key="member";req: "two"
// "@signature-params": ("@status" "example-dictionary";key="member";req)
console.log(base)
```
