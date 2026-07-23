# Interface: CryptoKeyPair

A Web Cryptography key pair, resolved from the host runtime the same way [CryptoKey](../type-aliases/CryptoKey.md) is.

Declared structurally because no supported runtime exposes a global `CryptoKeyPair` **type** on
every configuration: the DOM lib declares one, `@types/node` does not declare one at all.

## Contents

- [Properties](#properties)
  - [privateKey](#privatekey)
  - [publicKey](#publickey)

## Properties

### privateKey

> `readonly` **privateKey**: `CryptoKey`

***

### publicKey

> `readonly` **publicKey**: `CryptoKey`
