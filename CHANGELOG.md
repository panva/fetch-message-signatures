# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## [0.1.1](https://github.com/panva/fetch-message-signatures/compare/v0.1.0...v0.1.1) (2026-09-05)

### Fixes

* preserve leading question marks in query parameter names ([f4e34cb](https://github.com/panva/fetch-message-signatures/commit/f4e34cb05ee57e635d542737cb47c623717b82f9))
* preserve raw descriptor paths in signature bases ([03c772d](https://github.com/panva/fetch-message-signatures/commit/03c772de7e48984205ae8deda92cdde68f6f060e))

### Refactor

* share fetch signing and verification lifecycle helpers ([ffd8d13](https://github.com/panva/fetch-message-signatures/commit/ffd8d1326ebfbfcd6e0610400a24f35eb05337e8))

### Performance

* improve tree shaking of module initializers ([baebf9f](https://github.com/panva/fetch-message-signatures/commit/baebf9f5c4b264b9c66535bd7e0f22cbf0883f6f))

## [0.1.0](https://github.com/panva/fetch-message-signatures/compare/v0.0.7...v0.1.0) (2026-08-09)

### ⚠ BREAKING CHANGES

* remove provider discriminators
* replace field adapters with message snapshots
* require ordinary configuration records

### Features

* accept a plain object as the message ([ea1252e](https://github.com/panva/fetch-message-signatures/commit/ea1252efcca39a4cabf46e34bb58ea61f399ee07))
* add stable verification error codes ([b036fdb](https://github.com/panva/fetch-message-signatures/commit/b036fdb0ddf9635abcf33b595cf4740bb7566ceb))

### Refactor

* remove provider discriminators ([cd7dd6b](https://github.com/panva/fetch-message-signatures/commit/cd7dd6b857845ee26905323c0321962a1feb4af0))
* replace field adapters with message snapshots ([5d1752b](https://github.com/panva/fetch-message-signatures/commit/5d1752bebc6c21b967e0835ce507dd03d162494d))
* require ordinary configuration records ([414a88b](https://github.com/panva/fetch-message-signatures/commit/414a88b311ce07e478539cd59cdeea4d01205195))

## [0.0.7](https://github.com/panva/fetch-message-signatures/compare/v0.0.6...v0.0.7) (2026-08-08)

### Refactor

* detect target URI credentials with the URL parser ([066681c](https://github.com/panva/fetch-message-signatures/commit/066681c2e063b032be23e6484437328250f995de))

### Performance

* build a signature base with less work ([8e528ac](https://github.com/panva/fetch-message-signatures/commit/8e528ac40a9b212bae4fec3ba55c84dac2cae900))

## [0.0.6](https://github.com/panva/fetch-message-signatures/compare/v0.0.5...v0.0.6) (2026-08-08)

### Fixes

* refuse to cover the signature member being produced ([deb3b1b](https://github.com/panva/fetch-message-signatures/commit/deb3b1bc109a60b7c95740d0459f3039b4ef33e0))
* validate covered component identifiers in three entry points ([46614c1](https://github.com/panva/fetch-message-signatures/commit/46614c1b6897becbbb6eadb734c28cd8e0fef3fb))

### Documentation

* cover the Structured Fields exports in the README ([5d639c8](https://github.com/panva/fetch-message-signatures/commit/5d639c86d4856806f7fd0628859030e4c8032d0d))
* lead with signing requests ([da7f180](https://github.com/panva/fetch-message-signatures/commit/da7f1808bcd250afcc26ab08449f3556355ba86b))
* stop repeating one description per overload ([342fe49](https://github.com/panva/fetch-message-signatures/commit/342fe49270ce7194770639881e35074a1ac0b1a1))

## [0.0.5](https://github.com/panva/fetch-message-signatures/compare/v0.0.4...v0.0.5) (2026-08-08)

### Features

* export the Structured Fields parser and serializer ([bd6fa88](https://github.com/panva/fetch-message-signatures/commit/bd6fa8840e093d4a17fd12a05854e2d02cae2cd7))

## [0.0.4](https://github.com/panva/fetch-message-signatures/compare/v0.0.3...v0.0.4) (2026-08-08)

### Features

* add createSignatureFields ([5d71ea6](https://github.com/panva/fetch-message-signatures/commit/5d71ea65c62ece8bb28c0b3bbc7ad70f19aea86e))
* add findComponents ([73cba2a](https://github.com/panva/fetch-message-signatures/commit/73cba2a972f0aeda251deb6a27ac59f52a3e8828))

## [0.0.3](https://github.com/panva/fetch-message-signatures/compare/v0.0.2...v0.0.3) (2026-08-08)

### Features

* add includesComponent ([5fffa9d](https://github.com/panva/fetch-message-signatures/commit/5fffa9df3ac47e0e6080008194fdfd81e9d70d02))
* add rsa-pss-sha512 and rsa-v1_5-sha256 providers ([26c2d66](https://github.com/panva/fetch-message-signatures/commit/26c2d66b9e66c4e83772acdd0035dc348f865b2b))
* let a signer or verifier return synchronously ([7fd40c3](https://github.com/panva/fetch-message-signatures/commit/7fd40c3577ae6629461f008f5bed75607e1e7641))

## [0.0.2](https://github.com/panva/fetch-message-signatures/compare/v0.0.1...v0.0.2) (2026-08-08)

### Features

* add getSignatureParameter ([8c6da82](https://github.com/panva/fetch-message-signatures/commit/8c6da82dc5e5794e3145f9da4c14b49c357aea25))
* allow a verifier factory to resolve asynchronously ([1ed9165](https://github.com/panva/fetch-message-signatures/commit/1ed9165a9919a01e8c011e718cb257483701fee0))

### Documentation

* add wrapper examples and update to docs/README.md ([f1370b8](https://github.com/panva/fetch-message-signatures/commit/f1370b85686e873769a0a1f59d5da11296197e26))

## 0.0.1 (2026-08-08)

### Features

* Implementation of RFC 9421: HTTP Message Signatures for Fetch API
