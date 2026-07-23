# Contributing to fetch-message-signatures

Please follow the project [Code of Conduct][coc] in all interactions.

Before proposing a pull request, discuss substantial changes in [GitHub Discussions][discussions].
This project follows the specifications it implements; changes that introduce non-standard protocol
behavior are unlikely to be accepted. Bug fixes and new features that affect wire behavior should
identify the relevant specification section and include tests for both successful and rejected
inputs.

Never include private keys, shared secrets, access tokens, production messages, or other sensitive
material in an issue, discussion, test fixture, or reproduction.

## Development

Install the exact locked dependencies:

```sh
npm clean-install
```

The principal checks are:

```sh
node --run test
node --run test:types
node --run build
node --run format:check
```

The same suite runs on the other supported runtimes, and CI runs all of them:

```sh
node --run test:bun
node --run test:deno
node --run test:workerd
```

`test:workerd` needs `workerd` on the path; install it with
`npm install --global workerd && npm link workerd`. Note that a later `npm install` prunes the link
and it has to be re-created.

The published surface is checked separately:

```sh
node --run typecheck:dist
node --run check:packaging
node --run check:bundles
```

`typecheck:dist` type-checks the emitted `index.d.ts` on its own, under the module resolution modes
and lib configurations consumers use, and pins the ambient globals it depends on. `check:packaging`
runs publint and `@arethetypeswrong/cli` over a packed tarball. `check:bundles` enforces that the
sender, recipient, and `Accept-Signature` APIs stay out of each other's bundles, and reports what
each entry point costs a consumer.

Documentation examples are compiled as part of their check. It requires `pandoc` and `jq`:

```sh
node --run test:docs
```

Browser tests use Playwright against a localhost-only fixture. Install the browser binaries and run
the complete matrix:

```sh
npx playwright install --only-shell chromium firefox webkit
node --run test:browsers
```

Set `BROWSER` to `chromium`, `firefox`, or `safari` to run one browser.

Run `node --run format` before submitting changes. Generated API documentation under `docs/` is
committed and must match `index.ts`; regenerate it with `node --run docs`.

Keep runtime code in `index.ts`. The package intentionally exposes named functions from one module
so consumers can tree-shake unused operations, and the sender, recipient, and `Accept-Signature`
paths must not reach into one another; `check:bundles` enforces that. Some duplication between them
is deliberate for the same reason. Cryptography and key management remain behind the provider
interfaces.

The vendored httpwg/structured-field-tests corpus is refreshed with `node --run fixtures`, which
rewrites the generated `test/fixtures/corpus.ts` alongside the vendored files.

## Discussions

Be clear and transparent, keep discussion in English and on topic, and maintain a professional and
respectful tone.

Security vulnerabilities must be reported privately under the process in [SECURITY.md][security],
not in a public issue or discussion.

[coc]: https://github.com/panva/fetch-message-signatures/blob/main/CODE_OF_CONDUCT.md
[discussions]: https://github.com/panva/fetch-message-signatures/discussions
[security]: https://github.com/panva/fetch-message-signatures/blob/main/SECURITY.md
