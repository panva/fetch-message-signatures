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

Documentation examples are compiled as part of their check. It requires `pandoc` and `jq`:

```sh
node --run test:docs
```

Run `node --run format` before submitting changes. Generated API documentation under `docs/` is
committed and must match `index.ts`; regenerate it with `node --run docs`.

Keep runtime code in `index.ts`. The package intentionally exposes named functions from one module
so consumers can tree-shake unused operations. Cryptography and key management remain behind the
provider interfaces.

## Discussions

Be clear and transparent, keep discussion in English and on topic, and maintain a professional and
respectful tone.

Security vulnerabilities must be reported privately under the process in [SECURITY.md][security],
not in a public issue or discussion.

## Maintainer releases

Releases use [commit-and-tag-version][commit-and-tag-version] with `.versionrc.json`. From a clean
working tree, run the versioning tool and push its commit and tag. The prerelease hook formats and
generates documentation, runs the tests and build, and force-adds the otherwise ignored distribution
artifacts to the tagged commit.

Tags matching `v1.<minor>.<patch>` start `.github/workflows/release.yml`. The workflow:

1. stages the package through npm trusted publishing;
2. moves `v1.x` to the tagged release commit;
3. removes generated distribution artifacts again on `main`; and
4. creates a GitHub release and a discussion from the new changelog section.

Before enabling it:

- manually publish a placeholder package because npm cannot stage a brand-new package;
- configure npm trusted publishing for `panva/fetch-message-signatures`, workflow filename
  `release.yml`, with staged publishing allowed;
- enable GitHub Discussions with `q-a`, `ideas`, and `Releases` categories;
- create the `triage` label; and
- allow the workflow token to update `main` and `v1.x` under the repository's branch rules.

After the workflow succeeds, inspect and approve the staged npm package with 2FA.

[coc]: https://github.com/panva/fetch-message-signatures/blob/main/CODE_OF_CONDUCT.md
[commit-and-tag-version]: https://github.com/absolute-version/commit-and-tag-version
[discussions]: https://github.com/panva/fetch-message-signatures/discussions
[security]: https://github.com/panva/fetch-message-signatures/blob/main/SECURITY.md
