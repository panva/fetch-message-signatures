#!/bin/bash
# Type-checks the EMITTED index.d.ts standalone - index.ts is not involved - under the module
# resolution modes and lib configurations consumers actually use.
#
# The declarations are what ships, so this is the only place a consumer-visible type problem shows up
# before a consumer hits it: an internal type leaking into the public surface, a resolution mode that
# cannot load the package, or a NEW dependency on an ambient global that a given runtime's lib does
# not declare.
set -e

TSC="./node_modules/.bin/tsc"
BASE="--noEmit --ignoreConfig --strict --skipLibCheck false --target esnext"
ENTRY="index.d.ts"

if [ ! -f "$ENTRY" ]; then
  echo "$ENTRY not found - run 'node --run build' first" >&2
  exit 1
fi

run() {
  echo "  $*"
  # shellcheck disable=SC2086
  $TSC $BASE "$@" $ENTRY
}

echo "module resolution modes"
run --module preserve --moduleResolution bundler --lib esnext,dom,dom.iterable
run --module node16 --moduleResolution node16 --lib esnext,dom,dom.iterable
run --module nodenext --moduleResolution nodenext --lib esnext,dom,dom.iterable
run --module commonjs --moduleResolution node10 --ignoreDeprecations 6.0 --lib esnext,dom,dom.iterable

echo "supported consumer lib configurations"
# Browsers, Deno, Bun, Cloudflare Workers: DOM lib, no @types/node.
run --module preserve --moduleResolution bundler --lib esnext,dom,dom.iterable --typeRoots /nonexistent
# Node.js: @types/node, no DOM lib. @types/node declares a global `CryptoKey` VALUE but no global
# `CryptoKey` TYPE, and no `CryptoKeyPair` at all, so the published types must not depend on either
# being declared as a type by the host.
run --module nodenext --moduleResolution nodenext --lib esnext --types node

# Neither the DOM lib nor @types/node. The published types are not self-contained here - this package
# is an extension of Fetch and genuinely needs Request and Response - but the exact set of ambient
# globals they depend on is a contract with consumers. Pin it, so that a new dependency shows up here
# rather than in someone's build.
#
# Notably CryptoKey and CryptoKeyPair must NOT appear: they are resolved from the host structurally,
# so that a Node.js consumer without the DOM lib still gets checked types rather than an error.
echo "ambient globals depended on with a bare lib"
EXPECTED="Headers Request Response"
# shellcheck disable=SC2086
ACTUAL=$(
  $TSC $BASE --module preserve --moduleResolution bundler --lib esnext \
    --typeRoots /nonexistent $ENTRY 2>&1 |
    sed -n "s/.*error TS2304: Cannot find name '\([A-Za-z0-9_]*\)'.*/\1/p" | sort -u | tr '\n' ' ' | xargs
)
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "  FAIL: the ambient globals the published types depend on changed" >&2
  echo "    expected: $EXPECTED" >&2
  echo "    actual:   $ACTUAL" >&2
  exit 1
fi
echo "  $ACTUAL"

echo "OK"
