// Bundles the portable part of the test suite for the runtimes that cannot load it directly:
// browsers and Cloudflare Workers.
//
//   node test/runners/bundle.js browser    -> test/runners/browser-suite.bundle.js
//   node test/runners/bundle.js workerd    -> test/runners/run-workerd.bundle.js
//
// Two specifiers are redirected while bundling:
//
//   node:test, node:assert/strict  -> test/harness.ts, since neither runtime has them
//   ../index.ts                    -> index.js, the artifact that actually ships
//
// Redirecting to the built index.js matters: it is produced by amaro type stripping plus comment
// removal rather than by this bundler, so it is a distinct artifact, and these two runtimes are where
// it gets exercised.

import { build } from 'esbuild'
import { fileURLToPath } from 'node:url'

const HARNESS = fileURLToPath(new URL('./harness.ts', import.meta.url))
const BUILT_INDEX = fileURLToPath(new URL('../../index.js', import.meta.url))

const TARGETS = {
  browser: { entry: 'run-browser.ts', outfile: 'browser-suite.bundle.js' },
  workerd: { entry: 'run-workerd.ts', outfile: 'run-workerd.bundle.js' },
}

/** Bundles one runner and returns the path it was written to. */
export async function bundleSuite(target) {
  const definition = TARGETS[target]
  if (definition === undefined) {
    throw new Error(
      `Unknown bundle target "${target}"; expected ${Object.keys(TARGETS).join(' or ')}`,
    )
  }

  const outfile = fileURLToPath(new URL(`./${definition.outfile}`, import.meta.url))
  await build({
    entryPoints: [fileURLToPath(new URL(`./${definition.entry}`, import.meta.url))],
    outfile,
    bundle: true,
    format: 'esm',
    target: 'esnext',
    logLevel: 'warning',
    // The package declares "sideEffects": false so that applications can tree-shake the module.
    // That declaration covers test/ too, and without this the bundler would drop every test file,
    // since importing one only registers tests and produces no bindings. Nothing here is shipped, so
    // giving up dead-code elimination in the bundle costs nothing.
    ignoreAnnotations: true,
    plugins: [
      {
        name: 'suite-under-test',
        setup(pluginBuild) {
          pluginBuild.onResolve({ filter: /^node:(test|assert\/strict)$/ }, () => ({
            path: HARNESS,
          }))
          pluginBuild.onResolve({ filter: /^\.\.\/index\.ts$/ }, () => ({ path: BUILT_INDEX }))
        },
      },
    ],
  })
  return outfile
}

if (import.meta.filename === process.argv[1]) {
  console.log(`Bundled ${await bundleSuite(process.argv[2])}`)
}
