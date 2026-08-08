// Enforces that the sender, recipient, and Accept-Signature APIs stay out of each other's bundles,
// and reports what each entry point costs.
//
// The package is one module, so the split is not enforced by file layout: it holds only as long as
// nothing on one side reaches for something on the other. An application that only signs should not
// ship verification policy evaluation, and one that only verifies should not ship the signing path.
//
// Each family is detected by a string that appears exactly once in the source, in code only that
// family reaches. Those markers are self-validating: every one is asserted to be PRESENT in the
// bundle of an entry point that owns it, so rewording a message turns this check into a visible
// failure rather than a silent no-op that would then permit any bleed.
//
//   node tools/bundle-families.js            report sizes and check isolation
//   node --run check:bundles                 the same, as a script

import { build } from 'esbuild'
import { gzipSync } from 'node:zlib'
import { fileURLToPath } from 'node:url'

const INDEX = fileURLToPath(new URL('../index.js', import.meta.url))

/** A string present only in the code one family reaches. */
const FAMILIES = {
  sender: 'Invalid "signer"',
  recipient: 'Invalid "verifier"',
  accept: 'Accept-Signature',
}

/**
 * Entry points to check, with the families each is allowed to pull in.
 *
 * An entry with no families is expected to be usable on its own: the Structured Field helpers, the
 * cryptographic providers, and the parsing helpers belong to neither side.
 */
const ENTRIES = [
  { name: 'sign', families: ['sender'] },
  { name: 'createSignature', families: ['sender'] },
  { name: 'createSigningFetch', families: ['sender'] },
  { name: 'verify', families: ['recipient'] },
  { name: 'createVerifyingFetch', families: ['recipient'] },
  { name: 'createSignedFetch', families: ['sender', 'recipient'] },
  { name: 'appendAcceptSignature', families: ['accept'] },
  // Builds the field value only. It never names the field, so it pulls in no family.
  { name: 'createAcceptSignature', families: [] },
  { name: 'getSignatureRequests', families: ['accept'] },
  { name: 'signRequested', families: ['sender', 'accept'] },
  { name: 'getSignatures', families: [] },
  { name: 'getSignatureParameter', families: [] },
  { name: 'createSignatureBase', families: [] },
  { name: 'createSignatureFields', families: [] },
  { name: 'component', families: [] },
  { name: 'includesComponent', families: [] },
  { name: 'findComponents', families: [] },
  { name: 'parseStructuredField', families: [] },
  { name: 'serializeStructuredField', families: [] },
  { name: 'ed25519Signer', families: [] },
  { name: 'ed25519Verifier', families: [] },
]

/** Bundles one named export as an application would, and returns the minified output. */
async function bundleExport(name) {
  const result = await build({
    stdin: {
      contents: `export { ${name} } from ${JSON.stringify(INDEX)}\n`,
      resolveDir: fileURLToPath(new URL('.', import.meta.url)),
    },
    bundle: true,
    format: 'esm',
    target: 'esnext',
    minify: true,
    write: false,
    logLevel: 'warning',
  })
  return result.outputFiles[0].text
}

const failures = []
const rows = []

for (const { name, families } of ENTRIES) {
  const output = await bundleExport(name)
  const present = Object.entries(FAMILIES)
    .filter(([, marker]) => output.includes(marker))
    .map(([family]) => family)

  for (const family of families) {
    if (!present.includes(family)) {
      // The marker did not survive, so it no longer identifies this family and the absence checks
      // below prove nothing. Fix the marker rather than the expectation.
      failures.push(
        `${name}: marker for "${family}" (${FAMILIES[family]}) is missing from its own bundle`,
      )
    }
  }
  for (const family of present) {
    if (!families.includes(family)) {
      failures.push(`${name}: pulls in the "${family}" family, which it must not reach`)
    }
  }

  const bytes = Buffer.from(output)
  rows.push({ name, bytes: bytes.byteLength, gzip: gzipSync(bytes).byteLength, families: present })
}

const width = Math.max(...rows.map((row) => row.name.length))
// Both numbers are reported because the minified size is what a bundle report shows and the gzip
// size is what a consumer actually transfers.
for (const { name, bytes, gzip, families } of rows) {
  const min = `${(bytes / 1024).toFixed(1)} KB`.padStart(8)
  const wire = `${(gzip / 1024).toFixed(1)} KB gzip`.padStart(13)
  console.log(`  ${name.padEnd(width)}${min}${wire}  ${families.join(', ') || '-'}`)
}

if (failures.length !== 0) {
  console.error('\nBundle family isolation failed:')
  for (const failure of failures) {
    console.error(`  ${failure}`)
  }
  process.exit(1)
}

console.log('\nOK - sender, recipient, and Accept-Signature bundles stay separate')
