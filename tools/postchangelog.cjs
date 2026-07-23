// Normalizes the release headings that commit-and-tag-version writes into CHANGELOG.md, so that
// every release is an h2 and tools/release-notes.cjs can find any of them the same way.
//
// Three shapes need fixing:
//
//   "### [0.1.1]..."  patch releases are emitted one level deeper than minor and major releases
//   "# 0.1.0 (date)"  the first release has no previous tag to compare against, so it gets no
//                     link and an h1, which would otherwise outrank the "# Changelog" title
//   a heading placed directly under the preceding line, with no blank line between them

const { readFileSync, writeFileSync } = require('fs')

const CHANGELOG = './CHANGELOG.md'

/** Rewrites every release heading to "## " and guarantees a blank line above it. */
function formatChangelog(changelog) {
  return changelog
    .replace(/^#{1,3} (?=\[?\d+\.\d+\.\d+)/gm, '## ')
    .replace(/([^\n])\n(?=## \[?\d+\.\d+\.\d+)/g, '$1\n\n')
}

function main() {
  writeFileSync(CHANGELOG, formatChangelog(readFileSync(CHANGELOG, 'utf8')))
}

module.exports = { formatChangelog }

if (require.main === module) {
  main()
}
