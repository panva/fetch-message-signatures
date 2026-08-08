// Creates the GitHub Release for the tag at HEAD, using the CHANGELOG.md section for that version as
// the release notes.
//
// The notes are read from the changelog by heading rather than from the release commit's diff, so
// that they do not depend on how that commit happens to be shaped.

const fs = require('fs')
const { execFileSync } = require('child_process')

/**
 * Returns the CHANGELOG.md body for one version.
 *
 * Every release is already normalized to an h2 by `postchangelog.cjs` when this runs, but the link
 * that follows the version is optional: the first release of a package has no previous tag to
 * compare against, so it is written as "## 0.1.0 (date)" rather than "## [0.1.0](compare) (date)".
 */
function extractReleaseNotes(changelog, version) {
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const heading = new RegExp(`^## \\[?${escaped}(?:\\]|\\s)`, 'm')
  const match = heading.exec(changelog)

  if (match === null) {
    throw new Error(`could not find a "## ${version}" heading in CHANGELOG.md`)
  }

  const notesStart = changelog.indexOf('\n', match.index) + 1
  const nextRelease = /^## \[?\d+\.\d+\.\d+/m.exec(changelog.slice(notesStart))
  return (
    nextRelease === null
      ? changelog.slice(notesStart)
      : changelog.slice(notesStart, notesStart + nextRelease.index)
  ).trim()
}

function main() {
  const tag = execFileSync('git', ['tag', '--points-at', 'HEAD'], { encoding: 'utf8' }).trim()
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
    throw new Error(`unexpected release tag: ${tag || '(none)'}`)
  }

  const notes = extractReleaseNotes(fs.readFileSync('CHANGELOG.md', 'utf8'), tag.replace(/^v/, ''))

  fs.writeFileSync('notes.md', notes)
  execFileSync(
    'gh',
    [
      'release',
      'create',
      tag,
      '-F',
      'notes.md',
      '--title',
      tag,
      '--discussion-category',
      'Releases',
    ],
    { stdio: 'inherit' },
  )
}

module.exports = { extractReleaseNotes }

if (require.main === module) {
  main()
}
