import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { describe, it } from 'node:test'

const require = createRequire(import.meta.url)
const { formatChangelog } = require('../tools/postchangelog.cjs') as {
  formatChangelog(changelog: string): string
}

describe('postchangelog', () => {
  it('separates adjacent linked and unlinked release headings', () => {
    const changelog = [
      '# Changelog',
      '',
      '### [1.2.3](https://example.test/v1.2.3) (2026-08-24)',
      '',
      '### Fixes',
      '',
      '* newest fix',
      '## [1.2.2](https://example.test/v1.2.2) (2026-08-23)',
      '',
      '### Features',
      '',
      '* older feature',
      '## 1.0.0 (2026-08-22)',
      '',
    ].join('\n')
    const expected = changelog
      .replace('### [1.2.3]', '## [1.2.3]')
      .replace('* newest fix\n## [1.2.2]', '* newest fix\n\n## [1.2.2]')
      .replace('* older feature\n## 1.0.0', '* older feature\n\n## 1.0.0')

    assert.equal(formatChangelog(changelog), expected)
    assert.equal(formatChangelog(expected), expected)
  })
})
