const fs = require('node:fs')
const { execFileSync } = require('node:child_process')
const { gzipSync } = require('node:zlib')
const amaro = require('amaro')

execFileSync(process.execPath, [require.resolve('typescript/bin/tsc')], { stdio: 'inherit' })

let javascript = amaro.transformSync(fs.readFileSync('./index.ts'), { mode: 'strip-only' }).code

const before = sizes(javascript)
javascript = cleanJavaScript(javascript)
fs.writeFileSync('./index.js', javascript)
const after = sizes(javascript)

// Evaluated rather than only parsed. The comment stripping below is hand-rolled, so it can produce
// a file that parses cleanly and still throws the moment it is loaded.
execFileSync(process.execPath, ['--input-type=module', '-e', "import './index.js'"], {
  stdio: 'inherit',
})

console.log(`index.js: ${format(before.raw)} → ${format(after.raw)} (${format(after.gzip)} gzip)`)

for (const required of ['./index.d.ts', './index.d.ts.map']) {
  if (!fs.existsSync(required)) {
    throw new Error(`${required} was not emitted`)
  }
}

let declarations = fs.readFileSync('./index.d.ts', 'utf8')
const declarationsBefore = sizes(declarations)
declarations = stripExamples(declarations)
fs.writeFileSync('./index.d.ts', declarations)
const declarationsAfter = sizes(declarations)

console.log(
  `index.d.ts: ${format(declarationsBefore.raw)} → ${format(declarationsAfter.raw)} (${format(declarationsAfter.gzip)} gzip)`,
)

function cleanJavaScript(code) {
  // Whole JSDoc blocks go first. A single-line `/** @see [x](https://…) */` contains a `//` inside
  // its URL, so removing inline comments first would eat the closing `*/` and leave an unterminated
  // block for the next pass to swallow along with the code after it.
  code = code.replace(/^[ \t]*\/\*\*[\s\S]*?\*\/[ \t]*$/gm, (match) => {
    return '\n'.repeat((match.match(/\n/g) || []).length)
  })
  code = code.replace(/^[ \t]*\/\/.*$/gm, '')
  code = code.replace(/^(.+?)\/\/.*$/gm, (_match, source) => source.trimEnd())
  return code.replace(/^[ \t]+$/gm, '')
}

/**
 * Removes the `@example` blocks from the emitted declarations.
 *
 * The examples are the bulk of index.d.ts and are already published in docs/ and in the index.ts
 * that ships alongside it, so an editor still reaches them through the declaration map. What an
 * editor shows on hover is the description, which is kept.
 *
 * Each block is replaced by the same number of blank lines rather than deleted, because
 * index.d.ts.map addresses this file by line and column. Only comment text is removed, so every
 * declaration stays on the line the map already points at.
 *
 * The removal runs inside one JSDoc comment at a time. A single pass over the whole file would have
 * to guess where an example ends, and would run past the end of its own comment whenever a block
 * finishes on the closing fence, taking every declaration up to the next example with it.
 */
function stripExamples(declarations) {
  return declarations.replace(/\/\*\*[\s\S]*?\*\//g, (block) => {
    if (!block.includes('@example')) {
      return block
    }
    const kept = []
    let skipping = false
    for (const line of block.split('\n')) {
      const tag = /^\s*\*\s*@(\w+)/.exec(line)
      if (tag) {
        skipping = tag[1] === 'example'
      }
      const last = /\*\/\s*$/.test(line)
      if (skipping && !last) {
        kept.push('')
        continue
      }
      kept.push(line)
    }
    return kept.join('\n')
  })
}

function sizes(value) {
  const contents = Buffer.from(value)
  return { raw: contents.byteLength, gzip: gzipSync(contents).byteLength }
}

function format(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`
}
