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

execFileSync(process.execPath, ['--check', './index.js'], { stdio: 'inherit' })

console.log(`index.js: ${format(before.raw)} → ${format(after.raw)} (${format(after.gzip)} gzip)`)

function cleanJavaScript(code) {
  code = code.replace(/^[ \t]*\/\*\*[\s\S]*?\*\/[ \t]*$/gm, (match) => {
    return '\n'.repeat((match.match(/\n/g) || []).length)
  })
  code = code.replace(/^[ \t]*\/\/.*$/gm, '')
  code = code.replace(/^(.+?)\/\/.*$/gm, (_match, source) => source.trimEnd())
  return code.replace(/^[ \t]+$/gm, '')
}

function sizes(value) {
  const contents = Buffer.from(value)
  return { raw: contents.byteLength, gzip: gzipSync(contents).byteLength }
}

function format(bytes) {
  return `${(bytes / 1024).toFixed(2)} KB`
}
