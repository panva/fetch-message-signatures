const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { describe, it } = require('node:test')
const { runInNewContext } = require('node:vm')
const amaro = require('amaro')
const { transformSync } = require('esbuild')
const ts = require('typescript')
const cleanJavaScript = require('./clean-javascript.cjs')

function evaluate(code) {
  const context = {}
  runInNewContext(code, context)
  return context.result
}

function tokenPositions(code) {
  const source = ts.createSourceFile(
    'input.js',
    code,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.JS,
  )
  const positions = []
  function visit(node) {
    if (ts.isJSDoc(node)) {
      return
    }
    if (ts.isToken(node)) {
      const { line, character } = source.getLineAndCharacterOfPosition(node.getStart(source))
      positions.push([node.kind, node.getText(source), line, character])
      return
    }
    for (const child of node.getChildren(source)) {
      visit(child)
    }
  }
  visit(source)
  return positions
}

describe('JavaScript comment cleanup', () => {
  it('preserves emitted token text, lines, and columns without reprinting', () => {
    const lines = [
      '/** ordinary-sentinel',
      ' * documentation',
      ' */',
      'const value/* ordinary-sentinel */= 42',
      '',
      'export { value } // ordinary-sentinel',
      '',
    ]
    for (const newline of ['\n', '\r\n', '\r', '\u2028', '\u2029']) {
      const input = lines.join(newline)
      const output = cleanJavaScript(input)
      assert.doesNotMatch(output, /ordinary-sentinel/)
      assert.deepEqual(tokenPositions(output), tokenPositions(input))
      assert.deepEqual(
        output.match(/\r\n|[\r\n\u2028\u2029]/g),
        input.match(/\r\n|[\r\n\u2028\u2029]/g),
      )
    }
  })

  it('preserves source positions throughout the strip-only emitted module', () => {
    const source = readFileSync(require.resolve('../index.ts'), 'utf8')
    const input = amaro.transformSync(source, { mode: 'strip-only' }).code
    const output = cleanJavaScript(input)
    assert.deepEqual(tokenPositions(output), tokenPositions(input))
    assert.equal(output.split('\n').length, source.split('\n').length)
  })

  it('rejects syntactically invalid input', () => {
    assert.throws(() => cleanJavaScript('const value ='), SyntaxError)
  })

  for (const [name, source] of [
    ['quoted URLs', 'globalThis.result = "https://example.com/path"'],
    ['quoted comment markers', 'globalThis.result = "/* literal */ // literal"'],
    ['regular expression character classes', 'globalThis.result = /[//]/.test("/")'],
    [
      'escaped regular expression delimiters',
      String.raw`globalThis.result = /https?:\/\/[a-z/]+/.test("https://example/path")`,
    ],
    ['multiline templates', 'globalThis.result = `https://example.com\n// literal\n/* literal */`'],
    ['whitespace-only template lines', 'globalThis.result = `first\n   \n\t\nlast`'],
    [
      'nested template expressions',
      'globalThis.result = `first ${1 /* ordinary-sentinel */ + 2} // literal\n${`nested // text`}`',
    ],
    ['tagged templates', 'globalThis.result = String.raw`https://example.com\\npath`'],
    [
      'token separation',
      'function value() { return/* ordinary-sentinel */42 }\nglobalThis.result = value()',
    ],
    [
      'automatic semicolon insertion',
      'function value() { return /* ordinary-sentinel\n*/ 42 }\nglobalThis.result = value()',
    ],
  ]) {
    it(`preserves ${name}`, () => {
      const input = `/** ordinary-sentinel */\n${source}\n// ordinary-sentinel`
      const output = cleanJavaScript(input)
      assert.equal(evaluate(output), evaluate(input))
      assert.doesNotMatch(output, /ordinary-sentinel/)
    })
  }

  it('preserves pure annotations for downstream tree shaking', () => {
    const output = cleanJavaScript(
      'const unused = /* @__PURE__ */ globalThis.sideEffect();\nexport const kept = 1',
    )
    assert.match(output, /\/\* @__PURE__ \*\//)
    const bundled = transformSync(output, { format: 'esm', treeShaking: true }).code
    assert.doesNotMatch(bundled, /sideEffect/)
    assert.match(bundled, /kept/)
  })
})
