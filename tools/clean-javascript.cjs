const ts = require('typescript')

module.exports = function cleanJavaScript(code) {
  const source = ts.createSourceFile(
    'input.js',
    code,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.JS,
  )
  if (source.parseDiagnostics.length !== 0) {
    throw new SyntaxError(
      ts.flattenDiagnosticMessageText(source.parseDiagnostics[0].messageText, '\n'),
    )
  }
  const scanner = ts.createScanner(ts.ScriptTarget.ESNext, false)
  let output = ''
  let previousEnd = 0

  function cleanTrivia(start, end) {
    const parts = []
    let position = start
    scanner.setText(code, start, end - start)
    for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
      if (
        kind !== ts.SyntaxKind.SingleLineCommentTrivia &&
        kind !== ts.SyntaxKind.MultiLineCommentTrivia
      ) {
        continue
      }
      const commentStart = scanner.getTokenPos()
      const commentEnd = scanner.getTextPos()
      const comment = code.slice(commentStart, commentEnd)
      if (/[@#]__PURE__/.test(comment)) {
        continue
      }
      parts.push(code.slice(position, commentStart), comment.replace(/[^\r\n\u2028\u2029]/g, ' '))
      position = commentEnd
    }
    parts.push(code.slice(position, end))
    return parts.join('').replace(/^[\t ]+(?=[\r\n\u2028\u2029])/gm, '')
  }

  function visit(node) {
    if (ts.isJSDoc(node)) {
      return
    }
    if (ts.isToken(node)) {
      const start = node.getStart(source)
      output += cleanTrivia(previousEnd, start) + code.slice(start, node.end)
      previousEnd = node.end
      return
    }
    for (const child of node.getChildren(source)) {
      visit(child)
    }
  }

  visit(source)
  return output
}
