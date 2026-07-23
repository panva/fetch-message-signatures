import { type Application } from 'typedoc'
import { MarkdownPageEvent, MarkdownTheme, MarkdownThemeContext } from 'typedoc-plugin-markdown'

class FetchSigMarkdownTheme extends MarkdownTheme {
  // @ts-ignore TypeDoc's theme extension surface is intentionally untyped.
  getRenderContext(page) {
    const context = new MarkdownThemeContext(this, page, this.application.options)
    const typeArguments = context.partials.typeArguments
    context.partials.typeArguments = function (values, options) {
      // Hide the implementation-level backing-buffer generic from Uint8Array in the public docs.
      // @ts-ignore Reflection types do not expose a stable public shape.
      if (values[0]?.name === 'ArrayBuffer') return ''
      // @ts-ignore TypeDoc's partials are dynamically bound.
      return typeArguments.call(this, values, options)
    }

    const sources = context.partials.sources
    context.partials.sources = function (...args) {
      const source = sources.call(this, args[0])
      return `[source]${source.slice(source.indexOf(']') + 1)}`
    }

    return context
  }

  render(page: MarkdownPageEvent): string {
    return super.render(page).replaceAll(`\\|`, '∣')
  }
}

export function load(app: Application) {
  app.renderer.defineTheme('fetch-message-signatures-markdown', FetchSigMarkdownTheme)
}
