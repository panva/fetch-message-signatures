#!/usr/bin/env bash
set -euo pipefail

node --run docs

examples_dir='.docs-examples'
rm -rf "${examples_dir}"
mkdir "${examples_dir}"
trap 'rm -rf "${examples_dir}"' EXIT

extract_typescript_blocks() {
  local markdown_file="$1"
  local output_name
  local blocks_file
  output_name="$(printf '%s' "${markdown_file}" | tr '/.' '__')"
  blocks_file="${examples_dir}/${output_name}.json"

  pandoc -i "${markdown_file}" -t json |
    jq -a '
      .blocks[]
      | select(.t == "CodeBlock")
      | select(.c[0][1] | index("ts"))
      | select((.c[0][1] | index("no-check")) | not)
      | .c[1]
    ' |
    jq -s >"${blocks_file}"

  node --input-type=module - "${blocks_file}" "${examples_dir}" "${output_name}" <<'EOF'
    import fs from 'node:fs'

    const [, , blocksFile, examplesDir, outputName] = process.argv
    const blocks = JSON.parse(fs.readFileSync(blocksFile, 'utf8'))

    blocks.forEach((source, index) => {
      let code = source.replaceAll("from 'fetch-message-signatures'", "from '../index.ts'")
      if (!/import\s+\*\s+as\s+FetchSig\s+from/.test(code)) {
        code = `import * as FetchSig from '../index.ts'\n\n${code}`
      }
      fs.writeFileSync(`${examplesDir}/${outputName}_${index}.ts`, `${code}\n`)
    })
EOF

  rm "${blocks_file}"
}

while IFS= read -r markdown_file; do
  extract_typescript_blocks "${markdown_file}"
done < <(find README.md guides docs -type f -name '*.md' -print | sort)

npx tsc -p tsconfig.docs.json
