// Tests the package that would actually be published rather than only the working-tree source.
// Every tarball is installed in isolation to catch missing files or undeclared runtime imports.
// With no tarball argument, the Node.js suite also runs against the newly emitted index.js.

import { execFileSync } from 'node:child_process'
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const [suppliedTarball, ...extraArguments] = process.argv.slice(2)
if (extraArguments.length !== 0) {
  throw new Error('expected at most one package tarball')
}
const runBehaviorTests = suppliedTarball === undefined
const expectedFiles = [
  'LICENSE.md',
  'README.md',
  'index.d.ts',
  'index.d.ts.map',
  'index.js',
  'index.ts',
  'package.json',
]

function run(command, args, cwd = root) {
  execFileSync(command, args, { cwd, stdio: 'inherit' })
}

function createTarball(destination) {
  run(npm, ['pack', '--pack-destination', destination])
  const tarballs = readdirSync(destination).filter((entry) => entry.endsWith('.tgz'))
  if (tarballs.length !== 1) {
    throw new Error(`npm pack produced ${tarballs.length} tarballs`)
  }
  return join(destination, tarballs[0])
}

function listFiles(directory, prefix = '') {
  const files = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      files.push(...listFiles(join(directory, entry.name), relative))
    } else {
      files.push(relative)
    }
  }
  return files
}

const staging = mkdtempSync(join(tmpdir(), 'fetch-message-signatures-dist-'))

try {
  let tarball
  if (runBehaviorTests) {
    run(npm, ['run', 'build'])
    tarball = createTarball(staging)
  } else {
    tarball = resolve(root, suppliedTarball)
  }

  // Nothing from this repository is on the resolution path, and devDependencies are omitted.
  const isolated = join(staging, 'isolated')
  mkdirSync(isolated)
  writeFileSync(
    join(isolated, 'package.json'),
    JSON.stringify({ name: 'isolated', private: true, type: 'module' }),
  )
  run(
    npm,
    ['install', '--install-strategy=nested', '--omit=dev', '--no-audit', '--no-fund', tarball],
    isolated,
  )
  writeFileSync(
    join(isolated, 'smoke.mjs'),
    `import * as api from 'fetch-message-signatures'
for (const name of ['createSignature', 'sign', 'verify']) {
  if (typeof api[name] !== 'function') throw new Error(\`missing export \${name}\`)
}
`,
  )
  const installed = join(isolated, 'node_modules', 'fetch-message-signatures')
  const actualFiles = listFiles(installed).sort()
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(
      `packed files differ\nexpected: ${expectedFiles.join(', ')}\nactual:   ${actualFiles.join(', ')}`,
    )
  }

  const sourceManifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  const packedManifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'))
  if (
    packedManifest.name !== sourceManifest.name ||
    packedManifest.version !== sourceManifest.version
  ) {
    throw new Error('the package tarball does not match the checked-out package name and version')
  }
  if (
    !runBehaviorTests &&
    process.env.GITHUB_REF_NAME !== undefined &&
    process.env.GITHUB_REF_NAME !== `v${packedManifest.version}`
  ) {
    throw new Error(
      `release tag ${process.env.GITHUB_REF_NAME} does not match ${packedManifest.name}@${packedManifest.version}`,
    )
  }

  console.log(`validated ${basename(tarball)} containing ${actualFiles.join(', ')}`)
  run(process.execPath, ['smoke.mjs'], isolated)

  if (runBehaviorTests) {
    // The tests import ../index.ts. Put the published JavaScript at that path so their behavior pass
    // exercises the stripped runtime without maintaining a second suite or rewriting test sources.
    const work = join(staging, 'work')
    mkdirSync(work)
    cpSync(join(root, 'test'), join(work, 'test'), { recursive: true })
    cpSync(join(installed, 'index.js'), join(work, 'index.js'))
    cpSync(join(installed, 'index.js'), join(work, 'index.ts'))
    writeFileSync(join(work, 'package.json'), '{"private":true,"type":"module"}\n')
    symlinkSync(
      join(root, 'node_modules'),
      join(work, 'node_modules'),
      process.platform === 'win32' ? 'junction' : 'dir',
    )

    const tests = readdirSync(join(work, 'test'))
      .filter((entry) => entry.endsWith('.ts'))
      .sort()
      .map((entry) => join('test', entry))
    run(process.execPath, ['--test', '--no-warnings', ...tests], work)
  }
} finally {
  rmSync(staging, { recursive: true, force: true })
}
