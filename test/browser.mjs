import { execFileSync, spawn } from 'node:child_process'

import { chromium, firefox, webkit } from 'playwright'

execFileSync(process.execPath, ['--run', 'build'], { stdio: 'inherit' })
execFileSync(process.execPath, ['test/runners/bundle.js', 'browser'], { stdio: 'inherit' })

const PORT = 3000
const TEST_URL = `http://127.0.0.1:${PORT}/test/browser.html`
const TIMEOUT = 180_000

const browserDefinitions = [
  { id: 'chromium', name: 'Chromium', type: chromium },
  { id: 'firefox', name: 'Firefox', type: firefox },
  { id: 'safari', name: 'Safari', type: webkit },
]

function startServer() {
  return new Promise((resolve, reject) => {
    const server = spawn(
      'npx',
      ['serve', '-l', `tcp://127.0.0.1:${PORT}`, '-n', '-L', '--no-port-switching'],
      { stdio: 'pipe' },
    )
    let settled = false

    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true
        server.kill()
        reject(new Error('Browser test server failed to start within 10 seconds'))
      }
    }, 10_000)

    server.stdout.on('data', (data) => {
      const output = data.toString()
      if (!settled && output.includes('Accepting connections')) {
        settled = true
        clearTimeout(timeout)
        resolve(server)
      }
    })

    server.stderr.on('data', (data) => {
      const output = data.toString().trim()
      if (output) {
        console.error(`Browser test server: ${output}`)
      }
    })

    server.on('error', (error) => {
      if (!settled) {
        settled = true
        clearTimeout(timeout)
        reject(error)
      }
    })

    server.on('exit', (code, signal) => {
      if (!settled) {
        settled = true
        clearTimeout(timeout)
        reject(
          new Error(
            `Browser test server exited before startup (${signal ?? `exit code ${String(code)}`})`,
          ),
        )
      }
    })
  })
}

async function runBrowserTests({ name, type }) {
  console.log(`\nTesting with ${name}...`)
  const browser = await type.launch()
  try {
    const context = await browser.newContext()
    try {
      const page = await context.newPage()
      const pageErrors = []

      page.setDefaultTimeout(TIMEOUT)
      page.on('console', (message) => {
        if (message.type() === 'error') {
          console.error(`  [${name} console.error] ${message.text()}`)
        }
      })
      page.on('pageerror', (error) => {
        pageErrors.push(error.message)
        console.error(`  [${name} page error] ${error.message}`)
      })

      await page.goto(TEST_URL, { waitUntil: 'networkidle' })
      const userAgent = await page.evaluate(() => navigator.userAgent)
      console.log(`  User Agent: ${userAgent}`)

      await page.waitForFunction(
        () => globalThis.fetchMessageSignaturesTestResults?.completed === true,
        undefined,
        { timeout: TIMEOUT },
      )
      const results = await page.evaluate(() => globalThis.fetchMessageSignaturesTestResults)

      if (!results || !Array.isArray(results.tests)) {
        throw new Error('Browser test page did not expose results')
      }
      const passedTests = results.tests.filter((test) => test.status === 'passed')
      const failedTests = results.tests.filter((test) => test.status === 'failed')
      if (
        passedTests.length + failedTests.length !== results.tests.length ||
        results.total !== results.tests.length ||
        results.passed !== passedTests.length ||
        results.failed !== failedTests.length
      ) {
        throw new Error('Browser test page exposed inconsistent results')
      }

      console.log(`  Total tests: ${results.total}`)
      console.log(`  Passed: ${results.passed}`)
      console.log(`  Failed: ${results.failed}`)

      if (failedTests.length > 0) {
        console.error(`\n  Failed tests in ${name}:`)
        for (const test of failedTests) {
          console.error(`    - ${test.name}`)
          console.error(`      ${test.error}`)
        }
      }

      return {
        name,
        success: failedTests.length === 0 && pageErrors.length === 0,
        results,
        pageErrors,
      }
    } finally {
      await context.close()
    }
  } finally {
    await browser.close()
  }
}

async function main() {
  const requested = process.env.BROWSER?.toLowerCase()
  const definitions = requested
    ? browserDefinitions.filter(({ id }) => id === requested)
    : browserDefinitions

  if (definitions.length === 0) {
    throw new Error(`Unknown browser: ${process.env.BROWSER}`)
  }

  let server
  const results = []
  try {
    console.log('Starting browser test server...')
    server = await startServer()
    console.log(`Browser test server is listening at ${TEST_URL}`)

    for (const definition of definitions) {
      try {
        results.push(await runBrowserTests(definition))
      } catch (error) {
        console.error(`\n${definition.name} failed to run:`, error)
        results.push({ name: definition.name, success: false, error })
      }
    }
  } finally {
    server?.kill()
  }

  console.log('\nBrowser test summary')
  for (const result of results) {
    console.log(`  ${result.success ? 'PASS' : 'FAIL'} ${result.name}`)
  }

  if (results.some((result) => !result.success)) {
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error('\nBrowser tests failed:', error)
  process.exitCode = 1
})
