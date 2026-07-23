// Cloudflare Workers entry point for the shared suite. Bundled to test/run-workerd.bundle.js by
// test/bundle.js and embedded by test/.workerd.capnp, which `workerd test` runs.
//
// `workerd test` reports a pass when test() returns and a failure when it throws, so every failing
// test is listed in the thrown error.

import { runRegisteredTests } from './suite.ts'

export default {
  async test(): Promise<void> {
    const results = await runRegisteredTests()

    if (results.failed !== 0) {
      const failures = results.tests
        .filter((entry) => entry.status === 'failed')
        .map((entry) => `  ${entry.name}\n    ${entry.error}`)
        .join('\n')
      throw new Error(`${results.failed} of ${results.total} tests failed in workerd:\n${failures}`)
    }

    console.log(`workerd: ${results.passed} tests passed`)
  },
}
