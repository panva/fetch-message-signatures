// Browser entry point for the shared suite. Bundled to test/runners/browser-suite.bundle.js by
// test/runners/bundle.js and loaded by test/browser.html, which test/browser.mjs drives through
// Playwright.
//
// The driver waits for `completed` and then reads the counts and per-test results off the page.

import { runRegisteredTests } from './suite.ts'

const results = await runRegisteredTests()

Object.assign(globalThis, { fetchMessageSignaturesTestResults: { ...results, completed: true } })
