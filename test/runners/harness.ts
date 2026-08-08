// A minimal stand-in for `node:test` and `node:assert/strict`, used only when the suite is bundled
// for a runtime that has neither: browsers and Cloudflare Workers.
//
// The bundlers alias both module specifiers to this file, so the test files themselves are unchanged
// and one suite runs everywhere. Node.js, Deno, and Bun keep using the real `node:test`.
//
// Only the surface the suite actually uses is implemented, and `assert` follows the strict variant's
// semantics: `equal` is `Object.is`, and `deepEqual` compares prototypes, own enumerable keys, and
// typed array contents rather than coercing.

/**
 * One registration, kept in declaration order.
 *
 * `node:test` runs a suite's tests and its nested suites interleaved in the order they were
 * declared, and the suite here relies on that: one corpus test asserts what earlier tests
 * recorded.
 */
type Entry =
  | { readonly kind: 'case'; readonly name: string; readonly body: () => void | Promise<void> }
  | { readonly kind: 'suite'; readonly suite: Suite }

interface Suite {
  readonly name: string
  /** Cleared once the body has run and its registrations have been collected. */
  body?: () => void
  readonly entries: Entry[]
}

/** The result of one test, in the shape the browser driver reads off the page. */
export interface CaseResult {
  readonly name: string
  readonly status: 'passed' | 'failed'
  readonly error?: string
}

export interface SuiteResults {
  readonly total: number
  readonly passed: number
  readonly failed: number
  readonly tests: ReadonlyArray<CaseResult>
}

const root: Suite = { name: '', entries: [] }
let current = root

/**
 * Registers a group of tests.
 *
 * Unlike `node:test`, the body is not run at import time. Cloudflare Workers forbids I/O, timers,
 * and random values in global scope, and a `describe` body that builds a `Request` or a key pair
 * would hit that as soon as the bundle was evaluated. Deferring the bodies to
 * {@link runRegisteredTests}, which a handler calls, keeps every line of the suite inside a request
 * context. Registration order is unaffected.
 */
export function describe(name: string, body: () => void): void {
  current.entries.push({ kind: 'suite', suite: { name, body, entries: [] } })
}

/** Registers one test. */
export function it(name: string, body: () => void | Promise<void>): void {
  current.entries.push({ kind: 'case', name, body })
}

function describeValue(value: unknown): string {
  if (typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (typeof value === 'bigint') {
    return `${value}n`
  }
  if (value === null || typeof value !== 'object') {
    return String(value)
  }
  if (ArrayBuffer.isView(value)) {
    const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    return `${value.constructor.name}(${value.byteLength}) [${[...bytes].join(', ')}]`
  }
  try {
    return JSON.stringify(value) ?? String(value)
  } catch {
    return String(value)
  }
}

class AssertionError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AssertionError'
  }
}

function failAssertion(message: string | Error | undefined, fallback: string): never {
  if (message instanceof Error) {
    throw message
  }
  throw new AssertionError(message ?? fallback)
}

function sameBytes(left: ArrayBufferView, right: ArrayBufferView): boolean {
  if (left.byteLength !== right.byteLength) {
    return false
  }
  const a = new Uint8Array(left.buffer, left.byteOffset, left.byteLength)
  const b = new Uint8Array(right.buffer, right.byteOffset, right.byteLength)
  for (let index = 0; index < a.length; index++) {
    if (a[index] !== b[index]) {
      return false
    }
  }
  return true
}

/** Structural comparison matching `assert.deepStrictEqual` for the value shapes this suite uses. */
function deepEqualValue(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) {
    return true
  }
  if (typeof left !== 'object' || typeof right !== 'object' || left === null || right === null) {
    return false
  }
  if (Object.getPrototypeOf(left) !== Object.getPrototypeOf(right)) {
    return false
  }
  if (ArrayBuffer.isView(left)) {
    return sameBytes(left, right as ArrayBufferView)
  }
  if (left instanceof Date) {
    return Object.is(left.getTime(), (right as Date).getTime())
  }
  if (left instanceof RegExp) {
    return String(left) === String(right)
  }
  if (left instanceof Map) {
    const other = right as Map<unknown, unknown>
    if (left.size !== other.size) {
      return false
    }
    for (const [key, value] of left) {
      if (!other.has(key) || !deepEqualValue(value, other.get(key))) {
        return false
      }
    }
    return true
  }
  if (left instanceof Set) {
    const other = right as Set<unknown>
    if (left.size !== other.size) {
      return false
    }
    for (const value of left) {
      if (!other.has(value)) {
        return false
      }
    }
    return true
  }

  const leftKeys = Object.keys(left)
  const rightKeys = Object.keys(right)
  if (leftKeys.length !== rightKeys.length) {
    return false
  }
  for (const key of leftKeys) {
    if (!Object.hasOwn(right, key)) {
      return false
    }
    if (
      !deepEqualValue(
        (left as Record<string, unknown>)[key],
        (right as Record<string, unknown>)[key],
      )
    ) {
      return false
    }
  }
  return true
}

type Expectation =
  | RegExp
  | (new (...args: never[]) => Error)
  | ((error: unknown) => boolean)
  | Readonly<Record<string, unknown>>
  | undefined

/** Reports whether a function is an `Error` class, as opposed to a validation callback. */
function isErrorClass(value: object): boolean {
  const { prototype } = value as { prototype?: unknown }
  if (prototype === null || typeof prototype !== 'object') {
    return false
  }
  return prototype === Error.prototype || Error.prototype.isPrototypeOf(prototype)
}

/**
 * Applies the `assert.throws`/`assert.rejects` expectation argument to a caught value.
 *
 * A function is either an `Error` class, checked with `instanceof`, or a validation callback that
 * makes its own assertions and returns `true`, which is how `node:assert` treats it.
 */
function matchesExpectation(error: unknown, expected: Expectation): boolean {
  if (expected === undefined) {
    return true
  }
  if (expected instanceof RegExp) {
    return expected.test(error instanceof Error ? error.message : String(error))
  }
  if (typeof expected === 'object') {
    return matchesErrorProperties(error, expected)
  }
  if (isErrorClass(expected)) {
    return error instanceof (expected as new (...args: never[]) => Error)
  }
  return (expected as (error: unknown) => boolean)(error) === true
}

/**
 * Compares a caught value against the object form of the expectation argument.
 *
 * `node:assert` checks every own property of the object, including `name` and `message`, which are
 * not enumerable on an `Error`. A `RegExp` value tests the property instead of comparing it.
 */
function matchesErrorProperties(
  error: unknown,
  expected: Readonly<Record<string, unknown>>,
): boolean {
  if (error === null || (typeof error !== 'object' && typeof error !== 'function')) {
    return false
  }
  for (const [key, value] of Object.entries(expected)) {
    const actual = (error as Record<string, unknown>)[key]
    if (value instanceof RegExp) {
      if (!value.test(String(actual))) {
        return false
      }
    } else if (!deepEqualValue(value, actual)) {
      return false
    }
  }
  return true
}

function expectationName(expected: Expectation): string {
  if (expected === undefined) {
    return 'an error'
  }
  if (expected instanceof RegExp) {
    return String(expected)
  }
  if (typeof expected === 'object') {
    return `an error matching ${JSON.stringify(expected)}`
  }
  return isErrorClass(expected) ? expected.name : 'the expectation callback'
}

function assert(value: unknown, message?: string | Error): void {
  if (!value) {
    failAssertion(message, `Expected a truthy value, got ${describeValue(value)}`)
  }
}

const strict = Object.assign(assert, {
  ok: assert,

  equal(actual: unknown, expected: unknown, message?: string | Error): void {
    if (!Object.is(actual, expected)) {
      failAssertion(message, `${describeValue(actual)} !== ${describeValue(expected)}`)
    }
  },

  notEqual(actual: unknown, expected: unknown, message?: string | Error): void {
    if (Object.is(actual, expected)) {
      failAssertion(message, `Expected a value other than ${describeValue(expected)}`)
    }
  },

  deepEqual(actual: unknown, expected: unknown, message?: string | Error): void {
    if (!deepEqualValue(actual, expected)) {
      failAssertion(
        message,
        `${describeValue(actual)} does not deeply equal ${describeValue(expected)}`,
      )
    }
  },

  match(value: string, pattern: RegExp, message?: string | Error): void {
    if (!pattern.test(value)) {
      failAssertion(message, `${describeValue(value)} does not match ${String(pattern)}`)
    }
  },

  throws(body: () => unknown, expected?: Expectation, message?: string | Error): void {
    let thrown: unknown
    let threw = false
    try {
      body()
    } catch (error) {
      threw = true
      thrown = error
    }
    if (!threw) {
      failAssertion(message, `Expected ${expectationName(expected)} to be thrown`)
    }
    if (!matchesExpectation(thrown, expected)) {
      failAssertion(
        message,
        `Thrown value does not match ${expectationName(expected)}: ${String(thrown)}`,
      )
    }
  },

  async rejects(
    target: Promise<unknown> | (() => Promise<unknown>),
    expected?: Expectation,
    message?: string | Error,
  ): Promise<void> {
    let thrown: unknown
    let threw = false
    try {
      await (typeof target === 'function' ? target() : target)
    } catch (error) {
      threw = true
      thrown = error
    }
    if (!threw) {
      failAssertion(message, `Expected ${expectationName(expected)} to be rejected with`)
    }
    if (!matchesExpectation(thrown, expected)) {
      failAssertion(
        message,
        `Rejection does not match ${expectationName(expected)}: ${String(thrown)}`,
      )
    }
  },

  async doesNotReject(
    target: Promise<unknown> | (() => Promise<unknown>),
    message?: string | Error,
  ): Promise<void> {
    try {
      await (typeof target === 'function' ? target() : target)
    } catch (error) {
      failAssertion(message, `Expected no rejection, got ${String(error)}`)
    }
  },

  fail(message?: string | Error): never {
    failAssertion(message, 'Failed')
  },
})

// `strict.strict` mirrors `node:assert/strict`, whose default export also exposes itself that way.
export default Object.assign(strict, {
  strict,
  notStrictEqual: strict.notEqual,
  strictEqual: strict.equal,
  deepStrictEqual: strict.deepEqual,
})

/**
 * Runs every registered test and reports the outcome.
 *
 * Tests run sequentially, which keeps the shared global mutation some of them perform (hiding the
 * `Uint8Array` base64 methods, for instance) from leaking into a concurrently running test.
 */
export async function runRegisteredTests(): Promise<SuiteResults> {
  const tests: CaseResult[] = []

  const describeError = (error: unknown): string =>
    error instanceof Error ? `${error.name}: ${error.message}` : String(error)

  async function walk(suite: Suite, prefix: string): Promise<void> {
    const path =
      suite.name === '' ? prefix : prefix === '' ? suite.name : `${prefix} > ${suite.name}`

    const { body } = suite
    if (body !== undefined) {
      suite.body = undefined
      const parent = current
      current = suite
      try {
        body()
      } catch (error) {
        tests.push({
          name: `${path} > (suite registration)`,
          status: 'failed',
          error: describeError(error),
        })
        return
      } finally {
        current = parent
      }
    }

    for (const entry of suite.entries) {
      if (entry.kind === 'suite') {
        await walk(entry.suite, path)
        continue
      }
      const name = path === '' ? entry.name : `${path} > ${entry.name}`
      try {
        await entry.body()
        tests.push({ name, status: 'passed' })
      } catch (error) {
        tests.push({ name, status: 'failed', error: describeError(error) })
      }
    }
  }

  await walk(root, '')

  const failed = tests.filter((entry) => entry.status === 'failed').length
  return { total: tests.length, passed: tests.length - failed, failed, tests }
}
