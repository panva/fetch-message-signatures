// Runs the httpwg/structured-field-tests conformance corpus against this package's RFC 9651
// implementation. The corpus is vendored under test/fixtures/structured-field-tests; refresh it
// with `node --run fixtures`.
//
// The corpus tests a Structured Fields parser and serializer directly. This package does not export
// one, so the corpus is driven through the surface that RFC 9421 actually reaches it from:
//
//   - parsing and strict re-serialization, through the `sf` component parameter, which is defined
//     as "parse the field value, then serialize it with the strict rules"; and
//   - bare item serialization, through signature metadata parameter values and names.
//
// That is the behavior signature bases depend on, so a regression the corpus can detect is a
// regression that would change a signature base.

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { component, createSignatureBase, date, displayString, token } from '../index.ts'
import type { SignatureParameterInput, SignatureParameters, StructuredFieldType } from '../index.ts'
import { CORPUS_METADATA, PARSE_FIXTURES, SERIALISATION_FIXTURES } from './fixtures/corpus.ts'
import { withoutUint8ArrayBase64 } from './support.ts'

/** One case from the corpus. `raw` drives parsing, `expected` drives serialization. */
interface FixtureCase {
  readonly name: string
  readonly header_type: StructuredFieldType
  readonly raw?: ReadonlyArray<string>
  readonly canonical?: ReadonlyArray<string>
  readonly expected?: unknown
  readonly must_fail?: boolean
  readonly can_fail?: boolean
}

/**
 * Cases whose input is rejected by a bare Structured Fields parser but accepted here, because RFC
 * 9421 canonicalizes each HTTP field line before it is parsed: leading and trailing whitespace is
 * stripped first, so a field line whose only defect is a surrounding tab is repaired by the RFC
 * 9421 layer and never reaches the Structured Fields grammar.
 */
const REPAIRED_BY_FIELD_CANONICALIZATION = new Set([
  'item.json / leading space',
  'item.json / trailing space',
  'key-generated.json / 0x09 starting a dictionary key',
  'token-generated.json / 0x09 starting a token',
])

const COMPONENT = component('example', { sf: true })
const LINE_PREFIX = '"example";sf: '

/**
 * Parses the corpus field lines as the given Structured Field type and returns the strict
 * re-serialization that would appear in a signature base.
 *
 * The lines are supplied through a `fieldValues` adapter rather than through `Headers`, because the
 * corpus deliberately includes values that a Fetch `Headers` object refuses to hold.
 */
function canonicalize(lines: ReadonlyArray<string>, type: StructuredFieldType): string {
  const message = {
    method: 'GET',
    url: 'https://example.com/',
    headers: new Headers(),
  } as unknown as Request
  const base = createSignatureBase(message, {
    components: [COMPONENT],
    structuredFields: { example: type },
    fieldValues: () => lines,
  })
  const line = base.slice(0, base.indexOf('\n'))
  assert.ok(line.startsWith(LINE_PREFIX), `unexpected signature base line: ${line}`)
  return line.slice(LINE_PREFIX.length)
}

/** Serializes signature metadata parameters and returns just the serialized parameter list. */
function serializeParameters(parameters: SignatureParameters): string {
  const message = {
    method: 'GET',
    url: 'https://example.com/',
    headers: new Headers(),
  } as unknown as Request
  const base = createSignatureBase(message, { components: [], parameters })
  return base.slice(base.indexOf('()') + '()'.length)
}

/** Converts a corpus bare item into the equivalent signature metadata parameter input. */
function parameterInput(value: unknown): SignatureParameterInput {
  if (value === null || typeof value !== 'object') {
    return value as SignatureParameterInput
  }
  const { __type: type, value: inner } = value as { __type: string; value: string | number }
  switch (type) {
    case 'token':
      return token(inner as string)
    case 'date':
      return date(inner as number)
    case 'displaystring':
      return displayString(inner as string)
    case 'binary':
      // The corpus encodes Byte Sequences with base32.
      return base32Decode(inner as string)
  }
  // Not thrown from a case that is expected to fail: an unknown corpus type is a harness problem,
  // and would otherwise be mistaken for the implementation correctly rejecting the value.
  assert.fail(`unsupported corpus item type "${type}"`)
}

function base32Decode(value: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bytes: number[] = []
  let accumulator = 0
  let bits = 0
  for (const character of value.replace(/=+$/, '')) {
    const index = alphabet.indexOf(character)
    assert.notEqual(index, -1, `invalid base32 in corpus: ${value}`)
    accumulator = (accumulator << 5) | index
    bits += 5
    if (bits >= 8) {
      bytes.push((accumulator >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Uint8Array.from(bytes)
}

/** Collects per-case failures so that one `it()` reports every mismatch in a fixture file. */
class Failures {
  readonly #entries: string[] = []
  #checked = 0

  record(name: string, detail: string): void {
    this.#entries.push(`${name}: ${detail}`)
  }

  pass(): void {
    this.#checked++
  }

  assert(minimum: number): void {
    assert.deepEqual(this.#entries, [], `${this.#entries.length} corpus case(s) failed`)
    assert.ok(
      this.#checked >= minimum,
      `expected at least ${minimum} corpus cases, ran ${this.#checked}`,
    )
  }
}

/** The base64 implementations the corpus is run against. */
const BASE64_MODES = [
  ['Uint8Array methods', <T>(body: () => T): T => body()],
  ['btoa fallback', withoutUint8ArrayBase64],
] as const

function summarize(value: unknown): string {
  return JSON.stringify(value) ?? String(value)
}

describe('httpwg structured-field-tests corpus', () => {
  const skipped = new Set<string>()

  it('records the upstream revision it was vendored from', () => {
    assert.match(CORPUS_METADATA.commit, /^[0-9a-f]{40}$/)
    assert.ok(CORPUS_METADATA.files > 0)
    assert.ok(
      PARSE_FIXTURES.length >= 20,
      `expected the vendored corpus, found ${PARSE_FIXTURES.length} files`,
    )
    assert.ok(SERIALISATION_FIXTURES.length > 0)
  })

  for (const [mode, run] of BASE64_MODES) {
    describe(`parsing and strict re-serialization through "sf" (${mode})`, () => {
      for (const [name, cases] of PARSE_FIXTURES) {
        it(name, () => {
          run(() => runParseFixture(name, cases as ReadonlyArray<FixtureCase>, skipped))
        })
      }
    })
  }

  describe('bare item serialization through signature metadata parameters', () => {
    for (const [name, cases] of SERIALISATION_FIXTURES) {
      it(name, () => {
        const failures = new Failures()
        for (const fixture of cases as ReadonlyArray<FixtureCase>) {
          if (fixture.header_type === 'item') {
            checkItemSerialization(fixture, failures)
          } else {
            checkKeySerialization(fixture, failures)
          }
        }
        failures.assert(1)
      })
    }
  })

  it('exercises every documented corpus exception', () => {
    assert.deepEqual([...skipped].sort(), [...REPAIRED_BY_FIELD_CANONICALIZATION].sort())
  })
})

/** Runs one parse fixture file, returning nothing and failing the test on the first mismatch. */
function runParseFixture(
  name: string,
  cases: ReadonlyArray<FixtureCase>,
  skipped: Set<string>,
): void {
  const failures = new Failures()
  for (const fixture of cases) {
    if (fixture.raw === undefined) {
      continue
    }
    const label = `${name} / ${fixture.name}`
    if (REPAIRED_BY_FIELD_CANONICALIZATION.has(label)) {
      skipped.add(label)
      continue
    }

    const expected = (fixture.canonical ?? fixture.raw).join(', ')
    let actual: string | undefined
    let thrown: unknown
    try {
      actual = canonicalize(fixture.raw, fixture.header_type)
    } catch (error) {
      thrown = error
    }

    if (fixture.must_fail) {
      if (thrown === undefined) {
        failures.record(fixture.name, `accepted ${summarize(fixture.raw)} as ${actual}`)
      } else {
        failures.pass()
      }
      continue
    }
    if (thrown !== undefined) {
      if (!fixture.can_fail) {
        failures.record(fixture.name, `rejected ${summarize(fixture.raw)}: ${thrown}`)
      } else {
        failures.pass()
      }
      continue
    }
    if (actual !== expected && !fixture.can_fail) {
      failures.record(fixture.name, `expected ${summarize(expected)}, got ${summarize(actual)}`)
    } else {
      failures.pass()
    }
  }
  failures.assert(1)
}

/**
 * Drives an Item serialization case through a signature metadata parameter value.
 *
 * The corpus Items carry no parameters of their own, so the expected output is the canonical Item
 * text with the parameter name in front of it. A Boolean true is the one exception, because
 * Structured Fields omits the value of a Boolean true parameter.
 */
function checkItemSerialization(fixture: FixtureCase, failures: Failures): void {
  const [bare] = fixture.expected as [unknown, ReadonlyArray<unknown>]
  let actual: string | undefined
  let thrown: unknown
  try {
    // Built inside the try because the validating wrappers, such as `token()`, are where an
    // unserializable value is expected to be rejected.
    actual = serializeParameters([['sfvalue', parameterInput(bare)]])
  } catch (error) {
    thrown = error
  }

  if (fixture.must_fail) {
    if (thrown === undefined) {
      failures.record(fixture.name, `accepted ${summarize(bare)} as ${actual}`)
    } else {
      failures.pass()
    }
    return
  }
  if (thrown !== undefined) {
    failures.record(fixture.name, `rejected ${summarize(bare)}: ${thrown}`)
    return
  }

  const canonical = (fixture.canonical ?? []).join(', ')
  const expected = bare === true ? ';sfvalue' : `;sfvalue=${canonical}`
  if (actual !== expected) {
    failures.record(fixture.name, `expected ${summarize(expected)}, got ${summarize(actual)}`)
  } else {
    failures.pass()
  }
}

/**
 * Drives a Dictionary key or parameter key serialization case through a signature metadata
 * parameter name, which RFC 9421 requires to be a Structured Field key.
 */
function checkKeySerialization(fixture: FixtureCase, failures: Failures): void {
  const [member] = fixture.expected as ReadonlyArray<unknown>
  const key =
    fixture.header_type === 'dictionary'
      ? (member as [string, unknown])[0]
      : ((member as [unknown, ReadonlyArray<[string, unknown]>])[1][0] as [string, unknown])[0]

  let thrown: unknown
  try {
    serializeParameters([[key, 1]])
  } catch (error) {
    thrown = error
  }

  if (fixture.must_fail === true) {
    if (thrown === undefined) {
      failures.record(fixture.name, `accepted key ${summarize(key)}`)
    } else {
      failures.pass()
    }
    return
  }
  if (thrown !== undefined) {
    failures.record(fixture.name, `rejected key ${summarize(key)}: ${thrown}`)
  } else {
    failures.pass()
  }
}
