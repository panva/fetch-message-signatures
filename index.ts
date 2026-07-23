/**
 * HTTP Message Signatures for the Fetch API.
 *
 * Implements the sender, recipient, and `Accept-Signature` operations from [RFC
 * 9421](https://www.rfc-editor.org/rfc/rfc9421.html) on top of `Request`, `Response`, `Headers`,
 * and `fetch`. The module constructs and parses the required Structured Fields, includes Web
 * Cryptography implementations of the ECDSA and Ed25519 signature algorithms, and supports custom
 * cryptographic providers.
 *
 * @module fetch-message-signatures
 * @example
 *
 * Sign and verify a request with Ed25519 through Web Cryptography.
 *
 * ```ts
 * import * as FetchSig from 'fetch-message-signatures'
 *
 * const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
 * const signer = FetchSig.ed25519Signer(privateKey)
 * const verifyWithKey = FetchSig.ed25519Verifier(publicKey)
 *
 * const verifier: FetchSig.VerifierFactory = (signature, context) => {
 *   const keyid = signature.parameters.find(([name]) => name === 'keyid')?.[1]
 *   if (keyid !== 'example-key') throw new Error('Untrusted signing key')
 *   return verifyWithKey(signature, context)
 * }
 *
 * const request = await FetchSig.sign(new Request('https://api.example/orders/123'), {
 *   signer,
 *   components: ['@method', '@authority', '@path'],
 *   parameters: { alg: 'ed25519', keyid: 'example-key' },
 * })
 *
 * const verified = await FetchSig.verify(request, {
 *   verifier,
 *   policy: {
 *     requiredComponents: ['@method', '@authority', '@path'],
 *     requiredParameters: ['created', 'alg', 'keyid'],
 *     algorithms: ['ed25519'],
 *     maxAge: 60,
 *   },
 * })
 *
 * console.log(verified.label, verified.algorithm)
 * ```
 */

const encoder = /* @__PURE__ */ new TextEncoder()
const decoder = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

const DERIVED_COMPONENTS = new Set([
  '@method',
  '@target-uri',
  '@authority',
  '@scheme',
  '@request-target',
  '@path',
  '@query',
  '@query-param',
  '@status',
])

const SIGNATURE_PARAMETERS = new Set(['created', 'expires', 'nonce', 'alg', 'keyid', 'tag'])

const HTTP_FIELD_NAME = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/
const SF_KEY = /^[a-z*][a-z0-9_.*-]*$/
const SF_TOKEN = /^[A-Za-z*][!#$%&'*+\-.^_`|~A-Za-z0-9:/*]*$/
const ASCII = /^[\x00-\x7f]*$/
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/

/** The top-level type of an HTTP Structured Field. */
export type StructuredFieldType = 'dictionary' | 'list' | 'item'

/** A Structured Field Token. Plain JavaScript strings represent Structured Field Strings. */
export interface StructuredFieldToken {
  readonly type: 'token'
  readonly value: string
}

/** A Structured Field Decimal, including integral decimal values such as `1.0`. */
export interface StructuredFieldDecimal {
  readonly type: 'decimal'
  readonly value: number
}

/** A Structured Field Date represented as integer UNIX seconds. */
export interface StructuredFieldDate {
  readonly type: 'date'
  readonly value: number
}

/** A Structured Field Display String. */
export interface StructuredFieldDisplayString {
  readonly type: 'display-string'
  readonly value: string
}

/** A value that can be used as an HTTP signature metadata parameter. */
export type SignatureParameterValue =
  | string
  | number
  | boolean
  | Uint8Array
  | StructuredFieldToken
  | StructuredFieldDecimal
  | StructuredFieldDate
  | StructuredFieldDisplayString

/**
 * A signature metadata parameter input.
 *
 * `Date` values are converted to integer UNIX timestamps. `false` is useful only for the `created`
 * parameter, where it explicitly disables the default creation timestamp.
 */
export type SignatureParameterInput = SignatureParameterValue | Date | undefined

/** An ordered signature metadata parameter. */
export type SignatureParameter = readonly [name: string, value: SignatureParameterInput]

/**
 * Ordered parameters are recommended because their order is covered by the signature. Object
 * property insertion order is preserved when a record is supplied.
 */
export type SignatureParameters =
  ReadonlyArray<SignatureParameter> | Readonly<Record<string, SignatureParameterInput>>

/** A value supported by an HTTP message component parameter. */
export type ComponentParameterValue = string | boolean

/** An ordered HTTP message component parameter. */
export type ComponentParameter = readonly [name: string, value: ComponentParameterValue]

/**
 * Ordered parameters are recommended because their serialization order is covered by the signature.
 * Object property insertion order is preserved when a record is supplied.
 */
export type ComponentParameters =
  ReadonlyArray<ComponentParameter> | Readonly<Record<string, ComponentParameterValue>>

/** A parameterized HTTP message component identifier. */
export interface ParameterizedComponent {
  readonly name: string
  readonly parameters?: ComponentParameters
}

/**
 * An HTTP message component identifier.
 *
 * A string is shorthand for an identifier without parameters.
 */
export type ComponentIdentifier = string | ParameterizedComponent

/** A normalized HTTP message component identifier with ordered parameters. */
export interface MessageComponent {
  readonly name: string
  readonly parameters: ReadonlyArray<ComponentParameter>
}

/** Context supplied while deriving HTTP message components. */
export interface FieldValueContext {
  /** Whether the value is requested from the trailer section. */
  readonly trailers: boolean
  /** Whether the value is requested from the related request of a response. */
  readonly relatedRequest: boolean
}

/**
 * Supplies individual HTTP field occurrences in wire order.
 *
 * Fetch combines most repeated field lines and does not expose trailers. Provide this adapter when
 * using the `bs` or `tr` component parameters, or when an application has a more authoritative
 * representation of the HTTP message than `Headers`.
 *
 * If a field name occurs in both the header and trailer sections, return only the section selected
 * by `context.trailers`; RFC 9421 forbids combining same-name header and trailer values for
 * signature-base generation.
 *
 * Returning `undefined` or an empty array indicates that the field is absent.
 */
export type FieldValues = (
  message: Request | Response,
  name: string,
  context: FieldValueContext,
) => ReadonlyArray<string> | undefined

/** Options shared by signature-base creation, signing, and verification. */
export interface SignatureContext {
  /** The exact request that triggered a response. Required when a response signature uses `;req`. */
  readonly request?: Request
  /** Structured Field top-level types, indexed by lowercase HTTP field name. */
  readonly structuredFields?: Readonly<Record<string, StructuredFieldType>>
  /** Adapter for raw field occurrences and trailers. */
  readonly fieldValues?: FieldValues
}

/** Target-message context supplied to a verifier factory. */
export interface VerificationContext {
  /** The target message carrying the signature. */
  readonly message: Request | Response
  /** The exact related request, when response/request binding is in use. */
  readonly request?: Request
}

/** Authenticated context supplied to additional application policy. */
export interface VerifiedSignatureContext extends VerificationContext {
  /** The algorithm selected by the verifier factory. */
  readonly algorithm: string
}

/** A parsed HTTP message signature. */
export interface MessageSignature {
  readonly label: string
  readonly components: ReadonlyArray<MessageComponent>
  readonly parameters: ReadonlyArray<readonly [name: string, value: SignatureParameterValue]>
  readonly signature: Uint8Array<ArrayBuffer>
}

/** The result of creating one signature, ready to be added to the corresponding HTTP fields. */
export interface SignatureFields extends MessageSignature {
  /** A one-member `Signature-Input` Structured Field Dictionary. */
  readonly signatureInput: string
  /** A one-member `Signature` Structured Field Dictionary. */
  readonly signatureField: string
}

/**
 * A Promise-based signer implementation returned by a synchronous factory.
 *
 * Synchronous cryptographic libraries can be adapted by declaring `sign` as an `async` method.
 */
export interface Signer {
  readonly type: 'signer'
  /** The algorithm selected by configuration or key metadata. */
  readonly alg: string
  sign(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array>
}

/** A synchronous factory returning a signer implementation. */
export type SignerFactory = () => Readonly<Signer>

/** A Promise-based verifier implementation returned by a synchronous factory. */
export interface Verifier {
  readonly type: 'verifier'
  /** The algorithm selected by configuration or key metadata. */
  readonly alg: string
  verify(data: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>): Promise<boolean>
}

/**
 * A synchronous factory that selects trusted verification key material and an algorithm.
 *
 * The factory is the application's key-resolution and trust-policy boundary. It MUST reject unknown
 * or inappropriate key identifiers and algorithms instead of returning a verifier for them.
 */
export type VerifierFactory = (
  signature: Readonly<MessageSignature>,
  context: Readonly<VerificationContext>,
) => Readonly<Verifier>

/** Sender options. */
export interface SignOptions extends SignatureContext {
  readonly signer: SignerFactory
  readonly components: ReadonlyArray<ComponentIdentifier>
  readonly parameters?: SignatureParameters
  readonly label?: string
  /** Injectable clock used for the default `created` parameter. */
  readonly now?: number | Date
}

/** Explicit application policy required before a cryptographically valid signature is accepted. */
export interface VerificationPolicy {
  /** Every listed component identifier must be covered by the signature. */
  readonly requiredComponents: ReadonlyArray<ComponentIdentifier>
  /** Every listed metadata parameter must be present. */
  readonly requiredParameters: ReadonlyArray<string>
  /** Non-empty allowlist matched against the algorithm selected by the verifier factory. */
  readonly algorithms: ReadonlyArray<string>
  /** Maximum signature age in seconds. Requires a `created` parameter. */
  readonly maxAge?: number
  /** Permitted timestamp skew in seconds. Defaults to zero. */
  readonly clockSkew?: number
  /** Injectable verification clock. */
  readonly now?: number | Date
  /**
   * Additional application policy, such as nonce uniqueness, expected tags, field semantics, and
   * key/message authorization.
   */
  validate?(
    signature: Readonly<MessageSignature>,
    context: Readonly<VerifiedSignatureContext>,
  ): void | Promise<void>
}

/** Recipient options. */
export interface VerifyOptions extends SignatureContext {
  readonly verifier: VerifierFactory
  readonly policy: VerificationPolicy
  /**
   * The signature label to verify. Required when the message contains more than one signature.
   * Labels are not signed and MUST NOT be assigned application semantics.
   */
  readonly label?: string
}

/** A successfully verified signature. */
export interface VerifiedSignature extends MessageSignature {
  readonly algorithm: string
}

/** Options for direct signature-base creation. */
export interface SignatureBaseOptions extends SignatureContext {
  readonly components: ReadonlyArray<ComponentIdentifier>
  readonly parameters?: SignatureParameters
}

type SfBareItem =
  | { readonly kind: 'integer'; readonly value: number }
  | { readonly kind: 'decimal'; readonly value: number }
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'token'; readonly value: string }
  | { readonly kind: 'binary'; readonly value: Uint8Array }
  | { readonly kind: 'boolean'; readonly value: boolean }
  | { readonly kind: 'date'; readonly value: number }
  | { readonly kind: 'display-string'; readonly value: string }

type SfParameter = [name: string, value: SfBareItem]
type SfParameters = SfParameter[]

interface SfItem {
  readonly kind: 'item'
  readonly value: SfBareItem
  readonly parameters: SfParameters
}

interface SfInnerList {
  readonly kind: 'inner-list'
  readonly value: SfItem[]
  readonly parameters: SfParameters
}

type SfMember = SfItem | SfInnerList
type SfList = SfMember[]
type SfDictionaryEntry = [name: string, value: SfMember]
type SfDictionary = SfDictionaryEntry[]
type SfTopLevel = SfDictionary | SfList | SfItem

interface ParseState {
  readonly input: string
  index: number
  readonly duplicateKeys: string[]
}

function fail(message: string): never {
  throw new TypeError(message)
}

type AlgorithmKeyType = 'private' | 'public'
type SignatureKeyUsage = 'sign' | 'verify'
type WebCryptoSignatureAlgorithm = AlgorithmIdentifier | EcdsaParams
type WebCryptoKeyGenerationAlgorithm = AlgorithmIdentifier | EcKeyGenParams

interface AlgorithmKeyExpectation {
  readonly identifier: string
  readonly type: AlgorithmKeyType
  readonly usage: SignatureKeyUsage
  readonly algorithm: string
  readonly namedCurve?: string
}

function extractableOption(extractable: boolean | undefined): boolean {
  if (extractable === undefined) {
    return false
  }
  if (typeof extractable !== 'boolean') {
    fail('"extractable" must be a boolean')
  }
  return extractable
}

function algorithmProperty(value: unknown, property: string): unknown {
  if (value === null || typeof value !== 'object') {
    return undefined
  }
  return (value as Record<string, unknown>)[property]
}

function isAlgorithmKey(key: CryptoKey, expected: AlgorithmKeyExpectation): boolean {
  if (key === null || typeof key !== 'object') {
    return false
  }
  const algorithm = algorithmProperty(key, 'algorithm')
  const usages = algorithmProperty(key, 'usages')
  if (
    algorithmProperty(key, 'type') !== expected.type ||
    !Array.isArray(usages) ||
    !usages.includes(expected.usage) ||
    algorithmProperty(algorithm, 'name') !== expected.algorithm
  ) {
    return false
  }
  return (
    expected.namedCurve === undefined ||
    algorithmProperty(algorithm, 'namedCurve') === expected.namedCurve
  )
}

function assertAlgorithmKey(key: CryptoKey, expected: AlgorithmKeyExpectation): void {
  if (!isAlgorithmKey(key, expected)) {
    fail(
      `"key" must be Web Cryptography's ${expected.type} CryptoKey for "${expected.identifier}" with "${expected.usage}" usage`,
    )
  }
}

function webCryptoSigner(
  key: CryptoKey,
  expected: AlgorithmKeyExpectation,
  operation: WebCryptoSignatureAlgorithm,
): SignerFactory {
  assertAlgorithmKey(key, expected)
  return () => ({
    type: 'signer',
    alg: expected.identifier,
    async sign(data) {
      return new Uint8Array(await globalThis.crypto.subtle.sign(operation, key, data))
    },
  })
}

function webCryptoVerifier(
  key: CryptoKey,
  expected: AlgorithmKeyExpectation,
  operation: WebCryptoSignatureAlgorithm,
): VerifierFactory {
  assertAlgorithmKey(key, expected)
  return () => ({
    type: 'verifier',
    alg: expected.identifier,
    async verify(data, signature) {
      return globalThis.crypto.subtle.verify(operation, key, signature, data)
    },
  })
}

async function generateWebCryptoKeyPair(
  algorithm: WebCryptoKeyGenerationAlgorithm,
  extractable: boolean | undefined,
): Promise<CryptoKeyPair> {
  return (await globalThis.crypto.subtle.generateKey(algorithm, extractableOption(extractable), [
    'sign',
    'verify',
  ])) as CryptoKeyPair
}

/**
 * Generates an ECDSA P-256 key pair for the RFC 9421 `ecdsa-p256-sha256` algorithm.
 *
 * The generated public key is represented by Web Cryptography's `CryptoKey` and is always
 * extractable.
 *
 * @param extractable - Whether the private key can be exported. Defaults to `false`.
 *
 * @returns A randomly generated signing and verification key pair.
 * @group Cryptographic Algorithms
 */
export async function generateEcdsaP256Sha256KeyPair(
  extractable?: boolean,
): Promise<CryptoKeyPair> {
  return generateWebCryptoKeyPair({ name: 'ECDSA', namedCurve: 'P-256' }, extractable)
}

/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`.
 *
 * Signatures use the RFC-required 64-byte raw `r || s` representation.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-256 private key with `sign` usage.
 * @group Cryptographic Algorithms
 */
export function ecdsaP256Sha256Signer(key: CryptoKey): SignerFactory {
  return webCryptoSigner(
    key,
    {
      identifier: 'ecdsa-p256-sha256',
      type: 'private',
      usage: 'sign',
      algorithm: 'ECDSA',
      namedCurve: 'P-256',
    },
    { name: 'ECDSA', hash: 'SHA-256' },
  )
}

/**
 * Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`.
 *
 * Signatures use the RFC-required 64-byte raw `r || s` representation. This fixed-key factory does
 * not perform `keyid` lookup or authorization; select it from trusted application configuration
 * when more than one verification key can be used.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-256 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export function ecdsaP256Sha256Verifier(key: CryptoKey): VerifierFactory {
  return webCryptoVerifier(
    key,
    {
      identifier: 'ecdsa-p256-sha256',
      type: 'public',
      usage: 'verify',
      algorithm: 'ECDSA',
      namedCurve: 'P-256',
    },
    { name: 'ECDSA', hash: 'SHA-256' },
  )
}

/**
 * Generates an ECDSA P-384 key pair for the RFC 9421 `ecdsa-p384-sha384` algorithm.
 *
 * The generated public key is represented by Web Cryptography's `CryptoKey` and is always
 * extractable.
 *
 * @param extractable - Whether the private key can be exported. Defaults to `false`.
 *
 * @returns A randomly generated signing and verification key pair.
 * @group Cryptographic Algorithms
 */
export async function generateEcdsaP384Sha384KeyPair(
  extractable?: boolean,
): Promise<CryptoKeyPair> {
  return generateWebCryptoKeyPair({ name: 'ECDSA', namedCurve: 'P-384' }, extractable)
}

/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`.
 *
 * Signatures use the RFC-required 96-byte raw `r || s` representation.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-384 private key with `sign` usage.
 * @group Cryptographic Algorithms
 */
export function ecdsaP384Sha384Signer(key: CryptoKey): SignerFactory {
  return webCryptoSigner(
    key,
    {
      identifier: 'ecdsa-p384-sha384',
      type: 'private',
      usage: 'sign',
      algorithm: 'ECDSA',
      namedCurve: 'P-384',
    },
    { name: 'ECDSA', hash: 'SHA-384' },
  )
}

/**
 * Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`.
 *
 * Signatures use the RFC-required 96-byte raw `r || s` representation. This fixed-key factory does
 * not perform `keyid` lookup or authorization; select it from trusted application configuration
 * when more than one verification key can be used.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-384 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export function ecdsaP384Sha384Verifier(key: CryptoKey): VerifierFactory {
  return webCryptoVerifier(
    key,
    {
      identifier: 'ecdsa-p384-sha384',
      type: 'public',
      usage: 'verify',
      algorithm: 'ECDSA',
      namedCurve: 'P-384',
    },
    { name: 'ECDSA', hash: 'SHA-384' },
  )
}

/**
 * Generates an Ed25519 key pair for the RFC 9421 `ed25519` algorithm.
 *
 * The generated public key is represented by Web Cryptography's `CryptoKey` and is always
 * extractable.
 *
 * @param extractable - Whether the private key can be exported. Defaults to `false`.
 *
 * @returns A randomly generated signing and verification key pair.
 * @group Cryptographic Algorithms
 */
export async function generateEd25519KeyPair(extractable?: boolean): Promise<CryptoKeyPair> {
  return generateWebCryptoKeyPair('Ed25519', extractable)
}

/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ed25519`.
 *
 * The message is signed directly with Ed25519, without an external pre-hash.
 *
 * @param key - Web Cryptography's `CryptoKey` for an Ed25519 private key with `sign` usage.
 * @group Cryptographic Algorithms
 */
export function ed25519Signer(key: CryptoKey): SignerFactory {
  return webCryptoSigner(
    key,
    { identifier: 'ed25519', type: 'private', usage: 'sign', algorithm: 'Ed25519' },
    'Ed25519',
  )
}

/**
 * Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `ed25519`.
 *
 * The message is verified directly with Ed25519, without an external pre-hash. This fixed-key
 * factory does not perform `keyid` lookup or authorization; select it from trusted application
 * configuration when more than one verification key can be used.
 *
 * @param key - Web Cryptography's `CryptoKey` for an Ed25519 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export function ed25519Verifier(key: CryptoKey): VerifierFactory {
  return webCryptoVerifier(
    key,
    { identifier: 'ed25519', type: 'public', usage: 'verify', algorithm: 'Ed25519' },
    'Ed25519',
  )
}

function isRequest(message: Request | Response): message is Request {
  return typeof (message as Request).method === 'string'
}

function isHeaders(value: unknown): value is Headers {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as Headers).append === 'function' &&
    typeof (value as Headers).delete === 'function' &&
    typeof (value as Headers).get === 'function' &&
    typeof (value as Headers).has === 'function' &&
    typeof (value as Headers).set === 'function'
  )
}

function isDate(value: unknown): value is Date {
  return Object.prototype.toString.call(value) === '[object Date]'
}

function isUint8Array(value: unknown): value is Uint8Array {
  return (
    ArrayBuffer.isView(value) && Object.prototype.toString.call(value) === '[object Uint8Array]'
  )
}

function assertMessage(message: unknown): asserts message is Request | Response {
  if (
    message === null ||
    typeof message !== 'object' ||
    typeof (message as Request | Response).headers?.get !== 'function' ||
    (!isRequest(message as Request | Response) && typeof (message as Response).status !== 'number')
  ) {
    fail('"message" must be a Request or Response')
  }
}

function assertSfKey(value: string, description: string): void {
  if (typeof value !== 'string' || !SF_KEY.test(value)) {
    fail(`${description} must be a Structured Field key`)
  }
}

function assertAscii(value: string, description: string): void {
  if (!ASCII.test(value)) {
    fail(`${description} must contain only ASCII characters`)
  }
}

function cloneBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(value)
}

interface MessageMutationGuard {
  readonly message: Request | Response
  readonly headers: Headers
  readonly request?: Request
  readonly requestHeaders?: Headers
}

function createMessageMutationGuard(
  message: Request | Response,
  context: SignatureContext,
): MessageMutationGuard {
  let request: Request | undefined
  let requestHeaders: Headers | undefined
  if (context.request !== undefined) {
    assertMessage(context.request)
    if (!isRequest(context.request)) {
      fail('"request" must be the related Request')
    }
    request = context.request
    requestHeaders = new Headers(request.headers)
  }
  return { message, headers: new Headers(message.headers), request, requestHeaders }
}

function headersEqual(left: Headers, right: Headers): boolean {
  const leftEntries = [...left]
  const rightEntries = [...right]
  return (
    leftEntries.length === rightEntries.length &&
    leftEntries.every(
      ([name, value], index) =>
        rightEntries[index]?.[0] === name && rightEntries[index]?.[1] === value,
    )
  )
}

function assertMessageUnchanged(
  guard: MessageMutationGuard,
  operation: 'signing' | 'verification',
): void {
  if (
    !headersEqual(guard.headers, guard.message.headers) ||
    (guard.request !== undefined && !headersEqual(guard.requestHeaders!, guard.request.headers))
  ) {
    throw new Error(`HTTP message headers changed during signature ${operation}`)
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false
  }
  let different = 0
  for (let i = 0; i < left.byteLength; i++) {
    different |= left[i]! ^ right[i]!
  }
  return different === 0
}

function base64Encode(value: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < value.byteLength; i += chunk) {
    binary += String.fromCharCode(...value.subarray(i, i + chunk))
  }
  return btoa(binary)
}

function base64Decode(value: string): Uint8Array {
  if (
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value) ||
    value.length % 4 === 1 ||
    (value.includes('=') && value.length % 4 !== 0)
  ) {
    fail('Invalid Structured Field Byte Sequence')
  }

  const padded = value + '='.repeat((4 - (value.length % 4)) % 4)
  let binary: string
  try {
    binary = atob(padded)
  } catch (cause) {
    throw new TypeError('Invalid Structured Field Byte Sequence', { cause })
  }

  const output = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    output[i] = binary.charCodeAt(i)
  }
  return output
}

function skipSp(state: ParseState): void {
  while (state.input[state.index] === ' ') {
    state.index++
  }
}

function skipOws(state: ParseState): void {
  while (state.input[state.index] === ' ' || state.input[state.index] === '\t') {
    state.index++
  }
}

function parseKey(state: ParseState): string {
  const start = state.index
  const first = state.input[state.index]
  if (first === undefined || !/[a-z*]/.test(first)) {
    fail('Invalid Structured Field key')
  }
  state.index++
  while (state.index < state.input.length && /[a-z0-9_.*-]/.test(state.input[state.index]!)) {
    state.index++
  }
  return state.input.slice(start, state.index)
}

function setOrdered<T extends readonly [string, unknown]>(
  entries: T[],
  entry: T,
  duplicateKeys?: string[],
): void {
  const index = entries.findIndex(([name]) => name === entry[0])
  if (index === -1) {
    entries.push(entry)
  } else {
    duplicateKeys?.push(entry[0])
    entries[index] = entry
  }
}

function parseNumber(state: ParseState): SfBareItem {
  let sign = 1
  if (state.input[state.index] === '-') {
    sign = -1
    state.index++
  }

  const start = state.index
  while (/[0-9]/.test(state.input[state.index] ?? '')) {
    state.index++
  }
  const integerDigits = state.index - start
  if (integerDigits === 0) {
    fail('Invalid Structured Field number')
  }

  if (state.input[state.index] === '.') {
    if (integerDigits > 12) {
      fail('Structured Field Decimal is out of range')
    }
    state.index++
    const fractionStart = state.index
    while (/[0-9]/.test(state.input[state.index] ?? '')) {
      state.index++
    }
    const fractionDigits = state.index - fractionStart
    if (fractionDigits === 0 || fractionDigits > 3) {
      fail('Invalid Structured Field Decimal')
    }
    const value = Number(state.input.slice(start, state.index)) * sign
    return { kind: 'decimal', value }
  }

  if (integerDigits > 15) {
    fail('Structured Field Integer is out of range')
  }
  const value = Number(state.input.slice(start, state.index)) * sign
  return { kind: 'integer', value }
}

function parseString(state: ParseState): SfBareItem {
  if (state.input[state.index] !== '"') {
    fail('Invalid Structured Field String')
  }
  state.index++
  let value = ''
  while (state.index < state.input.length) {
    const character = state.input[state.index++]!
    if (character === '\\') {
      const escaped = state.input[state.index++]
      if (escaped !== '"' && escaped !== '\\') {
        fail('Invalid escape in Structured Field String')
      }
      value += escaped
    } else if (character === '"') {
      return { kind: 'string', value }
    } else if (!PRINTABLE_ASCII.test(character)) {
      fail('Invalid character in Structured Field String')
    } else {
      value += character
    }
  }
  return fail('Unterminated Structured Field String')
}

function parseToken(state: ParseState): SfBareItem {
  const start = state.index
  const first = state.input[state.index]
  if (first === undefined || !/[A-Za-z*]/.test(first)) {
    fail('Invalid Structured Field Token')
  }
  state.index++
  while (
    state.index < state.input.length &&
    /[!#$%&'*+\-.^_`|~A-Za-z0-9:/*]/.test(state.input[state.index]!)
  ) {
    state.index++
  }
  return { kind: 'token', value: state.input.slice(start, state.index) }
}

function parseBinary(state: ParseState): SfBareItem {
  if (state.input[state.index] !== ':') {
    fail('Invalid Structured Field Byte Sequence')
  }
  state.index++
  const end = state.input.indexOf(':', state.index)
  if (end === -1) {
    fail('Unterminated Structured Field Byte Sequence')
  }
  const encoded = state.input.slice(state.index, end)
  state.index = end + 1
  return { kind: 'binary', value: base64Decode(encoded) }
}

function parseBoolean(state: ParseState): SfBareItem {
  if (state.input[state.index] !== '?') {
    fail('Invalid Structured Field Boolean')
  }
  const value = state.input[state.index + 1]
  if (value !== '0' && value !== '1') {
    fail('Invalid Structured Field Boolean')
  }
  state.index += 2
  return { kind: 'boolean', value: value === '1' }
}

function parseDate(state: ParseState): SfBareItem {
  if (state.input[state.index] !== '@') {
    fail('Invalid Structured Field Date')
  }
  state.index++
  const value = parseNumber(state)
  if (value.kind !== 'integer') {
    fail('Structured Field Date must contain an Integer')
  }
  return { kind: 'date', value: value.value }
}

function parseDisplayString(state: ParseState): SfBareItem {
  if (state.input[state.index] !== '%' || state.input[state.index + 1] !== '"') {
    fail('Invalid Structured Field Display String')
  }
  state.index += 2
  const bytes: number[] = []
  while (state.index < state.input.length) {
    const character = state.input[state.index++]!
    if (character === '"') {
      try {
        return { kind: 'display-string', value: decoder.decode(new Uint8Array(bytes)) }
      } catch (cause) {
        throw new TypeError('Invalid UTF-8 in Structured Field Display String', { cause })
      }
    }
    if (!PRINTABLE_ASCII.test(character)) {
      fail('Invalid character in Structured Field Display String')
    }
    if (character === '%') {
      const encoded = state.input.slice(state.index, state.index + 2)
      if (!/^[0-9a-f]{2}$/.test(encoded)) {
        fail('Invalid percent encoding in Structured Field Display String')
      }
      bytes.push(Number.parseInt(encoded, 16))
      state.index += 2
    } else {
      bytes.push(character.charCodeAt(0))
    }
  }
  return fail('Unterminated Structured Field Display String')
}

function parseBareItem(state: ParseState): SfBareItem {
  const character = state.input[state.index]
  if (character === '-' || /[0-9]/.test(character ?? '')) {
    return parseNumber(state)
  }
  if (character === '"') {
    return parseString(state)
  }
  if (/[A-Za-z*]/.test(character ?? '')) {
    return parseToken(state)
  }
  if (character === ':') {
    return parseBinary(state)
  }
  if (character === '?') {
    return parseBoolean(state)
  }
  if (character === '@' || character === '%') {
    return character === '@' ? parseDate(state) : parseDisplayString(state)
  }
  return fail('Unrecognized Structured Field item')
}

function parseParameters(state: ParseState): SfParameters {
  const parameters: SfParameters = []
  while (state.input[state.index] === ';') {
    state.index++
    skipSp(state)
    const name = parseKey(state)
    let value: SfBareItem = { kind: 'boolean', value: true }
    if (state.input[state.index] === '=') {
      state.index++
      value = parseBareItem(state)
    }
    setOrdered(parameters, [name, value])
  }
  return parameters
}

function parseItem(state: ParseState): SfItem {
  return { kind: 'item', value: parseBareItem(state), parameters: parseParameters(state) }
}

function parseInnerList(state: ParseState): SfInnerList {
  if (state.input[state.index] !== '(') {
    fail('Invalid Structured Field Inner List')
  }
  state.index++
  const value: SfItem[] = []
  while (state.index < state.input.length) {
    skipSp(state)
    if (state.input[state.index] === ')') {
      state.index++
      return { kind: 'inner-list', value, parameters: parseParameters(state) }
    }
    value.push(parseItem(state))
    const next = state.input[state.index]
    if (next !== ' ' && next !== ')') {
      fail('Invalid delimiter in Structured Field Inner List')
    }
  }
  return fail('Unterminated Structured Field Inner List')
}

function parseMember(state: ParseState): SfMember {
  return state.input[state.index] === '(' ? parseInnerList(state) : parseItem(state)
}

function parseList(state: ParseState): SfList {
  const output: SfList = []
  while (state.index < state.input.length) {
    output.push(parseMember(state))
    skipOws(state)
    if (state.index === state.input.length) {
      return output
    }
    if (state.input[state.index] !== ',') {
      fail('Invalid Structured Field List delimiter')
    }
    state.index++
    skipOws(state)
    if (state.index === state.input.length) {
      fail('Structured Field List has a trailing comma')
    }
  }
  return output
}

function parseDictionary(state: ParseState): SfDictionary {
  const output: SfDictionary = []
  while (state.index < state.input.length) {
    const name = parseKey(state)
    let value: SfMember
    if (state.input[state.index] === '=') {
      state.index++
      value = parseMember(state)
    } else {
      value = {
        kind: 'item',
        value: { kind: 'boolean', value: true },
        parameters: parseParameters(state),
      }
    }
    setOrdered(output, [name, value], state.duplicateKeys)
    skipOws(state)
    if (state.index === state.input.length) {
      return output
    }
    if (state.input[state.index] !== ',') {
      fail('Invalid Structured Field Dictionary delimiter')
    }
    state.index++
    skipOws(state)
    if (state.index === state.input.length) {
      fail('Structured Field Dictionary has a trailing comma')
    }
  }
  return output
}

function parseStructuredField(
  input: string,
  type: StructuredFieldType,
  rejectDuplicateKeys = false,
): SfTopLevel {
  assertAscii(input, 'Structured Field value')
  const state: ParseState = { input, index: 0, duplicateKeys: [] }
  skipSp(state)
  let output: SfTopLevel
  switch (type) {
    case 'dictionary':
      output = parseDictionary(state)
      break
    case 'list':
      output = parseList(state)
      break
    case 'item':
      output = parseItem(state)
      break
  }
  skipSp(state)
  if (state.index !== state.input.length) {
    fail('Unexpected data after Structured Field value')
  }
  if (rejectDuplicateKeys && state.duplicateKeys.length !== 0) {
    fail(`Duplicate Structured Field Dictionary key "${state.duplicateKeys[0]}"`)
  }
  return output
}

function serializeKey(value: string): string {
  assertSfKey(value, 'Structured Field key')
  return value
}

function serializeString(value: string): string {
  if (!PRINTABLE_ASCII.test(value)) {
    fail('Structured Field String must contain only printable ASCII characters')
  }
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`
}

function assertUnicodeScalarValues(value: string): void {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) {
        fail('Structured Field Display String contains an unpaired surrogate')
      }
      index++
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail('Structured Field Display String contains an unpaired surrogate')
    }
  }
}

function serializeDisplayString(value: string): string {
  assertUnicodeScalarValues(value)
  let output = '%"'
  for (const byte of encoder.encode(value)) {
    if (byte === 0x22 || byte === 0x25 || byte <= 0x1f || byte >= 0x7f) {
      output += `%${byte.toString(16).padStart(2, '0')}`
    } else {
      output += String.fromCharCode(byte)
    }
  }
  return `${output}"`
}

function serializeDecimal(value: number): string {
  if (!Number.isFinite(value)) {
    fail('Structured Field Decimal must be finite')
  }

  const absolute = Math.abs(value)
  const [mantissa, exponentInput] = absolute.toString().toLowerCase().split('e')
  const exponent = exponentInput === undefined ? 0 : Number(exponentInput)
  const point = mantissa!.indexOf('.')
  const fractionDigits = point === -1 ? 0 : mantissa!.length - point - 1
  const digits = point === -1 ? mantissa! : mantissa!.slice(0, point) + mantissa!.slice(point + 1)
  let numerator = BigInt(digits)
  const power = exponent - fractionDigits + 3
  let scaled: bigint
  if (power >= 0) {
    scaled = numerator * 10n ** BigInt(power)
  } else {
    const denominator = 10n ** BigInt(-power)
    scaled = numerator / denominator
    const remainder = numerator % denominator
    const comparison = remainder * 2n - denominator
    if (comparison > 0n || (comparison === 0n && scaled % 2n === 1n)) {
      scaled++
    }
  }

  if (scaled > 999_999_999_999_999n) {
    fail('Structured Field Decimal is out of range')
  }

  const integer = scaled / 1000n
  const remainder = (scaled % 1000n).toString().padStart(3, '0').replace(/0+$/, '')
  let output = `${integer}.${remainder || '0'}`
  if (value < 0 && scaled !== 0n) {
    output = `-${output}`
  }
  return output
}

function serializeBareItem(item: SfBareItem): string {
  switch (item.kind) {
    case 'integer':
      if (!Number.isSafeInteger(item.value) || Math.abs(item.value) > 999_999_999_999_999) {
        fail('Structured Field Integer is out of range')
      }
      return Object.is(item.value, -0) ? '0' : String(item.value)
    case 'decimal':
      return serializeDecimal(item.value)
    case 'string':
      return serializeString(item.value)
    case 'token':
      if (!SF_TOKEN.test(item.value)) {
        fail('Invalid Structured Field Token')
      }
      return item.value
    case 'binary':
      return `:${base64Encode(item.value)}:`
    case 'boolean':
      return item.value ? '?1' : '?0'
    case 'date':
      if (!Number.isSafeInteger(item.value) || Math.abs(item.value) > 999_999_999_999_999) {
        fail('Structured Field Date is out of range')
      }
      return `@${Object.is(item.value, -0) ? '0' : String(item.value)}`
    case 'display-string':
      return serializeDisplayString(item.value)
  }
}

function serializeParameters(parameters: SfParameters): string {
  let output = ''
  for (const [name, value] of parameters) {
    output += `;${serializeKey(name)}`
    if (value.kind !== 'boolean' || !value.value) {
      output += `=${serializeBareItem(value)}`
    }
  }
  return output
}

function serializeItem(item: SfItem): string {
  return serializeBareItem(item.value) + serializeParameters(item.parameters)
}

function serializeInnerList(value: SfInnerList): string {
  return `(${value.value.map(serializeItem).join(' ')})${serializeParameters(value.parameters)}`
}

function serializeMember(value: SfMember): string {
  return value.kind === 'inner-list' ? serializeInnerList(value) : serializeItem(value)
}

function serializeList(value: SfList): string {
  return value.map(serializeMember).join(', ')
}

function serializeDictionary(value: SfDictionary): string {
  return value
    .map(([name, member]) => {
      const key = serializeKey(name)
      if (member.kind === 'item' && member.value.kind === 'boolean' && member.value.value) {
        return key + serializeParameters(member.parameters)
      }
      return `${key}=${serializeMember(member)}`
    })
    .join(', ')
}

function serializeStructuredField(value: SfTopLevel, type: StructuredFieldType): string {
  switch (type) {
    case 'dictionary':
      return serializeDictionary(value as SfDictionary)
    case 'list':
      return serializeList(value as SfList)
    case 'item':
      return serializeItem(value as SfItem)
  }
}

/**
 * Creates a validated Structured Field Token.
 *
 * @group Components and Structured Fields
 */
export function token(value: string): StructuredFieldToken {
  if (typeof value !== 'string' || !SF_TOKEN.test(value)) {
    fail('"value" must be a Structured Field Token')
  }
  return { type: 'token', value }
}

/**
 * Creates a validated Structured Field Decimal.
 *
 * Use this wrapper when an integral value must retain its Decimal type, such as `decimal(1)` for
 * the serialized value `1.0`.
 *
 * @group Components and Structured Fields
 */
export function decimal(value: number): StructuredFieldDecimal {
  return { type: 'decimal', value: Number(serializeDecimal(value)) }
}

/**
 * Creates a validated Structured Field Date.
 *
 * Numbers are interpreted as integer UNIX seconds. JavaScript `Date` values are rounded down to
 * whole UNIX seconds. A JavaScript `Date` passed directly as a signature parameter is an RFC 9421
 * Integer timestamp. Wrap it with `date()` to select a Structured Field Date and serialize it with
 * the `@` prefix.
 *
 * @group Components and Structured Fields
 */
export function date(value: number | Date): StructuredFieldDate {
  const seconds = isDate(value) ? Math.floor(Date.prototype.getTime.call(value) / 1000) : value
  if (!Number.isSafeInteger(seconds) || Math.abs(seconds) > 999_999_999_999_999) {
    fail('Structured Field Date is out of range')
  }
  return { type: 'date', value: Object.is(seconds, -0) ? 0 : seconds }
}

/**
 * Creates a validated Structured Field Display String.
 *
 * The value must contain only Unicode scalar values. Serialization UTF-8 encodes characters that
 * are not safe ASCII and represents their bytes using lowercase percent encoding. Display Strings
 * are intended for text shown to users; use a regular Structured Field String when Unicode display
 * text is not required.
 *
 * @group Components and Structured Fields
 */
export function displayString(value: string): StructuredFieldDisplayString {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  serializeDisplayString(value)
  return { type: 'display-string', value }
}

/**
 * Creates a component identifier while preserving the supplied parameter order.
 *
 * HTTP field names are normalized to lowercase. Derived component names are case-sensitive.
 *
 * @group Components and Structured Fields
 */
export function component(
  name: string,
  parameters: ComponentParameters = [],
): ParameterizedComponent {
  if (typeof name !== 'string') {
    fail('"name" must be a string')
  }
  return { name: name.startsWith('@') ? name : name.toLowerCase(), parameters }
}

function parameterEntries<T>(
  parameters: ReadonlyArray<readonly [string, T]> | Readonly<Record<string, T>> | undefined,
): Array<[string, T]> {
  if (parameters === undefined) {
    return []
  }
  if (Array.isArray(parameters)) {
    return parameters.map((entry) => {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') {
        fail('Parameters must contain [name, value] tuples')
      }
      return [entry[0], entry[1]]
    })
  }
  if (parameters === null || typeof parameters !== 'object') {
    fail('Parameters must be an ordered array or object')
  }
  return Object.entries(parameters) as Array<[string, T]>
}

function sfItemFromSignatureParameter(
  name: string,
  input: SignatureParameterInput,
): SfBareItem | undefined {
  if (input === undefined) {
    return undefined
  }

  let value: SignatureParameterValue
  if (isDate(input)) {
    const time = Date.prototype.getTime.call(input)
    if (Number.isNaN(time)) {
      fail(`Signature parameter "${name}" must be a valid Date`)
    }
    value = Math.floor(time / 1000)
  } else {
    value = input
  }

  if (typeof value === 'string') {
    return { kind: 'string', value }
  }
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? { kind: 'integer', value }
      : { kind: 'decimal', value: Number(serializeDecimal(value)) }
  }
  if (typeof value === 'boolean') {
    return { kind: 'boolean', value }
  }
  if (isUint8Array(value)) {
    return { kind: 'binary', value: cloneBytes(value) }
  }
  if (
    value !== null &&
    typeof value === 'object' &&
    value.type === 'decimal' &&
    typeof value.value === 'number'
  ) {
    return { kind: 'decimal', value: Number(serializeDecimal(value.value)) }
  }
  if (
    value !== null &&
    typeof value === 'object' &&
    value.type === 'token' &&
    typeof value.value === 'string'
  ) {
    if (!SF_TOKEN.test(value.value)) {
      fail(`Signature parameter "${name}" contains an invalid Structured Field Token`)
    }
    return { kind: 'token', value: value.value }
  }
  if (
    value !== null &&
    typeof value === 'object' &&
    value.type === 'date' &&
    typeof value.value === 'number'
  ) {
    return { kind: 'date', value: date(value.value).value }
  }
  if (
    value !== null &&
    typeof value === 'object' &&
    value.type === 'display-string' &&
    typeof value.value === 'string'
  ) {
    return { kind: 'display-string', value: displayString(value.value).value }
  }
  return fail(`Signature parameter "${name}" has an unsupported value`)
}

function signatureParameterFromSf(item: SfBareItem): SignatureParameterValue {
  switch (item.kind) {
    case 'integer':
    case 'string':
    case 'boolean':
      return item.value
    case 'decimal':
      return { type: 'decimal', value: item.value }
    case 'binary':
      return cloneBytes(item.value)
    case 'token':
      return { type: 'token', value: item.value }
    case 'date':
      return { type: 'date', value: item.value }
    case 'display-string':
      return { type: 'display-string', value: item.value }
  }
}

function normalizeSignatureParameters(
  parameters: SignatureParameters | undefined,
  defaultCreated: number | undefined,
): SfParameters {
  return normalizeSignatureParameterEntries(parameterEntries(parameters), defaultCreated)
}

function normalizeSignatureParameterEntries(
  entries: Array<[string, SignatureParameterInput]>,
  defaultCreated: number | undefined,
): SfParameters {
  const output: SfParameters = []
  const seen = new Set<string>()

  for (const [name] of entries) {
    assertSfKey(name, 'Signature parameter name')
    if (seen.has(name)) {
      fail(`Duplicate signature parameter "${name}"`)
    }
    seen.add(name)
  }

  const created = entries.find(([name]) => name === 'created')
  if ((created === undefined || created[1] === undefined) && defaultCreated !== undefined) {
    output.push(['created', { kind: 'integer', value: defaultCreated }])
  }

  for (const [name, input] of entries) {
    if (name === 'created' && input === false) {
      continue
    }
    const value = sfItemFromSignatureParameter(name, input)
    if (value !== undefined) {
      output.push([name, value])
    }
  }

  validateKnownSignatureParameters(output, false)
  return output
}

function findSfParameter(parameters: SfParameters, name: string): SfBareItem | undefined {
  return parameters.find(([candidate]) => candidate === name)?.[1]
}

function validateKnownSignatureParameters(parameters: SfParameters, requested: boolean): void {
  for (const [name, value] of parameters) {
    switch (name) {
      case 'created':
      case 'expires':
        if (requested) {
          if (value.kind !== 'boolean' || !value.value) {
            fail(`Requested signature parameter "${name}" must be a bare Boolean true`)
          }
        } else if (value.kind !== 'integer') {
          fail(`Signature parameter "${name}" must be an Integer`)
        }
        break
      case 'nonce':
      case 'alg':
      case 'keyid':
      case 'tag':
        if (value.kind !== 'string') {
          fail(`Signature parameter "${name}" must be a String`)
        }
        break
    }
  }
}

function normalizeComponentParameters(parameters: ComponentParameters | undefined): SfParameters {
  const entries = parameterEntries(parameters)
  const output: SfParameters = []
  for (const [name, value] of entries) {
    assertSfKey(name, 'Component parameter name')
    if (output.some(([existing]) => existing === name)) {
      fail(`Duplicate component parameter "${name}"`)
    }
    if (typeof value === 'string') {
      output.push([name, { kind: 'string', value }])
    } else if (typeof value === 'boolean') {
      output.push([name, { kind: 'boolean', value }])
    } else {
      fail(`Component parameter "${name}" must be a string or boolean`)
    }
  }
  return output
}

function publicComponentParameter(value: SfBareItem): ComponentParameterValue {
  if (value.kind === 'string' || value.kind === 'boolean') {
    return value.value
  }
  return fail('Component parameters must be Strings or Booleans')
}

function publicComponent(componentValue: SfItem): MessageComponent {
  if (componentValue.value.kind !== 'string') {
    fail('Covered component identifiers must be Structured Field Strings')
  }
  return {
    name: componentValue.value.value,
    parameters: componentValue.parameters.map(([name, value]) => [
      name,
      publicComponentParameter(value),
    ]),
  }
}

function internalComponent(componentValue: MessageComponent): SfItem {
  return {
    kind: 'item',
    value: { kind: 'string', value: componentValue.name },
    parameters: componentValue.parameters.map(([name, value]) => [
      name,
      typeof value === 'string' ? { kind: 'string', value } : { kind: 'boolean', value },
    ]),
  }
}

function normalizeComponents(components: ReadonlyArray<ComponentIdentifier>): MessageComponent[] {
  if (!Array.isArray(components)) {
    fail('"components" must be an array')
  }
  return components.map((input) => {
    let name: string
    let parameters: ComponentParameters | undefined
    if (typeof input === 'string') {
      name = input
    } else if (input !== null && typeof input === 'object' && typeof input.name === 'string') {
      name = input.name
      parameters = input.parameters
    } else {
      return fail('Invalid HTTP message component identifier')
    }

    if (!name.startsWith('@')) {
      name = name.toLowerCase()
    }
    const normalized: MessageComponent = {
      name,
      parameters: normalizeComponentParameters(parameters).map(([parameterName, value]) => [
        parameterName,
        publicComponentParameter(value),
      ]),
    }
    validateComponentName(normalized)
    return normalized
  })
}

function validateComponentName(componentValue: MessageComponent): void {
  const { name } = componentValue
  if (name === '@signature-params') {
    fail('"@signature-params" cannot be listed as a covered component')
  }
  if (name.startsWith('@')) {
    if (!DERIVED_COMPONENTS.has(name)) {
      fail(`Unknown derived component "${name}"`)
    }
  } else if (!HTTP_FIELD_NAME.test(name)) {
    fail(`Invalid or non-lowercase HTTP field component name "${name}"`)
  }
}

function componentParameterMap(
  componentValue: MessageComponent,
): Map<string, ComponentParameterValue> {
  return new Map(componentValue.parameters)
}

function assertFlag(parameters: Map<string, ComponentParameterValue>, name: string): boolean {
  const value = parameters.get(name)
  if (value === undefined) {
    return false
  }
  if (value !== true) {
    fail(`Component parameter "${name}" must be a bare Boolean true`)
  }
  return true
}

function validateComponentParameters(componentValue: MessageComponent): boolean {
  validateComponentName(componentValue)
  const parameters = componentParameterMap(componentValue)

  if (componentValue.name.startsWith('@')) {
    const allowed = new Set<string>()
    if (componentValue.name === '@query-param') {
      allowed.add('name')
    }
    if (componentValue.name !== '@status') {
      allowed.add('req')
    }
    for (const name of parameters.keys()) {
      if (!allowed.has(name)) {
        fail(`Parameter "${name}" does not apply to "${componentValue.name}"`)
      }
    }

    const relatedRequest = assertFlag(parameters, 'req')
    if (componentValue.name === '@query-param') {
      const name = parameters.get('name')
      if (typeof name !== 'string') {
        fail('"@query-param" requires a String "name" parameter')
      }
    }

    return relatedRequest
  }

  const allowed = new Set(['sf', 'key', 'bs', 'tr', 'req'])
  for (const name of parameters.keys()) {
    if (!allowed.has(name)) {
      fail(`Unknown HTTP field component parameter "${name}"`)
    }
  }

  const sf = assertFlag(parameters, 'sf')
  const bs = assertFlag(parameters, 'bs')
  assertFlag(parameters, 'tr')
  const relatedRequest = assertFlag(parameters, 'req')
  const key = parameters.get('key')
  if (key !== undefined && typeof key !== 'string') {
    fail('Component parameter "key" must be a String')
  }
  if (bs && (sf || key !== undefined)) {
    fail('Component parameter "bs" is incompatible with "sf" and "key"')
  }
  return relatedRequest
}

function validateComponentForTarget(componentValue: MessageComponent, request: boolean): void {
  const relatedRequest = validateComponentParameters(componentValue)

  if (componentValue.name.startsWith('@')) {
    if (componentValue.name === '@status') {
      if (request) {
        fail('"@status" cannot be used with a request')
      }
    } else if (request) {
      if (relatedRequest) {
        fail('"req" cannot be used with a request signature')
      }
    } else if (!relatedRequest) {
      fail(`"${componentValue.name}" requires "req" in a response signature`)
    }
    return
  }

  if (request && relatedRequest) {
    fail('"req" cannot be used with a request signature')
  }
}

function validateComponentForMessage(
  componentValue: MessageComponent,
  message: Request | Response,
): void {
  validateComponentForTarget(componentValue, isRequest(message))
}

function sameBareItem(left: SfBareItem, right: SfBareItem): boolean {
  if (left.kind !== right.kind) {
    return false
  }
  if (left.kind === 'binary' && right.kind === 'binary') {
    return bytesEqual(left.value, right.value)
  }
  return left.value === right.value
}

function sameComponent(left: MessageComponent, right: MessageComponent): boolean {
  if (left.name !== right.name || left.parameters.length !== right.parameters.length) {
    return false
  }
  const rightParameters = new Map(right.parameters)
  return left.parameters.every(([name, value]) => rightParameters.get(name) === value)
}

function assertUniqueComponents(components: ReadonlyArray<MessageComponent>): void {
  for (let index = 0; index < components.length; index++) {
    for (let other = 0; other < index; other++) {
      const componentValue = components[index]!
      const otherComponent = components[other]!
      if (sameComponent(componentValue, otherComponent)) {
        fail(`Duplicate covered component "${componentValue.name}"`)
      }

      const key = componentParameterMap(componentValue).get('key')
      const otherParameters = componentParameterMap(otherComponent)
      if (
        typeof key === 'string' &&
        componentValue.name === otherComponent.name &&
        key === otherParameters.get('key') &&
        componentParameterMap(componentValue).get('req') === otherParameters.get('req') &&
        componentParameterMap(componentValue).get('tr') === otherParameters.get('tr')
      ) {
        fail(`Duplicate covered dictionary key "${componentValue.name}";key="${key}"`)
      }
    }
  }
}

function signatureParametersValue(
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
): SfInnerList {
  return { kind: 'inner-list', value: components.map(internalComponent), parameters }
}

function signatureParametersPublic(
  parameters: SfParameters,
): Array<readonly [string, SignatureParameterValue]> {
  return parameters.map(([name, value]) => [name, signatureParameterFromSf(value)])
}

function timestamp(input: number | Date | undefined): number {
  const value = isDate(input)
    ? Math.floor(Date.prototype.getTime.call(input) / 1000)
    : input === undefined
      ? Math.floor(Date.now() / 1000)
      : input
  if (!Number.isSafeInteger(value)) {
    fail('Clock value must be an integer UNIX timestamp')
  }
  return value
}

function getTargetUri(request: Request): string {
  const hash = request.url.indexOf('#')
  const value = hash === -1 ? request.url : request.url.slice(0, hash)
  if (!ASCII.test(value)) {
    fail('Request target URI must contain only ASCII characters')
  }
  return value
}

function getRequestUrl(request: Request): URL {
  try {
    return new URL(getTargetUri(request))
  } catch (cause) {
    throw new TypeError('Request does not have a valid target URI', { cause })
  }
}

function formPercentEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()~]/g, (character) => {
    return `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  })
}

function deriveQueryParameter(request: Request, encodedName: string): string {
  const target = getTargetUri(request)
  const queryStart = target.indexOf('?')
  const query = queryStart === -1 ? '' : target.slice(queryStart + 1)
  const matches: string[] = []
  for (const [name, value] of new URLSearchParams(query)) {
    if (formPercentEncode(name) === encodedName) {
      matches.push(formPercentEncode(value))
    }
  }
  if (matches.length === 0) {
    fail(`Query parameter "${encodedName}" is not present`)
  }
  if (matches.length !== 1) {
    fail(`Query parameter "${encodedName}" occurs more than once`)
  }
  return matches[0]!
}

function deriveComponentValue(componentValue: MessageComponent, request: Request): string {
  const parameters = componentParameterMap(componentValue)
  const target = getTargetUri(request)
  const url = getRequestUrl(request)
  switch (componentValue.name) {
    case '@method':
      return request.method
    case '@target-uri':
      return target
    case '@authority':
      return url.host
    case '@scheme':
      return url.protocol.slice(0, -1).toLowerCase()
    case '@request-target': {
      const queryStart = target.indexOf('?')
      return url.pathname + (queryStart === -1 ? '' : target.slice(queryStart))
    }
    case '@path':
      return url.pathname || '/'
    case '@query': {
      const queryStart = target.indexOf('?')
      return queryStart === -1 ? '?' : target.slice(queryStart)
    }
    case '@query-param':
      return deriveQueryParameter(request, parameters.get('name') as string)
    default:
      return fail(`Derived component "${componentValue.name}" does not apply to a request`)
  }
}

function normalizeFieldLine(value: string): string {
  return value.replace(/^[ \t]+|[ \t]+$/g, '').replace(/\r\n[ \t]+/g, ' ')
}

function assertFieldValue(value: string, name: string): void {
  if (/[\r\n]/.test(value)) {
    fail(`HTTP field "${name}" contains a newline`)
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) {
    fail(`HTTP field "${name}" contains an invalid control character`)
  }
}

function defaultFieldValues(
  message: Request | Response,
  name: string,
  trailers: boolean,
): ReadonlyArray<string> | undefined {
  if (trailers) {
    fail(`Trailer field "${name}" is not exposed by Fetch; provide the "fieldValues" option`)
  }
  if (!message.headers.has(name)) {
    return undefined
  }
  if (name === 'set-cookie') {
    const headers = message.headers as Headers & { getSetCookie?: () => string[] }
    if (typeof headers.getSetCookie === 'function') {
      return headers.getSetCookie()
    }
  }
  return [message.headers.get(name)!]
}

function getFieldValues(
  message: Request | Response,
  name: string,
  trailers: boolean,
  relatedRequest: boolean,
  options: SignatureContext,
): string[] {
  const values =
    options.fieldValues === undefined
      ? defaultFieldValues(message, name, trailers)
      : options.fieldValues(message, name, { trailers, relatedRequest })
  if (values !== undefined && !Array.isArray(values)) {
    fail('"fieldValues" must return an array of strings or undefined')
  }
  if (values === undefined || values.length === 0) {
    fail(`${trailers ? 'Trailer' : 'Header'} field "${name}" is not present`)
  }
  return values.map((value) => {
    if (typeof value !== 'string') {
      fail('"fieldValues" must return strings')
    }
    const normalized = normalizeFieldLine(value)
    assertFieldValue(normalized, name)
    return normalized
  })
}

function latin1Bytes(value: string, name: string): Uint8Array {
  const output = new Uint8Array(value.length)
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code > 0xff) {
      fail(`HTTP field "${name}" cannot be represented as bytes`)
    }
    output[i] = code
  }
  return output
}

function structuredFieldType(
  name: string,
  options: SignatureContext,
): StructuredFieldType | undefined {
  if (name === 'signature-input' || name === 'signature' || name === 'accept-signature') {
    return 'dictionary'
  }
  if (options.structuredFields !== undefined) {
    if (options.structuredFields === null || typeof options.structuredFields !== 'object') {
      fail('"structuredFields" must be an object')
    }
    if (!Object.hasOwn(options.structuredFields, name)) {
      return undefined
    }
    const configured = options.structuredFields[name]
    if (configured === 'dictionary' || configured === 'list' || configured === 'item') {
      return configured
    }
    fail(`Structured Field type for "${name}" is invalid`)
  }
  return undefined
}

function fieldComponentValue(
  componentValue: MessageComponent,
  message: Request | Response,
  relatedRequest: boolean,
  options: SignatureContext,
): string {
  const parameters = componentParameterMap(componentValue)
  const sf = assertFlag(parameters, 'sf')
  const bs = assertFlag(parameters, 'bs')
  const trailers = assertFlag(parameters, 'tr')
  const key = parameters.get('key')

  const fetchExposesOccurrences =
    componentValue.name === 'set-cookie' &&
    typeof (message.headers as Headers & { getSetCookie?: unknown }).getSetCookie === 'function'
  if (bs && options.fieldValues === undefined && !fetchExposesOccurrences) {
    fail(`"${componentValue.name}";bs requires "fieldValues" because Fetch hides field occurrences`)
  }

  const values = getFieldValues(message, componentValue.name, trailers, relatedRequest, options)

  if (bs) {
    const list: SfList = values.map((value) => ({
      kind: 'item',
      value: { kind: 'binary', value: latin1Bytes(value, componentValue.name) },
      parameters: [],
    }))
    return serializeList(list)
  }

  const combined = values.join(', ')
  if (key !== undefined) {
    const type = structuredFieldType(componentValue.name, options)
    if (type !== undefined && type !== 'dictionary') {
      fail(
        `Structured Field type for "${componentValue.name}" must be "dictionary" with the "key" parameter`,
      )
    }
    const dictionary = parseStructuredField(combined, 'dictionary') as SfDictionary
    const member = dictionary.find(([name]) => name === key)?.[1]
    if (member === undefined) {
      fail(`Structured Field "${componentValue.name}" has no member "${key}"`)
    }
    return serializeMember(member)
  }

  if (sf) {
    const type = structuredFieldType(componentValue.name, options)
    if (type === undefined) {
      fail(`Structured Field type for "${componentValue.name}" is required by the "sf" parameter`)
    }
    return serializeStructuredField(parseStructuredField(combined, type), type)
  }

  return combined
}

function componentValue(
  componentValue: MessageComponent,
  message: Request | Response,
  options: SignatureContext,
): string {
  validateComponentForMessage(componentValue, message)
  const parameters = componentParameterMap(componentValue)
  const relatedRequest = parameters.has('req')
  let source: Request | Response = message
  if (relatedRequest) {
    if (options.request === undefined) {
      fail(`Component "${componentValue.name}";req requires the related request`)
    }
    assertMessage(options.request)
    if (!isRequest(options.request)) {
      fail('"request" must be the related Request')
    }
    source = options.request
  }

  let value: string
  if (componentValue.name.startsWith('@')) {
    if (componentValue.name === '@status') {
      const status = (source as Response).status
      if (!Number.isInteger(status) || status < 100 || status > 599) {
        fail('"@status" requires an unfiltered HTTP response status')
      }
      value = String(status)
    } else {
      if (!isRequest(source)) {
        fail(`Derived component "${componentValue.name}" requires a request context`)
      }
      value = deriveComponentValue(componentValue, source)
    }
    if (!PRINTABLE_ASCII.test(value) || value.startsWith(' ') || value.endsWith(' ')) {
      fail(`Derived component "${componentValue.name}" has an invalid value`)
    }
  } else {
    value = fieldComponentValue(componentValue, source, relatedRequest, options)
  }
  assertFieldValue(value, componentValue.name)
  return value
}

function buildSignatureBase(
  message: Request | Response,
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
  options: SignatureContext,
): string {
  assertUniqueComponents(components)
  let output = ''
  for (const identifier of components) {
    const serializedIdentifier = serializeItem(internalComponent(identifier))
    output += `${serializedIdentifier}: ${componentValue(identifier, message, options)}\n`
  }
  output += `"@signature-params": ${serializeInnerList(
    signatureParametersValue(components, parameters),
  )}`
  assertAscii(output, 'Signature base')
  return output
}

function assertSignatureBaseUnchanged(
  guard: MessageMutationGuard,
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
  options: SignatureContext,
  expected: string,
  operation: 'signing' | 'verification',
): void {
  assertMessageUnchanged(guard, operation)
  let current: string
  try {
    current = buildSignatureBase(guard.message, components, parameters, options)
  } catch (cause) {
    throw new Error(`HTTP signature context changed during ${operation}`, { cause })
  }
  assertMessageUnchanged(guard, operation)
  if (current !== expected) {
    throw new Error(`HTTP signature context changed during ${operation}`)
  }
}

/**
 * Creates the RFC 9421 signature base for a Fetch `Request` or `Response`.
 *
 * Unlike {@link createSignature}, this low-level function does not add a default `created`
 * parameter.
 *
 * @group Components and Structured Fields
 */
export function createSignatureBase(
  message: Request | Response,
  options: SignatureBaseOptions,
): string {
  assertMessage(message)
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const components = normalizeComponents(options.components)
  const parameters = normalizeSignatureParameters(options.parameters, undefined)
  return buildSignatureBase(message, components, parameters, options)
}

interface ParsedSignatureInput {
  readonly label: string
  readonly components: MessageComponent[]
  readonly parameters: SfParameters
}

interface ParsedSignatureValue {
  readonly label: string
  readonly value: Uint8Array<ArrayBuffer>
}

function parseSignatureInputMember(label: string, member: SfMember): ParsedSignatureInput {
  if (member.kind !== 'inner-list') {
    fail(`Signature-Input member "${label}" must be an Inner List`)
  }
  return { label, components: member.value.map(publicComponent), parameters: member.parameters }
}

function validateSignatureInput(input: ParsedSignatureInput): ParsedSignatureInput {
  validateKnownSignatureParameters(input.parameters, false)
  for (const componentValue of input.components) {
    validateComponentParameters(componentValue)
  }
  assertUniqueComponents(input.components)
  return input
}

function parseSignatureValueMember(label: string, member: SfMember): ParsedSignatureValue {
  if (member.kind !== 'item' || member.value.kind !== 'binary') {
    fail(`Signature member "${label}" must be a Byte Sequence`)
  }
  return { label, value: cloneBytes(member.value.value) }
}

function parseSignatureInputInternal(value: string): ParsedSignatureInput[] {
  const dictionary = parseStructuredField(value, 'dictionary', true) as SfDictionary
  return dictionary.map(([label, member]) => {
    return validateSignatureInput(parseSignatureInputMember(label, member))
  })
}

function parseSignatureInternal(value: string): ParsedSignatureValue[] {
  const dictionary = parseStructuredField(value, 'dictionary', true) as SfDictionary
  return dictionary.map(([label, member]) => parseSignatureValueMember(label, member))
}

/**
 * Parses a `Signature-Input` field value.
 *
 * @group Recipient
 */
export function parseSignatureInput(
  value: string,
): ReadonlyArray<Omit<MessageSignature, 'signature'>> {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  return parseSignatureInputInternal(value).map(({ label, components, parameters }) => ({
    label,
    components,
    parameters: signatureParametersPublic(parameters),
  }))
}

/**
 * Parses a `Signature` field value.
 *
 * @group Recipient
 */
export function parseSignature(
  value: string,
): ReadonlyArray<Readonly<{ label: string; signature: Uint8Array<ArrayBuffer> }>> {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  return parseSignatureInternal(value).map(({ label, value: signature }) => ({ label, signature }))
}

function messageSignatureDictionaries(headers: Headers): {
  readonly inputs: SfDictionary
  readonly values: SfDictionary
} {
  const signatureInput = headers.get('signature-input')
  const signature = headers.get('signature')
  if (signatureInput === null && signature === null) {
    return { inputs: [], values: [] }
  }
  if (signatureInput === null || signature === null) {
    fail('Signature and Signature-Input fields must both be present')
  }
  const inputs = parseStructuredField(signatureInput, 'dictionary', true) as SfDictionary
  const values = parseStructuredField(signature, 'dictionary', true) as SfDictionary
  const inputLabels = new Set(inputs.map(([label]) => label))
  const valueLabels = new Set(values.map(([label]) => label))
  if (
    inputLabels.size !== valueLabels.size ||
    [...inputLabels].some((label) => !valueLabels.has(label))
  ) {
    fail('Signature and Signature-Input fields must contain identical labels')
  }
  return { inputs, values }
}

function messageSignatureFields(headers: Headers): {
  readonly inputs: ParsedSignatureInput[]
  readonly values: ParsedSignatureValue[]
} {
  const dictionaries = messageSignatureDictionaries(headers)
  return {
    inputs: dictionaries.inputs.map(([label, member]) => {
      return validateSignatureInput(parseSignatureInputMember(label, member))
    }),
    values: dictionaries.values.map(([label, member]) => {
      return parseSignatureValueMember(label, member)
    }),
  }
}

/**
 * Parses and pairs all signatures carried by a Fetch message.
 *
 * @group Recipient
 */
export function getSignatures(message: Request | Response): ReadonlyArray<MessageSignature> {
  assertMessage(message)
  const { inputs, values } = messageSignatureFields(message.headers)
  return inputs.map(({ label, components, parameters }) => {
    const signature = values.find((entry) => entry.label === label)!.value
    return { label, components, parameters: signatureParametersPublic(parameters), signature }
  })
}

function selectSignature(
  message: Request | Response,
  label: string | undefined,
): {
  readonly input: ParsedSignatureInput
  readonly signature: Uint8Array<ArrayBuffer>
  readonly public: MessageSignature
} {
  const { inputs, values } = messageSignatureDictionaries(message.headers)
  if (inputs.length === 0) {
    fail('Message does not contain an HTTP message signature')
  }
  let inputMember: SfDictionaryEntry | undefined
  if (label === undefined) {
    if (inputs.length !== 1) {
      fail('"label" is required when a message contains multiple signatures')
    }
    inputMember = inputs[0]
  } else {
    assertSfKey(label, 'Signature label')
    inputMember = inputs.find(([candidate]) => candidate === label)
    if (inputMember === undefined) {
      fail(`Message does not contain signature label "${label}"`)
    }
  }
  if (inputMember === undefined) {
    return fail('Unable to select an HTTP message signature')
  }
  const input = validateSignatureInput(parseSignatureInputMember(...inputMember))
  const valueMember = values.find(([candidate]) => candidate === input.label)!
  const signature = parseSignatureValueMember(...valueMember).value
  return {
    input,
    signature,
    public: {
      label: input.label,
      components: input.components,
      parameters: signatureParametersPublic(input.parameters),
      signature,
    },
  }
}

function createSigner(factory: SignerFactory): Readonly<Signer> {
  if (typeof factory !== 'function') {
    fail('"signer" must be a factory function')
  }
  let signer: Readonly<Signer>
  try {
    signer = factory()
    if (
      signer === null ||
      typeof signer !== 'object' ||
      signer.type !== 'signer' ||
      typeof signer.alg !== 'string' ||
      signer.alg.length === 0 ||
      typeof signer.sign !== 'function'
    ) {
      throw new TypeError('Invalid signer implementation')
    }
  } catch (cause) {
    throw new TypeError('Invalid "signer"', { cause })
  }
  return signer
}

function createVerifier(
  factory: VerifierFactory,
  signature: Readonly<MessageSignature>,
  context: Readonly<VerificationContext>,
): Readonly<Verifier> {
  if (typeof factory !== 'function') {
    fail('"verifier" must be a factory function')
  }
  let verifier: Readonly<Verifier>
  try {
    verifier = factory(signature, context)
    if (
      verifier === null ||
      typeof verifier !== 'object' ||
      verifier.type !== 'verifier' ||
      typeof verifier.alg !== 'string' ||
      verifier.alg.length === 0 ||
      typeof verifier.verify !== 'function'
    ) {
      throw new TypeError('Invalid verifier implementation')
    }
  } catch (cause) {
    throw new TypeError('Invalid "verifier"', { cause })
  }
  return verifier
}

function findPublicParameter(
  parameters: ReadonlyArray<readonly [string, SignatureParameterValue]>,
  name: string,
): SignatureParameterValue | undefined {
  return parameters.find(([candidate]) => candidate === name)?.[1]
}

function cloneSignatureParameterValue(value: SignatureParameterValue): SignatureParameterValue {
  if (isUint8Array(value)) {
    return cloneBytes(value)
  }
  if (value !== null && typeof value === 'object') {
    return { ...value }
  }
  return value
}

function cloneMessageSignature(signature: Readonly<MessageSignature>): MessageSignature {
  return {
    label: signature.label,
    components: signature.components.map(({ name, parameters }) => ({
      name,
      parameters: parameters.map(([parameterName, value]) => [parameterName, value]),
    })),
    parameters: signature.parameters.map(([name, value]) => [
      name,
      cloneSignatureParameterValue(value),
    ]),
    signature: cloneBytes(signature.signature),
  }
}

function signatureFieldValues(
  label: string,
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
  signature: Uint8Array,
): { readonly signatureInput: string; readonly signatureField: string } {
  const inputDictionary: SfDictionary = [[label, signatureParametersValue(components, parameters)]]
  const signatureDictionary: SfDictionary = [
    [label, { kind: 'item', value: { kind: 'binary', value: signature }, parameters: [] }],
  ]
  return {
    signatureInput: serializeDictionary(inputDictionary),
    signatureField: serializeDictionary(signatureDictionary),
  }
}

interface SignatureCreation {
  readonly fields: SignatureFields
  assertUnchanged(): void
}

async function createSignatureInternal(
  message: Request | Response,
  options: SignOptions,
): Promise<SignatureCreation> {
  assertMessage(message)
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const label = options.label ?? 'sig1'
  assertSfKey(label, 'Signature label')

  const existing = messageSignatureDictionaries(message.headers)
  if (existing.inputs.some(([existingLabel]) => existingLabel === label)) {
    fail(`Signature label "${label}" is already present`)
  }

  const components = normalizeComponents(options.components)
  for (const componentValue of components) {
    const componentParameters = componentParameterMap(componentValue)
    if (
      (componentValue.name === 'signature' || componentValue.name === 'signature-input') &&
      componentParameters.get('req') !== true &&
      componentParameters.get('tr') !== true &&
      componentParameters.get('key') === undefined
    ) {
      fail('A signature cannot cover fields to which it is being appended')
    }
  }
  const parameters = normalizeSignatureParameters(options.parameters, timestamp(options.now))

  const guard = createMessageMutationGuard(message, options)
  const base = buildSignatureBase(message, components, parameters, options)
  assertMessageUnchanged(guard, 'signing')

  const signer = createSigner(options.signer)
  const algorithm = signer.alg
  assertSignatureBaseUnchanged(guard, components, parameters, options, base, 'signing')

  const signaledAlgorithm = findSfParameter(parameters, 'alg')
  if (
    signaledAlgorithm !== undefined &&
    (signaledAlgorithm.kind !== 'string' || signaledAlgorithm.value !== algorithm)
  ) {
    fail('The signer algorithm does not match the "alg" signature parameter')
  }

  let signature: Uint8Array
  try {
    signature = await signer.sign(encoder.encode(base))
  } catch (cause) {
    throw new Error('Failed to create HTTP message signature', { cause })
  }
  if (!isUint8Array(signature)) {
    fail('Signer output must be a Uint8Array')
  }
  assertSignatureBaseUnchanged(guard, components, parameters, options, base, 'signing')

  const ownedSignature = cloneBytes(signature)
  const serializedFields = signatureFieldValues(label, components, parameters, ownedSignature)
  const fields: SignatureFields = {
    label,
    components,
    parameters: signatureParametersPublic(parameters),
    signature: ownedSignature,
    ...serializedFields,
  }
  return {
    fields,
    assertUnchanged() {
      assertSignatureBaseUnchanged(guard, components, parameters, options, base, 'signing')
    },
  }
}

/**
 * Creates one HTTP message signature without modifying or cloning the Fetch message.
 *
 * The returned one-member field values can be attached while constructing a message or passed to
 * {@link appendSignature}. A `created` timestamp is added by default; pass `created: false` in
 * `parameters` to explicitly omit it.
 *
 * @group Sender
 */
export async function createSignature(
  message: Request | Response,
  options: SignOptions,
): Promise<SignatureFields> {
  return (await createSignatureInternal(message, options)).fields
}

function appendFieldValue(headers: Headers, name: string, value: string): void {
  const existing = headers.get(name)
  headers.set(name, existing === null ? value : `${existing}, ${value}`)
}

function appendSignatureHeaders(headers: Headers, fields: SignatureFields): Headers {
  const output = new Headers(headers)
  const existing = messageSignatureDictionaries(output)
  if (existing.inputs.some(([label]) => label === fields.label)) {
    fail(`Signature label "${fields.label}" is already present`)
  }

  const input = parseSignatureInputInternal(fields.signatureInput)
  const signature = parseSignatureInternal(fields.signatureField)
  if (
    input.length !== 1 ||
    signature.length !== 1 ||
    input[0]!.label !== fields.label ||
    signature[0]!.label !== fields.label
  ) {
    fail('"fields" does not contain exactly one matching signature label')
  }

  appendFieldValue(output, 'signature-input', fields.signatureInput)
  appendFieldValue(output, 'signature', fields.signatureField)
  messageSignatureDictionaries(output)
  return output
}

/**
 * Adds one signature to `Headers` and returns a new `Headers` object.
 *
 * @group Sender
 */
export function appendSignature(headers: Headers, fields: SignatureFields): Headers
/**
 * Adds one signature to a `Request` and returns a new `Request`.
 *
 * The returned message passes the source body to a new Fetch message without explicitly cloning or
 * buffering it. The source body's observable state is runtime-dependent. Consume the returned
 * request and do not rely on the source request afterward. Use {@link createSignature} and construct
 * the final message explicitly when both bodies must remain readable.
 */
export function appendSignature(headers: Request, fields: SignatureFields): Request
/**
 * Adds one signature to a `Response` and returns a new `Response`.
 *
 * The returned message passes the source body to a new Fetch message without explicitly cloning or
 * buffering it. The source body's observable state is runtime-dependent. Consume the returned
 * response and do not rely on the source response afterward. Use {@link createSignature} and
 * construct the final message explicitly when both bodies must remain readable.
 *
 * Fetch does not provide a way to clone a network response while changing its immutable headers.
 * The returned response preserves status, status text, headers, and body, but Fetch-managed
 * metadata such as `url`, `redirected`, and `type` cannot be preserved.
 */
export function appendSignature(headers: Response, fields: SignatureFields): Response
export function appendSignature(
  headers: Headers | Request | Response,
  fields: SignatureFields,
): Headers | Request | Response
export function appendSignature(
  message: Headers | Request | Response,
  fields: SignatureFields,
): Headers | Request | Response {
  if (fields === null || typeof fields !== 'object') {
    fail('"fields" must be a SignatureFields object')
  }
  if (isHeaders(message)) {
    return appendSignatureHeaders(message, fields)
  }
  assertMessage(message)
  const headers = appendSignatureHeaders(message.headers, fields)
  if (isRequest(message)) {
    return new Request(message, { headers })
  }
  if (message.status === 0) {
    fail('Opaque and error responses cannot carry HTTP message signatures')
  }
  return new Response(message.body, {
    headers,
    status: message.status,
    statusText: message.statusText,
  })
}

/**
 * Creates and appends one HTTP message signature.
 *
 * Appending passes the source body to a new Fetch message without explicitly cloning or buffering
 * it. The source body's observable state is runtime-dependent. Consume the returned message and do
 * not rely on the source message afterward. Use {@link createSignature} and construct the final
 * message explicitly when both bodies must remain readable.
 *
 * @group Sender
 */
export function sign(message: Request, options: SignOptions): Promise<Request>
export function sign(message: Response, options: SignOptions): Promise<Response>
export function sign(message: Request | Response, options: SignOptions): Promise<Request | Response>
export async function sign(
  message: Request | Response,
  options: SignOptions,
): Promise<Request | Response> {
  const created = await createSignatureInternal(message, options)
  created.assertUnchanged()
  return isRequest(message)
    ? appendSignature(message, created.fields)
    : appendSignature(message, created.fields)
}

function snapshotVerificationPolicy(policy: VerificationPolicy): VerificationPolicy {
  if (policy === null || typeof policy !== 'object') {
    fail('"policy" must be an object')
  }
  if (
    !Array.isArray(policy.requiredComponents) ||
    !Array.isArray(policy.requiredParameters) ||
    !Array.isArray(policy.algorithms)
  ) {
    fail('"policy" must define requiredComponents, requiredParameters, and algorithms arrays')
  }
  if (policy.validate !== undefined && typeof policy.validate !== 'function') {
    fail('"policy.validate" must be a function')
  }
  return {
    requiredComponents: normalizeComponents(policy.requiredComponents),
    requiredParameters: [...policy.requiredParameters],
    algorithms: [...policy.algorithms],
    maxAge: policy.maxAge,
    clockSkew: policy.clockSkew,
    now: policy.now === undefined ? undefined : timestamp(policy.now),
    validate: policy.validate,
  }
}

function validateVerificationPolicy(
  signature: Readonly<MessageSignature>,
  policy: VerificationPolicy,
): void {
  if (policy === null || typeof policy !== 'object') {
    fail('"policy" must be an object')
  }
  if (
    !Array.isArray(policy.requiredComponents) ||
    !Array.isArray(policy.requiredParameters) ||
    !Array.isArray(policy.algorithms)
  ) {
    fail('"policy" must define requiredComponents, requiredParameters, and algorithms arrays')
  }
  if (policy.algorithms.length === 0) {
    fail('"policy.algorithms" must not be empty')
  }
  if (
    policy.algorithms.some((algorithm) => typeof algorithm !== 'string' || algorithm.length === 0)
  ) {
    fail('"policy.algorithms" must contain non-empty strings')
  }
  const signaledAlgorithm = findPublicParameter(signature.parameters, 'alg')
  if (typeof signaledAlgorithm === 'string' && !policy.algorithms.includes(signaledAlgorithm)) {
    fail(`Algorithm "${signaledAlgorithm}" is not allowed by policy`)
  }

  const requiredComponents = normalizeComponents(policy.requiredComponents)
  for (const required of requiredComponents) {
    if (!signature.components.some((covered) => sameComponent(required, covered))) {
      fail(`Required component "${required.name}" is not covered`)
    }
  }

  for (const parameter of policy.requiredParameters) {
    if (typeof parameter !== 'string') {
      fail('"policy.requiredParameters" must contain strings')
    }
    assertSfKey(parameter, 'Required signature parameter')
    if (findPublicParameter(signature.parameters, parameter) === undefined) {
      fail(`Required signature parameter "${parameter}" is missing`)
    }
  }

  const skew = policy.clockSkew ?? 0
  if (!Number.isFinite(skew) || skew < 0) {
    fail('"policy.clockSkew" must be a non-negative number')
  }
  const now = timestamp(policy.now)
  const created = findPublicParameter(signature.parameters, 'created')
  const expires = findPublicParameter(signature.parameters, 'expires')
  if (created !== undefined && typeof created !== 'number') {
    fail('Signature parameter "created" must be an Integer')
  }
  if (expires !== undefined && typeof expires !== 'number') {
    fail('Signature parameter "expires" must be an Integer')
  }
  if (created !== undefined && created > now + skew) {
    fail('HTTP message signature was created in the future')
  }
  if (expires !== undefined && expires < now - skew) {
    fail('HTTP message signature has expired')
  }
  if (created !== undefined && expires !== undefined && expires < created) {
    fail('HTTP message signature expires before it was created')
  }

  if (policy.maxAge !== undefined) {
    if (!Number.isFinite(policy.maxAge) || policy.maxAge < 0) {
      fail('"policy.maxAge" must be a non-negative number')
    }
    if (created === undefined) {
      fail('"policy.maxAge" requires the "created" signature parameter')
    }
    if (now - created > policy.maxAge + skew) {
      fail('HTTP message signature is older than policy permits')
    }
  }
}

function validateVerificationAlgorithm(
  signature: Readonly<MessageSignature>,
  algorithm: string,
  policy: VerificationPolicy,
): void {
  if (!policy.algorithms.includes(algorithm)) {
    fail(`Algorithm "${algorithm}" is not allowed by policy`)
  }

  const signaledAlgorithm = findPublicParameter(signature.parameters, 'alg')
  if (signaledAlgorithm !== undefined && signaledAlgorithm !== algorithm) {
    fail('The verifier algorithm does not match the "alg" signature parameter')
  }
}

/**
 * Verifies and applies explicit application policy to one HTTP message signature.
 *
 * The function throws on parse, policy, context, key-selection, algorithm, or cryptographic
 * failure. When multiple signatures are present, callers must select a label explicitly.
 *
 * @group Recipient
 */
export async function verify(
  message: Request | Response,
  options: VerifyOptions,
): Promise<VerifiedSignature> {
  assertMessage(message)
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const policy = snapshotVerificationPolicy(options.policy)
  const selected = selectSignature(message, options.label)
  for (const componentValue of selected.input.components) {
    validateComponentForMessage(componentValue, message)
  }

  const signature = cloneMessageSignature(selected.public)
  validateVerificationPolicy(signature, policy)
  const guard = createMessageMutationGuard(message, options)
  const base = buildSignatureBase(
    message,
    selected.input.components,
    selected.input.parameters,
    options,
  )
  assertMessageUnchanged(guard, 'verification')

  const context: VerificationContext = { message, request: options.request }
  const verifier = createVerifier(options.verifier, cloneMessageSignature(signature), {
    ...context,
  })
  const algorithm = verifier.alg
  validateVerificationAlgorithm(signature, algorithm, policy)

  assertSignatureBaseUnchanged(
    guard,
    selected.input.components,
    selected.input.parameters,
    options,
    base,
    'verification',
  )
  let valid: boolean
  try {
    valid = await verifier.verify(encoder.encode(base), cloneBytes(selected.signature))
  } catch (cause) {
    throw new Error('Failed to verify HTTP message signature', { cause })
  }
  if (typeof valid !== 'boolean') {
    fail('Verifier output must be a boolean')
  }
  assertSignatureBaseUnchanged(
    guard,
    selected.input.components,
    selected.input.parameters,
    options,
    base,
    'verification',
  )
  if (!valid) {
    throw new Error('HTTP message signature verification failed')
  }
  validateVerificationPolicy(signature, policy)
  if (policy.validate !== undefined) {
    await policy.validate(cloneMessageSignature(signature), {
      message,
      request: context.request,
      algorithm,
    })
    assertSignatureBaseUnchanged(
      guard,
      selected.input.components,
      selected.input.parameters,
      options,
      base,
      'verification',
    )
    validateVerificationPolicy(signature, policy)
  }
  return { ...signature, algorithm }
}

/** A requested HTTP message signature parsed from `Accept-Signature`. */
export interface SignatureRequest {
  readonly label: string
  readonly components: ReadonlyArray<MessageComponent>
  readonly parameters: ReadonlyArray<readonly [name: string, value: SignatureParameterValue]>
}

/** Input used to create an `Accept-Signature` member. */
export interface SignatureRequestInput {
  readonly label: string
  readonly components: ReadonlyArray<ComponentIdentifier>
  readonly parameters?: SignatureParameters
}

/** Options for fulfilling an `Accept-Signature` member. */
export interface RequestedSignOptions extends SignatureContext {
  readonly signer: SignerFactory
  /**
   * Values that satisfy requested parameters and any additional parameters selected by the signer.
   * An `expires` request requires an explicit `expires` value here.
   */
  readonly parameters?: SignatureParameters
  readonly now?: number | Date
}

function normalizeRequestedParameters(parameters: SignatureParameters | undefined): SfParameters {
  const output: SfParameters = []
  const seen = new Set<string>()
  for (const [name, input] of parameterEntries(parameters)) {
    assertSfKey(name, 'Requested signature parameter name')
    if (seen.has(name)) {
      fail(`Duplicate requested signature parameter "${name}"`)
    }
    seen.add(name)
    const value = sfItemFromSignatureParameter(name, input)
    if (value !== undefined) {
      output.push([name, value])
    }
  }
  validateKnownSignatureParameters(output, true)
  return output
}

function parseAcceptSignatureInternal(value: string): ParsedSignatureInput[] {
  const dictionary = parseStructuredField(value, 'dictionary', true) as SfDictionary
  return dictionary.map(([label, member]) => {
    if (member.kind !== 'inner-list') {
      fail(`Accept-Signature member "${label}" must be an Inner List`)
    }
    validateKnownSignatureParameters(member.parameters, true)
    const components = member.value.map(publicComponent)
    for (const componentValue of components) {
      validateComponentParameters(componentValue)
    }
    assertUniqueComponents(components)
    return { label, components, parameters: member.parameters }
  })
}

/**
 * Parses an `Accept-Signature` field value.
 *
 * @group Signature Negotiation
 */
export function parseAcceptSignature(value: string): ReadonlyArray<SignatureRequest> {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  return parseAcceptSignatureInternal(value).map(({ label, components, parameters }) => ({
    label,
    components,
    parameters: signatureParametersPublic(parameters),
  }))
}

/**
 * Parses all signature requests carried by a Fetch message.
 *
 * @group Signature Negotiation
 */
export function getSignatureRequests(message: Request | Response): ReadonlyArray<SignatureRequest> {
  assertMessage(message)
  const value = message.headers.get('accept-signature')
  if (value === null) {
    return []
  }
  const requests = parseAcceptSignature(value)
  const targetIsRequest = !isRequest(message)
  for (const request of requests) {
    for (const componentValue of request.components) {
      validateComponentForTarget(componentValue, targetIsRequest)
    }
  }
  return requests
}

/**
 * Serializes one or more signature requests as an `Accept-Signature` Structured Field Dictionary.
 *
 * Use {@link appendAcceptSignature} when the sender message is available so component applicability
 * can also be checked against the type of the requested target message.
 *
 * @group Signature Negotiation
 */
export function createAcceptSignature(requests: ReadonlyArray<SignatureRequestInput>): string {
  if (!Array.isArray(requests) || requests.length === 0) {
    fail('"requests" must be a non-empty array')
  }
  const dictionary: SfDictionary = []
  for (const request of requests) {
    if (request === null || typeof request !== 'object') {
      fail('Invalid signature request')
    }
    assertSfKey(request.label, 'Signature request label')
    if (dictionary.some(([label]) => label === request.label)) {
      fail(`Duplicate signature request label "${request.label}"`)
    }
    const components = normalizeComponents(request.components)
    for (const componentValue of components) {
      validateComponentParameters(componentValue)
    }
    assertUniqueComponents(components)
    const parameters = normalizeRequestedParameters(request.parameters)
    dictionary.push([request.label, signatureParametersValue(components, parameters)])
  }
  return serializeDictionary(dictionary)
}

function appendAcceptSignatureHeaders(
  headers: Headers,
  value: string,
  targetIsRequest: boolean,
): Headers {
  const output = new Headers(headers)
  const existing = output.get('accept-signature')
  const combined = existing === null ? value : `${existing}, ${value}`
  const requests = parseAcceptSignatureInternal(combined)
  for (const request of requests) {
    for (const componentValue of request.components) {
      validateComponentForTarget(componentValue, targetIsRequest)
    }
  }
  output.set('accept-signature', combined)
  return output
}

/**
 * Adds `Accept-Signature` requests to a `Request` or `Response` and returns a new message.
 *
 * On a request, the field asks for signatures on the response. On a response, it asks for
 * signatures on the client's next request.
 *
 * The returned message passes the source body to a new Fetch message without explicitly cloning or
 * buffering it. The source body's observable state is runtime-dependent. Consume the returned
 * message and do not rely on the source message afterward. Use {@link createAcceptSignature} and
 * construct the final message explicitly when both bodies must remain readable.
 *
 * @group Signature Negotiation
 */
export function appendAcceptSignature(
  message: Request,
  requests: ReadonlyArray<SignatureRequestInput>,
): Request
export function appendAcceptSignature(
  message: Response,
  requests: ReadonlyArray<SignatureRequestInput>,
): Response
export function appendAcceptSignature(
  message: Request | Response,
  requests: ReadonlyArray<SignatureRequestInput>,
): Request | Response
export function appendAcceptSignature(
  message: Request | Response,
  requests: ReadonlyArray<SignatureRequestInput>,
): Request | Response {
  assertMessage(message)
  const value = createAcceptSignature(requests)
  const targetIsRequest = !isRequest(message)
  for (const request of requests) {
    for (const componentValue of normalizeComponents(request.components)) {
      validateComponentForTarget(componentValue, targetIsRequest)
    }
  }
  const headers = appendAcceptSignatureHeaders(message.headers, value, targetIsRequest)
  if (isRequest(message)) {
    return new Request(message, { headers })
  }
  if (message.status === 0) {
    fail('Opaque and error responses cannot carry Accept-Signature')
  }
  return new Response(message.body, {
    headers,
    status: message.status,
    statusText: message.statusText,
  })
}

function internalParametersFromPublic(
  parameters: ReadonlyArray<readonly [string, SignatureParameterValue]>,
): SfParameters {
  if (!Array.isArray(parameters)) {
    fail('Signature request parameters must be an array')
  }
  const seen = new Set<string>()
  const output: SfParameters = []
  for (const [name, value] of parameters) {
    assertSfKey(name, 'Requested signature parameter name')
    if (seen.has(name)) {
      fail(`Duplicate requested signature parameter "${name}"`)
    }
    seen.add(name)
    const item = sfItemFromSignatureParameter(name, value)
    if (item === undefined) {
      fail(`Signature parameter "${name}" is undefined`)
    }
    output.push([name, item])
  }
  validateKnownSignatureParameters(output, true)
  return output
}

function mergeRequestedParameters(
  request: SignatureRequest,
  parameters: SignatureParameters | undefined,
  now: number,
): { readonly parameters: SfParameters; readonly omitDefaultCreated: boolean } {
  const requested = internalParametersFromPublic(request.parameters)
  const suppliedEntries = parameterEntries(parameters)
  const supplied = normalizeSignatureParameterEntries(suppliedEntries, undefined)
  const output: SfParameters = []
  const omitDefaultCreated = suppliedEntries.some(
    ([name, value]) => name === 'created' && value === false,
  )

  for (const [name, requestedValue] of requested) {
    const suppliedValue = findSfParameter(supplied, name)
    if (name === 'created') {
      output.push([name, suppliedValue ?? { kind: 'integer', value: now }])
      continue
    }
    if (name === 'expires') {
      if (suppliedValue === undefined) {
        fail('An Accept-Signature "expires" request requires an explicit expiration time')
      }
      output.push([name, suppliedValue])
      continue
    }
    if (name === 'keyid' && suppliedValue === undefined) {
      fail('An Accept-Signature "keyid" request requires explicit key selection')
    }
    if (!SIGNATURE_PARAMETERS.has(name) && suppliedValue === undefined) {
      fail(`Unsupported requested signature parameter "${name}" must be explicitly processed`)
    }
    if (suppliedValue !== undefined && !sameBareItem(requestedValue, suppliedValue)) {
      fail(`Supplied signature parameter "${name}" conflicts with Accept-Signature`)
    }
    output.push([name, requestedValue])
  }

  for (const [name, value] of supplied) {
    if (!output.some(([existing]) => existing === name)) {
      output.push([name, value])
    }
  }
  return {
    parameters: output,
    omitDefaultCreated: omitDefaultCreated && findSfParameter(output, 'created') === undefined,
  }
}

/** Validates a parsed request and turns it into regular signing options. */
function requestedSignatureOptions(
  message: Request | Response,
  request: SignatureRequest,
  options: RequestedSignOptions,
): SignOptions {
  assertMessage(message)
  if (request === null || typeof request !== 'object') {
    fail('"request" must be a SignatureRequest')
  }
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  assertSfKey(request.label, 'Signature request label')
  const components = normalizeComponents(request.components)
  assertUniqueComponents(components)
  for (const componentValue of components) {
    validateComponentForMessage(componentValue, message)
  }
  const normalizedRequest: SignatureRequest = {
    label: request.label,
    components,
    parameters: request.parameters,
  }
  const now = timestamp(options.now)
  const merged = mergeRequestedParameters(normalizedRequest, options.parameters, now)
  const parameters: SignatureParameter[] = signatureParametersPublic(merged.parameters)
  if (merged.omitDefaultCreated) {
    parameters.push(['created', false])
  }
  return { ...options, label: normalizedRequest.label, components, parameters, now }
}

/**
 * Fulfills one parsed `Accept-Signature` request without modifying the target Fetch message.
 *
 * @group Signature Negotiation
 */
export async function createRequestedSignature(
  message: Request | Response,
  request: SignatureRequest,
  options: RequestedSignOptions,
): Promise<SignatureFields> {
  return createSignature(message, requestedSignatureOptions(message, request, options))
}

/**
 * Fulfills and appends one parsed `Accept-Signature` request.
 *
 * Appending passes the source body to a new Fetch message without explicitly cloning or buffering
 * it. The source body's observable state is runtime-dependent. Consume the returned message and do
 * not rely on the source message afterward. Use {@link createRequestedSignature} and construct the
 * final message explicitly when both bodies must remain readable.
 *
 * @group Signature Negotiation
 */
export function signRequested(
  message: Request,
  request: SignatureRequest,
  options: RequestedSignOptions,
): Promise<Request>
export function signRequested(
  message: Response,
  request: SignatureRequest,
  options: RequestedSignOptions,
): Promise<Response>
export function signRequested(
  message: Request | Response,
  request: SignatureRequest,
  options: RequestedSignOptions,
): Promise<Request | Response>
export async function signRequested(
  message: Request | Response,
  request: SignatureRequest,
  options: RequestedSignOptions,
): Promise<Request | Response> {
  const created = await createSignatureInternal(
    message,
    requestedSignatureOptions(message, request, options),
  )
  created.assertUnchanged()
  return isRequest(message)
    ? appendSignature(message, created.fields)
    : appendSignature(message, created.fields)
}

/** Options for a Fetch-compatible function that signs requests. */
export interface SigningFetchOptions {
  readonly sign: Omit<SignOptions, 'request'>
  readonly fetch?: typeof globalThis.fetch
}

/** Options for a Fetch-compatible function that verifies responses against their requests. */
export interface VerifyingFetchOptions {
  readonly verify: Omit<VerifyOptions, 'request'>
  readonly fetch?: typeof globalThis.fetch
}

/** Options for a Fetch-compatible function that signs requests and optionally verifies responses. */
export interface SignedFetchOptions {
  readonly sign: Omit<SignOptions, 'request'>
  readonly verify?: Omit<VerifyOptions, 'request'>
  readonly fetch?: typeof globalThis.fetch
}

function snapshotStructuredFields(
  structuredFields: SignatureContext['structuredFields'],
): SignatureContext['structuredFields'] {
  if (structuredFields === undefined) {
    return undefined
  }
  if (structuredFields === null || typeof structuredFields !== 'object') {
    fail('"structuredFields" must be an object')
  }
  return Object.fromEntries(Object.entries(structuredFields))
}

function snapshotSignatureParameterInput(value: SignatureParameterInput): SignatureParameterInput {
  if (isDate(value)) {
    return new Date(Date.prototype.getTime.call(value))
  }
  if (isUint8Array(value)) {
    return cloneBytes(value)
  }
  if (value !== null && typeof value === 'object') {
    return { ...value }
  }
  return value
}

function snapshotSignatureParameters(
  parameters: SignatureParameters | undefined,
): SignatureParameters | undefined {
  if (parameters === undefined) {
    return undefined
  }
  return parameterEntries(parameters).map(([name, value]) => [
    name,
    snapshotSignatureParameterInput(value),
  ])
}

function snapshotSignedFetchSignOptions(
  options: Omit<SignOptions, 'request'>,
): Omit<SignOptions, 'request'> {
  if (options === null || typeof options !== 'object') {
    fail('"options.sign" must be an object')
  }
  return {
    signer: options.signer,
    components: normalizeComponents(options.components),
    parameters: snapshotSignatureParameters(options.parameters),
    label: options.label,
    now: isDate(options.now) ? new Date(Date.prototype.getTime.call(options.now)) : options.now,
    structuredFields: snapshotStructuredFields(options.structuredFields),
    fieldValues: options.fieldValues,
  }
}

function snapshotSignedFetchVerifyOptions(
  options: Omit<VerifyOptions, 'request'>,
): Omit<VerifyOptions, 'request'> {
  if (options === null || typeof options !== 'object') {
    fail('"options.verify" must be an object')
  }
  return {
    verifier: options.verifier,
    policy: snapshotVerificationPolicy(options.policy),
    label: options.label,
    structuredFields: snapshotStructuredFields(options.structuredFields),
    fieldValues: options.fieldValues,
  }
}

function fetchImplementation(
  options: Readonly<{ fetch?: typeof globalThis.fetch }>,
): typeof globalThis.fetch {
  const implementation = options.fetch ?? globalThis.fetch
  if (typeof implementation !== 'function') {
    fail('"options.fetch" must be a Fetch implementation')
  }
  return implementation
}

function fetchRequest(input: RequestInfo | URL, init?: RequestInit): Request {
  let request = new Request(input, init)
  if (request.redirect === 'follow') {
    request = new Request(request, { redirect: 'manual' })
  }
  return request
}

/**
 * Creates a Fetch-compatible function that signs every outgoing request.
 *
 * Automatic redirects are changed to manual redirects because Fetch cannot re-sign each redirected
 * request and could otherwise forward stale signature fields to a different origin.
 *
 * @group Fetch Integration
 */
export function createSigningFetch(options: SigningFetchOptions): typeof globalThis.fetch {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = fetchImplementation(options)
  const signOptions = snapshotSignedFetchSignOptions(options.sign)

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const signedRequest = await sign(fetchRequest(input, init), signOptions)
    return implementation(signedRequest)
  }
}

/**
 * Creates a Fetch-compatible function that verifies every response against its exact request.
 *
 * Automatic redirects are changed to manual redirects because Fetch does not expose the request
 * that produced a response after following a redirect.
 *
 * @group Fetch Integration
 */
export function createVerifyingFetch(options: VerifyingFetchOptions): typeof globalThis.fetch {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = fetchImplementation(options)
  const verifyOptions = snapshotSignedFetchVerifyOptions(options.verify)

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = fetchRequest(input, init)
    const response = await implementation(request)
    await verify(response, { ...verifyOptions, request })
    return response
  }
}

/**
 * Creates a Fetch-compatible function that signs every outgoing request and, when configured,
 * verifies every returned response against that exact request.
 *
 * Automatic redirects are changed to manual redirects because Fetch cannot re-sign each redirected
 * request and could otherwise forward stale signature fields to a different origin.
 *
 * @group Fetch Integration
 */
export function createSignedFetch(options: SignedFetchOptions): typeof globalThis.fetch {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = fetchImplementation(options)
  const signOptions = snapshotSignedFetchSignOptions(options.sign)
  const verifyOptions =
    options.verify === undefined ? undefined : snapshotSignedFetchVerifyOptions(options.verify)

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const signedRequest = await sign(fetchRequest(input, init), signOptions)
    const response = await implementation(signedRequest)
    if (verifyOptions !== undefined) {
      await verify(response, { ...verifyOptions, request: signedRequest })
    }
    return response
  }
}
