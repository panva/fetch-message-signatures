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
 * // sig1=("@method" "@authority" "@path");created=1735689600;alg="ed25519";keyid="example-key"
 * console.log(request.headers.get('signature-input'))
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
 * // sig1 ed25519
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

/**
 * Throws the `TypeError` used for every input, syntax, and policy rejection in this module.
 *
 * The `never` return type lets call sites use it as an expression, so a validation branch can both
 * reject and satisfy a function's declared return type.
 */
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

/**
 * Validates the optional `extractable` argument of a key-pair generator and applies its non-
 * extractable default.
 */
function resolveExtractableOption(extractable: boolean | undefined): boolean {
  if (extractable === undefined) {
    return false
  }
  if (typeof extractable !== 'boolean') {
    fail('"extractable" must be a boolean')
  }
  return extractable
}

/**
 * Reads a property from a value that is not known to be an object, returning `undefined` instead of
 * throwing when it is not.
 *
 * Used to inspect `CryptoKey` objects that may come from a foreign implementation.
 */
function readProperty(value: unknown, property: string): unknown {
  if (value === null || typeof value !== 'object') {
    return undefined
  }
  return (value as Record<string, unknown>)[property]
}

/**
 * Reports whether a `CryptoKey` matches the type, usage, Web Cryptography algorithm, and named
 * curve required by one RFC 9421 algorithm identifier.
 */
function isAlgorithmKey(key: CryptoKey, expected: AlgorithmKeyExpectation): boolean {
  if (key === null || typeof key !== 'object') {
    return false
  }
  const algorithm = readProperty(key, 'algorithm')
  const usages = readProperty(key, 'usages')
  if (
    readProperty(key, 'type') !== expected.type ||
    !Array.isArray(usages) ||
    !usages.includes(expected.usage) ||
    readProperty(algorithm, 'name') !== expected.algorithm
  ) {
    return false
  }
  return (
    expected.namedCurve === undefined ||
    readProperty(algorithm, 'namedCurve') === expected.namedCurve
  )
}

/**
 * Rejects a `CryptoKey` that does not match the expectation for one RFC 9421 algorithm identifier,
 * naming the identifier, key type, and usage that were required.
 */
function assertAlgorithmKey(key: CryptoKey, expected: AlgorithmKeyExpectation): void {
  if (!isAlgorithmKey(key, expected)) {
    fail(
      `"key" must be Web Cryptography's ${expected.type} CryptoKey for "${expected.identifier}" with "${expected.usage}" usage`,
    )
  }
}

/**
 * Builds a fixed-key {@link SignerFactory} that signs the signature base with `crypto.subtle.sign`.
 *
 * The key is checked once, when the factory is created, so that a mismatched key is reported before
 * any message is signed.
 */
function createWebCryptoSignerFactory(
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

/**
 * Builds a fixed-key {@link VerifierFactory} that verifies the signature base with
 * `crypto.subtle.verify`.
 *
 * The key is checked once, when the factory is created, so that a mismatched key is reported before
 * any message is verified.
 */
function createWebCryptoVerifierFactory(
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

/** Generates a Web Cryptography key pair restricted to the `sign` and `verify` usages. */
async function generateWebCryptoKeyPair(
  algorithm: WebCryptoKeyGenerationAlgorithm,
  extractable: boolean | undefined,
): Promise<CryptoKeyPair> {
  return (await globalThis.crypto.subtle.generateKey(
    algorithm,
    resolveExtractableOption(extractable),
    ['sign', 'verify'],
  )) as CryptoKeyPair
}

/**
 * Generates an ECDSA P-256 key pair for the RFC 9421 `ecdsa-p256-sha256` algorithm.
 *
 * The generated public key is represented by Web Cryptography's `CryptoKey` and is always
 * extractable.
 *
 * @example
 *
 * Generate a pair and turn it into the sender and recipient providers.
 *
 * ```ts
 * const { privateKey, publicKey } = await FetchSig.generateEcdsaP256Sha256KeyPair()
 *
 * const signer = FetchSig.ecdsaP256Sha256Signer(privateKey)
 * const verifier = FetchSig.ecdsaP256Sha256Verifier(publicKey)
 *
 * // Pass true only when the private key has to leave the process.
 * const portable = await FetchSig.generateEcdsaP256Sha256KeyPair(true)
 * const pkcs8 = await crypto.subtle.exportKey('pkcs8', portable.privateKey)
 * ```
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
  return createWebCryptoSignerFactory(
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
  return createWebCryptoVerifierFactory(
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
 * @example
 *
 * A complete P-384 round trip, signing then verifying the same request.
 *
 * ```ts
 * const { privateKey, publicKey } = await FetchSig.generateEcdsaP384Sha384KeyPair()
 *
 * const signed = await FetchSig.sign(new Request('https://api.example/orders'), {
 *   signer: FetchSig.ecdsaP384Sha384Signer(privateKey),
 *   components: ['@method', '@authority', '@path'],
 *   parameters: [['alg', 'ecdsa-p384-sha384']],
 * })
 *
 * const verified = await FetchSig.verify(signed, {
 *   verifier: FetchSig.ecdsaP384Sha384Verifier(publicKey),
 *   policy: {
 *     requiredComponents: ['@method', '@authority', '@path'],
 *     requiredParameters: ['created', 'alg'],
 *     algorithms: ['ecdsa-p384-sha384'],
 *     maxAge: 60,
 *   },
 * })
 *
 * // sig1 ecdsa-p384-sha384
 * console.log(verified.label, verified.algorithm)
 * ```
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
  return createWebCryptoSignerFactory(
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
  return createWebCryptoVerifierFactory(
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
 * @example
 *
 * Publish the public key in a format a peer can import, and keep the private key non-extractable.
 *
 * ```ts
 * const { privateKey, publicKey } = await FetchSig.generateEd25519KeyPair()
 *
 * const signer = FetchSig.ed25519Signer(privateKey)
 * const jwk = await crypto.subtle.exportKey('jwk', publicKey)
 *
 * // { kty: 'OKP', crv: 'Ed25519', x: '…' }
 * console.log(jwk)
 * ```
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
  return createWebCryptoSignerFactory(
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
 * @example
 *
 * Compose the fixed-key factory into an application factory that selects a trusted key by `keyid`.
 * This is the shape to reach for whenever more than one key can sign.
 *
 * ```ts
 * declare const publicKeys: ReadonlyMap<string, CryptoKey>
 *
 * const verifier: FetchSig.VerifierFactory = (signature, context) => {
 *   const keyid = signature.parameters.find(([name]) => name === 'keyid')?.[1]
 *   if (typeof keyid !== 'string') {
 *     throw new Error('A key identifier is required')
 *   }
 *
 *   const publicKey = publicKeys.get(keyid)
 *   if (publicKey === undefined) {
 *     throw new Error('Unknown signing key')
 *   }
 *
 *   return FetchSig.ed25519Verifier(publicKey)(signature, context)
 * }
 * ```
 *
 * @param key - Web Cryptography's `CryptoKey` for an Ed25519 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export function ed25519Verifier(key: CryptoKey): VerifierFactory {
  return createWebCryptoVerifierFactory(
    key,
    { identifier: 'ed25519', type: 'public', usage: 'verify', algorithm: 'Ed25519' },
    'Ed25519',
  )
}

/**
 * Reports whether a Fetch message is a `Request` rather than a `Response`.
 *
 * Only requests carry a method, and Fetch exposes it as a string.
 */
function isRequest(message: Request | Response): message is Request {
  return typeof (message as Request).method === 'string'
}

/**
 * Reports whether a value implements the mutating and reading operations of `Headers`.
 *
 * Used to distinguish the `Headers` overload of {@link appendSignature} from its message overloads
 * without depending on a particular runtime's class identity.
 */
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

/**
 * Reports whether a value is a `Date`, including one created in another realm.
 *
 * `Date.prototype.getTime` reads an internal slot and throws for anything that is not a real
 * `Date`, so this cannot be defeated by a look-alike object. `Object.prototype.toString` would be,
 * because any object can claim `Symbol.toStringTag` of `"Date"`.
 */
function isDate(value: unknown): value is Date {
  try {
    Date.prototype.getTime.call(value as Date)
    return true
  } catch {
    return false
  }
}

/**
 * The `%TypedArray%.prototype[Symbol.toStringTag]` getter, which reports the name of a typed array
 * from an internal slot and returns `undefined` for every other value.
 */
const typedArrayName = /* @__PURE__ */ Object.getOwnPropertyDescriptor(
  /* @__PURE__ */ Object.getPrototypeOf(Uint8Array.prototype),
  Symbol.toStringTag,
)!.get! as (this: unknown) => string | undefined

/**
 * Reports whether a value is a `Uint8Array`, including one created in another realm.
 *
 * The typed array name is read through the built-in getter rather than with
 * `Object.prototype.toString`, which any object can spoof through `Symbol.toStringTag`. Spoofing it
 * mattered: a `DataView` or a `Float64Array` labelled as a `Uint8Array` used to be copied by `new
 * Uint8Array(value)` into a silently wrong Byte Sequence instead of being rejected.
 */
function isUint8Array(value: unknown): value is Uint8Array {
  return typedArrayName.call(value) === 'Uint8Array'
}

/**
 * Rejects a value that is not usable as a Fetch `Request` or `Response`.
 *
 * Structural rather than instance-based, so that messages from a runtime's own Fetch
 * implementation, a test double, or a transport integration are all accepted.
 */
function assertMessage(message: unknown): asserts message is Request | Response {
  const candidate = message as Request | Response | null
  if (
    candidate === null ||
    typeof candidate !== 'object' ||
    typeof candidate.headers?.get !== 'function'
  ) {
    fail('"message" must be a Request or Response')
  }
  if (isRequest(candidate)) {
    // Every request-targeted derived component is read from the target URI, so a request without a
    // usable "url" is rejected here instead of failing later with a less specific error.
    if (typeof candidate.url !== 'string') {
      fail('"message" must be a Request or Response')
    }
    return
  }
  if (typeof (candidate as Response).status !== 'number') {
    fail('"message" must be a Request or Response')
  }
}

/**
 * Rejects the shared signature context options that are only consulted later, while deriving
 * individual components, so that a malformed option is reported by every entry point instead of
 * only by the messages that happen to use it.
 */
function assertSignatureContext(context: Readonly<SignatureContext>): void {
  if (
    context.structuredFields !== undefined &&
    (context.structuredFields === null || typeof context.structuredFields !== 'object')
  ) {
    fail('"structuredFields" must be an object')
  }
  if (context.fieldValues !== undefined && typeof context.fieldValues !== 'function') {
    fail('"fieldValues" must be a function')
  }
}

/**
 * Rejects a value that is not a Structured Field key, which is the syntax RFC 9421 requires for
 * signature labels, signature metadata parameter names, and component parameter names.
 */
function assertSfKey(value: string, description: string): void {
  if (typeof value !== 'string' || !SF_KEY.test(value)) {
    fail(`${description} must be a Structured Field key`)
  }
}

/** Rejects a string that contains any non-ASCII character. */
function assertAscii(value: string, description: string): void {
  if (!ASCII.test(value)) {
    fail(`${description} must contain only ASCII characters`)
  }
}

/**
 * Copies bytes into a newly allocated `Uint8Array` so that neither side of an API boundary can
 * observe or modify the other's buffer.
 */
function cloneBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(value)
}

interface MessageMutationGuard {
  readonly message: Request | Response
  readonly headers: Headers
  readonly request?: Request
  readonly requestHeaders?: Headers
}

/**
 * Snapshots the observable headers of the target message, and of the related request when one is
 * supplied, before an asynchronous signing or verification operation begins.
 *
 * Signing and verification call out to application-provided signers, verifiers, field adapters, and
 * policy callbacks. The snapshot lets those operations detect a message that changed while they
 * were suspended, which would otherwise produce a signature over a message that was never sent.
 */
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

/** Reports whether two `Headers` objects expose the same field names and values in the same order. */
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

/**
 * Rejects an operation whose target message, or related request, had its headers changed since the
 * guard was created.
 */
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

/**
 * Reports whether two byte sequences have the same length and contents.
 *
 * The comparison is not short-circuiting, but it is only used on public Structured Field values and
 * never on secrets.
 */
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

/**
 * Encodes bytes as padded standard base64, the form RFC 9651 requires when serializing a Structured
 * Field Byte Sequence.
 *
 * `Uint8Array.prototype.toBase64()` defaults to exactly that form. Runtimes that do not implement
 * it fall back to `btoa()`, which takes a string of code units below `U+0100`. The bytes are spread
 * into that string in small chunks, because engines cap how many arguments a call may spread and
 * the cap differs between them.
 *
 * The method is looked up on the value rather than on `Uint8Array.prototype`, so a typed array from
 * a realm that does not implement it still takes the fallback.
 */
function base64Encode(value: Uint8Array): string {
  if (typeof value.toBase64 === 'function') {
    return value.toBase64()
  }

  let binary = ''
  const chunk = 0x1000
  for (let i = 0; i < value.byteLength; i += chunk) {
    binary += String.fromCharCode(...value.subarray(i, i + chunk))
  }
  return btoa(binary)
}

/**
 * Decodes the contents of a Structured Field Byte Sequence.
 *
 * The alphabet and length are checked before decoding, because both decoders skip ASCII whitespace
 * and RFC 9651 does not: `:AQ I=:` has to fail.
 *
 * RFC 9651 lets a parser synthesize missing padding, so unpadded input is accepted.
 * `Uint8Array.fromBase64()` does that under its default `lastChunkHandling` of `"loose"`, and the
 * `atob()` fallback is handed the padding explicitly. `atob()` is forgiving-base64 decoding and
 * would synthesize it anyway, so that is belt and braces: it keeps the RFC 9651 requirement met
 * without depending on a second specification for it.
 *
 * Both decoders ignore non-zero padding bits, which RFC 9651 permits because not every base64
 * implementation is able to reject them.
 */
function base64Decode(value: string): Uint8Array<ArrayBuffer> {
  if (
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value) ||
    value.length % 4 === 1 ||
    (value.includes('=') && value.length % 4 !== 0)
  ) {
    fail('Invalid Structured Field Byte Sequence')
  }

  try {
    if (typeof Uint8Array.fromBase64 === 'function') {
      return Uint8Array.fromBase64(value)
    }

    const binary = atob(value + '='.repeat((4 - (value.length % 4)) % 4))
    const output = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      output[i] = binary.charCodeAt(i)
    }
    return output
  } catch (cause) {
    // Reported as a SyntaxError by the runtime; every other parse failure here is a TypeError.
    throw new TypeError('Invalid Structured Field Byte Sequence', { cause })
  }
}

/** Advances past any run of spaces, per the leading-whitespace handling of RFC 9651. */
function skipSp(state: ParseState): void {
  while (state.input[state.index] === ' ') {
    state.index++
  }
}

/**
 * Advances past any run of optional whitespace, which RFC 9651 defines as spaces and horizontal
 * tabs.
 */
function skipOws(state: ParseState): void {
  while (state.input[state.index] === ' ' || state.input[state.index] === '\t') {
    state.index++
  }
}

/** Parses an RFC 9651 key, used for Dictionary member names and parameter names. */
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

/**
 * Inserts or replaces an entry in an ordered map, keeping the position of an existing key.
 *
 * RFC 9651 Dictionaries and Parameters are ordered maps in which a repeated key overwrites the
 * earlier value in place. When `duplicateKeys` is supplied, the repeated key is recorded so that a
 * caller such as `Signature-Input` parsing can reject the input outright.
 */
function setOrderedEntry<T extends readonly [string, unknown]>(
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

/** Parses an RFC 9651 Integer or Decimal, enforcing the digit limits that bound each type. */
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

/** Parses an RFC 9651 String, resolving the two permitted escape sequences. */
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

/** Parses an RFC 9651 Token. */
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

/** Parses an RFC 9651 Byte Sequence, delimited by colons. */
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

/** Parses an RFC 9651 Boolean. */
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

/** Parses an RFC 9651 Date, which is an Integer of UNIX seconds prefixed with `@`. */
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

/**
 * Parses an RFC 9651 Display String, percent-decoding the escaped octets and decoding the result as
 * UTF-8.
 */
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

/** Parses any RFC 9651 bare item by dispatching on its first character. */
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

/** Parses a trailing RFC 9651 parameter list, defaulting a parameter with no value to Boolean true. */
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
    setOrderedEntry(parameters, [name, value])
  }
  return parameters
}

/** Parses an RFC 9651 Item, which is a bare item with its parameters. */
function parseItem(state: ParseState): SfItem {
  return { kind: 'item', value: parseBareItem(state), parameters: parseParameters(state) }
}

/**
 * Parses an RFC 9651 Inner List, which is the form the `Signature-Input` and `Accept-Signature`
 * members take.
 */
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

/** Parses one member of an RFC 9651 List or Dictionary, which is either an Inner List or an Item. */
function parseMember(state: ParseState): SfMember {
  return state.input[state.index] === '(' ? parseInnerList(state) : parseItem(state)
}

/** Parses an RFC 9651 List. */
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

/** Parses an RFC 9651 Dictionary, defaulting a member with no value to Boolean true. */
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
    setOrderedEntry(output, [name, value], state.duplicateKeys)
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

/**
 * Parses a complete HTTP field value as the given Structured Field top-level type.
 *
 * Trailing content is rejected, as required by RFC 9651. Setting `rejectDuplicateKeys` additionally
 * rejects a Dictionary that repeats a key, which the `Signature`, `Signature-Input`, and
 * `Accept-Signature` fields must not do because a repeated label would silently discard a
 * signature.
 */
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

/** Serializes an RFC 9651 key, rejecting a value that is not one. */
function serializeKey(value: string): string {
  assertSfKey(value, 'Structured Field key')
  return value
}

/** Serializes an RFC 9651 String, escaping backslashes and double quotes. */
function serializeString(value: string): string {
  if (!PRINTABLE_ASCII.test(value)) {
    fail('Structured Field String must contain only printable ASCII characters')
  }
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`
}

/**
 * Rejects a string containing an unpaired UTF-16 surrogate.
 *
 * RFC 9651 Display Strings hold Unicode scalar values, and an unpaired surrogate cannot be encoded
 * as UTF-8.
 */
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

/**
 * Serializes an RFC 9651 Display String, UTF-8 encoding the value and percent-escaping every octet
 * that is not safe printable ASCII.
 */
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

/**
 * Serializes an RFC 9651 Decimal.
 *
 * The value is scaled to thousandths using exact integer arithmetic and rounded half to even, as
 * the RFC requires, because binary floating point cannot represent every decimal exactly. Values
 * that cannot be represented within the RFC's range are rejected.
 */
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

/** Serializes any RFC 9651 bare item, enforcing the range limits of Integers and Dates. */
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

/** Serializes an RFC 9651 parameter list, omitting the value of a parameter that is Boolean true. */
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

/** Serializes an RFC 9651 Item, which is a bare item followed by its parameters. */
function serializeItem(item: SfItem): string {
  return serializeBareItem(item.value) + serializeParameters(item.parameters)
}

/** Serializes an RFC 9651 Inner List, which is the form of a `Signature-Input` member value. */
function serializeInnerList(value: SfInnerList): string {
  return `(${value.value.map(serializeItem).join(' ')})${serializeParameters(value.parameters)}`
}

/** Serializes one member of an RFC 9651 List or Dictionary. */
function serializeMember(value: SfMember): string {
  return value.kind === 'inner-list' ? serializeInnerList(value) : serializeItem(value)
}

/** Serializes an RFC 9651 List. */
function serializeList(value: SfList): string {
  return value.map(serializeMember).join(', ')
}

/** Serializes an RFC 9651 Dictionary, omitting the value of a member that is Boolean true. */
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

/**
 * Serializes a parsed Structured Field back to its strict RFC 9651 form.
 *
 * This is the "re-serialization" that the `sf` component parameter of RFC 9421 requires, which
 * normalizes internal whitespace and item representation.
 */
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
 * Creates a validated Structured Field Token, for use as an extension signature metadata parameter
 * value.
 *
 * Plain JavaScript strings are Structured Field Strings, so this wrapper is how a value is marked
 * as a Token instead.
 *
 * @example
 *
 * The wrapper is the difference between a quoted String and a bare Token on the wire.
 *
 * ```ts
 * const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
 *   components: ['@method'],
 *   parameters: [
 *     ['as-string', 'example/value'],
 *     ['as-token', FetchSig.token('example/value')],
 *   ],
 * })
 *
 * // "@signature-params": ("@method");as-string="example/value";as-token=example/value
 * console.log(base)
 * ```
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
 * @example
 *
 * A plain integral number is an Integer; the wrapper keeps it a Decimal. Values are rounded to
 * three fraction digits, half to even, as RFC 9651 requires.
 *
 * ```ts
 * const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
 *   components: ['@method'],
 *   parameters: [
 *     ['as-integer', 1],
 *     ['as-decimal', FetchSig.decimal(1)],
 *     ['rounded', FetchSig.decimal(1.23456)],
 *   ],
 * })
 *
 * // "@signature-params": ("@method");as-integer=1;as-decimal=1.0;rounded=1.235
 * console.log(base)
 * ```
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
 * @example
 *
 * The same instant, as the Integer form RFC 9421 defines for `created` and `expires`, and as a
 * Structured Field Date. Only use the Date type for extension parameters.
 *
 * ```ts
 * const instant = new Date(1_659_578_233_000)
 *
 * const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
 *   components: ['@method'],
 *   parameters: [
 *     ['created', instant],
 *     ['example-date', FetchSig.date(instant)],
 *   ],
 * })
 *
 * // "@signature-params": ("@method");created=1659578233;example-date=@1659578233
 * console.log(base)
 * ```
 *
 * @group Components and Structured Fields
 */
export function date(value: number | Date): StructuredFieldDate {
  let seconds: number
  if (isDate(value)) {
    seconds = Math.floor(Date.prototype.getTime.call(value) / 1000)
  } else if (typeof value === 'number') {
    seconds = value
  } else {
    return fail('"value" must be a number of UNIX seconds or a Date')
  }
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
 * @example
 *
 * A Structured Field String cannot carry non-ASCII text at all, so Unicode needs this wrapper.
 *
 * ```ts
 * const base = FetchSig.createSignatureBase(new Request('https://api.example/orders'), {
 *   components: ['@method'],
 *   parameters: [['example-display', FetchSig.displayString('snowman ☃')]],
 * })
 *
 * // "@signature-params": ("@method");example-display=%"snowman %e2%98%83"
 * console.log(base)
 * ```
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
 * @example
 *
 * A plain string is shorthand for an identifier with no parameters, so `component()` is only needed
 * when a component carries parameters.
 *
 * ```ts
 * const request = new Request('https://api.example/orders?page=2', {
 *   headers: { 'example-dictionary': 'a=1, member="two"' },
 * })
 *
 * const base = FetchSig.createSignatureBase(request, {
 *   components: [
 *     '@method',
 *     FetchSig.component('@query-param', [['name', 'page']]),
 *     FetchSig.component('Example-Dictionary', [['key', 'member']]),
 *   ],
 * })
 *
 * // "@method": GET
 * // "@query-param";name="page": 2
 * // "example-dictionary";key="member": "two"
 * // "@signature-params": ("@method" "@query-param";name="page" "example-dictionary";key="member")
 * console.log(base)
 * ```
 *
 * @example
 *
 * Parameters combine, and their order is covered by the signature. Pass ordered tuples whenever
 * another implementation has to reproduce the exact serialization; an object is also accepted and
 * keeps its property insertion order.
 *
 * ```ts
 * const request = new Request('https://api.example/orders', {
 *   headers: { 'example-dictionary': 'a=1, member="two"' },
 * })
 * const response = new Response('', { status: 200 })
 *
 * const base = FetchSig.createSignatureBase(response, {
 *   request,
 *   components: [
 *     '@status',
 *     FetchSig.component('example-dictionary', [
 *       ['key', 'member'],
 *       ['req', true],
 *     ]),
 *   ],
 * })
 *
 * // "@status": 200
 * // "example-dictionary";key="member";req: "two"
 * // "@signature-params": ("@status" "example-dictionary";key="member";req)
 * console.log(base)
 * ```
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

/**
 * Normalizes the two accepted parameter inputs, an ordered array of tuples or a plain object, into
 * an ordered array of entries.
 *
 * Object property insertion order is preserved because RFC 9421 covers the serialized parameter
 * order with the signature.
 */
function orderedParameterEntries<T>(
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

/**
 * Converts one signature metadata parameter supplied by an application into a Structured Field bare
 * item.
 *
 * `Date` values become RFC 9421 Integer UNIX timestamps. `undefined` means the parameter is
 * omitted, which the caller signals by returning `undefined`.
 */
function sfBareItemFromSignatureParameter(
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

/**
 * Converts one parsed Structured Field bare item into the public signature metadata parameter value
 * that is handed to applications.
 */
function signatureParameterValueFromSfBareItem(item: SfBareItem): SignatureParameterValue {
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

/**
 * Converts application-supplied signature metadata parameters into ordered Structured Field
 * parameters, adding `defaultCreated` when a creation timestamp was neither supplied nor explicitly
 * disabled.
 */
function normalizeSignatureParameters(
  parameters: SignatureParameters | undefined,
  defaultCreated: number | undefined,
): SfParameters {
  return normalizeSignatureParameterEntries(orderedParameterEntries(parameters), defaultCreated)
}

/**
 * Converts already-ordered signature metadata parameter entries into Structured Field parameters.
 *
 * Duplicate names are rejected, `['created', false]` suppresses the default creation timestamp, and
 * a default creation timestamp is inserted ahead of the supplied parameters. The resulting order is
 * covered by the signature, so it is fixed from this point on.
 */
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
    const value = sfBareItemFromSignatureParameter(name, input)
    if (value !== undefined) {
      output.push([name, value])
    }
  }

  validateKnownSignatureParameters(output, false)
  return output
}

/** Returns the value of one Structured Field parameter, or `undefined` when it is absent. */
function findSfParameterValue(parameters: SfParameters, name: string): SfBareItem | undefined {
  return parameters.find(([candidate]) => candidate === name)?.[1]
}

/**
 * Enforces the value types RFC 9421 defines for its own signature metadata parameters, leaving
 * extension parameters to the application.
 *
 * In a signature, `created` and `expires` are Integers and `nonce`, `alg`, `keyid`, and `tag` are
 * Strings. In an `Accept-Signature` request, `created` and `expires` instead carry no value,
 * because the signer chooses the timestamps.
 */
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

/**
 * Converts application-supplied HTTP message component parameters into ordered Structured Field
 * parameters, rejecting duplicates and values that are neither a string nor a boolean.
 */
function normalizeComponentParameters(parameters: ComponentParameters | undefined): SfParameters {
  const entries = orderedParameterEntries(parameters)
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

/**
 * Converts one parsed component parameter into its public form, rejecting the Structured Field
 * types that RFC 9421 component parameters cannot use.
 */
function componentParameterFromSfBareItem(value: SfBareItem): ComponentParameterValue {
  if (value.kind === 'string' || value.kind === 'boolean') {
    return value.value
  }
  return fail('Component parameters must be Strings or Booleans')
}

/**
 * Converts one member of a parsed `Signature-Input` or `Accept-Signature` Inner List into a message
 * component identifier.
 */
function componentFromSfItem(item: SfItem): MessageComponent {
  if (item.value.kind !== 'string') {
    fail('Covered component identifiers must be Structured Field Strings')
  }
  return {
    name: item.value.value,
    parameters: item.parameters.map(([name, value]) => [
      name,
      componentParameterFromSfBareItem(value),
    ]),
  }
}

/**
 * Converts a message component identifier into the Structured Field Item used for its signature
 * base line and for its entry in the `@signature-params` Inner List.
 */
function componentToSfItem(identifier: MessageComponent): SfItem {
  return {
    kind: 'item',
    value: { kind: 'string', value: identifier.name },
    parameters: identifier.parameters.map(([name, value]) => [
      name,
      typeof value === 'string' ? { kind: 'string', value } : { kind: 'boolean', value },
    ]),
  }
}

/**
 * Converts the covered component identifiers supplied by an application into normalized identifiers
 * with ordered parameters.
 *
 * HTTP field names are lowercased, as RFC 9421 requires. Derived component names are left alone
 * because they are case-sensitive.
 */
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
        componentParameterFromSfBareItem(value),
      ]),
    }
    validateComponentName(normalized)
    return normalized
  })
}

/**
 * Rejects a component name that cannot appear in a covered component list: `@signature-params`
 * itself, an unknown derived component, and any field name that is not a lowercase HTTP field
 * name.
 */
function validateComponentName(identifier: MessageComponent): void {
  const { name } = identifier
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

/** Indexes a component identifier's ordered parameters by name for lookup. */
function componentParameterMap(identifier: MessageComponent): Map<string, ComponentParameterValue> {
  return new Map(identifier.parameters)
}

/**
 * Reads a Boolean component parameter, rejecting a flag that carries an explicit value.
 *
 * RFC 9421 defines `sf`, `bs`, `tr`, and `req` as bare Boolean true, so `;sf=?0` and `;sf="yes"`
 * are both invalid.
 */
function readComponentFlag(
  parameters: Map<string, ComponentParameterValue>,
  name: string,
): boolean {
  const value = parameters.get(name)
  if (value === undefined) {
    return false
  }
  if (value !== true) {
    fail(`Component parameter "${name}" must be a bare Boolean true`)
  }
  return true
}

/**
 * Enforces the component parameters RFC 9421 allows on a given component identifier and reports
 * whether the value comes from the related request.
 *
 * Derived components accept only `req`, plus `name` on `@query-param`; `@status` accepts neither.
 * HTTP fields accept `sf`, `key`, `bs`, `tr`, and `req`, and `bs` is incompatible with `sf` and
 * `key`.
 */
function validateComponentParameters(identifier: MessageComponent): boolean {
  validateComponentName(identifier)
  const parameters = componentParameterMap(identifier)

  if (identifier.name.startsWith('@')) {
    const allowed = new Set<string>()
    if (identifier.name === '@query-param') {
      allowed.add('name')
    }
    if (identifier.name !== '@status') {
      allowed.add('req')
    }
    for (const name of parameters.keys()) {
      if (!allowed.has(name)) {
        fail(`Parameter "${name}" does not apply to "${identifier.name}"`)
      }
    }

    const relatedRequest = readComponentFlag(parameters, 'req')
    if (identifier.name === '@query-param') {
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

  const sf = readComponentFlag(parameters, 'sf')
  const bs = readComponentFlag(parameters, 'bs')
  readComponentFlag(parameters, 'tr')
  const relatedRequest = readComponentFlag(parameters, 'req')
  const key = parameters.get('key')
  if (key !== undefined && typeof key !== 'string') {
    fail('Component parameter "key" must be a String')
  }
  if (bs && (sf || key !== undefined)) {
    fail('Component parameter "bs" is incompatible with "sf" and "key"')
  }
  return relatedRequest
}

/**
 * Enforces the RFC 9421 rules that depend on whether the signature targets a request or a response.
 *
 * `@status` applies only to responses. `req` applies only to response signatures. Every other
 * derived component describes a request, so covering one in a response signature requires `req`.
 */
function validateComponentForTarget(identifier: MessageComponent, request: boolean): void {
  const relatedRequest = validateComponentParameters(identifier)

  if (identifier.name.startsWith('@')) {
    if (identifier.name === '@status') {
      if (request) {
        fail('"@status" cannot be used with a request')
      }
    } else if (request) {
      if (relatedRequest) {
        fail('"req" cannot be used with a request signature')
      }
    } else if (!relatedRequest) {
      fail(`"${identifier.name}" requires "req" in a response signature`)
    }
    return
  }

  if (request && relatedRequest) {
    fail('"req" cannot be used with a request signature')
  }
}

/** Enforces {@link validateComponentForTarget} against the type of an actual Fetch message. */
function validateComponentForMessage(
  identifier: MessageComponent,
  message: Request | Response,
): void {
  validateComponentForTarget(identifier, isRequest(message))
}

/** Reports whether two Structured Field bare items have the same type and value. */
function sameBareItem(left: SfBareItem, right: SfBareItem): boolean {
  if (left.kind !== right.kind) {
    return false
  }
  if (left.kind === 'binary' && right.kind === 'binary') {
    return bytesEqual(left.value, right.value)
  }
  return left.value === right.value
}

/**
 * Reports whether two component identifiers name the same component with the same parameters.
 *
 * Parameter order is ignored, because RFC 9651 parameters are an ordered map keyed by name.
 */
function sameComponent(left: MessageComponent, right: MessageComponent): boolean {
  if (left.name !== right.name || left.parameters.length !== right.parameters.length) {
    return false
  }
  // Parameter names are unique within an identifier and there are only ever a handful of them, so
  // a linear scan compares the two ordered maps without allocating.
  return left.parameters.every(([name, value]) =>
    right.parameters.some(([otherName, otherValue]) => otherName === name && otherValue === value),
  )
}

/**
 * Rejects a covered component list that resolves the same component twice.
 *
 * RFC 9421 requires that a component identifier, including its parameters, appear at most once in a
 * signature base, and that a parameterized Dictionary key appear at most once for a given field.
 * The second rule is enforced independently, so `"x";key="a"` and `"x";key="a";sf` are rejected
 * even though their identifiers differ.
 */
function assertUniqueComponents(components: ReadonlyArray<MessageComponent>): void {
  const parameterMaps = components.map(componentParameterMap)
  for (let index = 0; index < components.length; index++) {
    const identifier = components[index]!
    const parameters = parameterMaps[index]!
    const key = parameters.get('key')
    for (let other = 0; other < index; other++) {
      const otherIdentifier = components[other]!
      const otherParameters = parameterMaps[other]!
      if (sameComponent(identifier, otherIdentifier)) {
        fail(`Duplicate covered component "${identifier.name}"`)
      }

      if (
        typeof key === 'string' &&
        identifier.name === otherIdentifier.name &&
        key === otherParameters.get('key') &&
        parameters.get('req') === otherParameters.get('req') &&
        parameters.get('tr') === otherParameters.get('tr')
      ) {
        fail(`Duplicate covered dictionary key "${identifier.name}";key="${key}"`)
      }
    }
  }
}

/**
 * Builds the `@signature-params` value: an Inner List of covered component identifiers carrying the
 * signature metadata parameters.
 */
function signatureParametersInnerList(
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
): SfInnerList {
  return { kind: 'inner-list', value: components.map(componentToSfItem), parameters }
}

/**
 * Converts parsed signature metadata parameters into the public ordered form handed to
 * applications.
 */
function signatureParametersFromSf(
  parameters: SfParameters,
): Array<readonly [string, SignatureParameterValue]> {
  return parameters.map(([name, value]) => [name, signatureParameterValueFromSfBareItem(value)])
}

/** Resolves an injectable clock value to integer UNIX seconds, defaulting to the current time. */
function unixTimestamp(input: number | Date | undefined): number {
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

/**
 * Returns the request's target URI with any fragment removed.
 *
 * Fetch keeps the fragment in `Request.url`, but RFC 9421 derives `@target-uri`, `@request-
 * target`, `@query`, and `@query-param` from the target URI, which has none.
 */
function getTargetUri(request: Request): string {
  const hash = request.url.indexOf('#')
  const value = hash === -1 ? request.url : request.url.slice(0, hash)
  if (!ASCII.test(value)) {
    fail('Request target URI must contain only ASCII characters')
  }
  // An "http" or "https" URI must not carry a userinfo subcomponent, and Node.js and browsers refuse
  // to construct such a Request at all. Deno, Bun, and workerd allow it, which would put a password
  // into the signature base and into anything that logs or exchanges it. Rejecting here makes every
  // runtime behave the way the strictest ones already do.
  if (/^[^/?#]*\/\/[^/?#]*@/.test(value)) {
    fail('Request target URI must not include credentials')
  }
  return value
}

/** Parses a request's target URI, reporting a message whose URI cannot be resolved. */
function parseTargetUri(target: string): URL {
  try {
    return new URL(target)
  } catch (cause) {
    throw new TypeError('Request does not have a valid target URI', { cause })
  }
}

/**
 * The values derived from one request's target URI, memoized for the duration of a single signature
 * base.
 *
 * A covered component list is attacker-controlled during verification and can name many components
 * of the same message, including one `@query-param` per query parameter. Parsing the target URI and
 * the query string again for every component would make signature base generation quadratic in the
 * size of the request, so each request's derived state is computed at most once per signature
 * base.
 */
interface TargetUriDerivation {
  /** The target URI with any fragment removed. */
  readonly target: string
  /** The parsed target URI, used for the components that need its normalized parts. */
  readonly url: URL
  /** Encoded query parameter values indexed by encoded name, built on first `@query-param` use. */
  queryParameters?: Map<string, string[]>
}

/** Memoized target URI derivations for the requests read while building one signature base. */
type TargetUriDerivations = Map<Request, TargetUriDerivation>

/** Returns the memoized target URI derivation for a request, computing it on first use. */
function deriveTargetUri(request: Request, derivations: TargetUriDerivations): TargetUriDerivation {
  let derived = derivations.get(request)
  if (derived === undefined) {
    const target = getTargetUri(request)
    derived = { target, url: parseTargetUri(target) }
    derivations.set(request, derived)
  }
  return derived
}

/**
 * Percent-encodes a decoded query parameter name or value using the `application/x-www-form-
 * urlencoded` percent-encode set of the URL Standard.
 *
 * `encodeURIComponent` escapes that set except for `!`, `'`, `(`, `)`, and `~`, which are added
 * here. Spaces become `%20` rather than `+`, matching the worked example in RFC 9421.
 */
function formPercentEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()~]/g, (character) => {
    return `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  })
}

/**
 * Derives the `@query-param` component value for one encoded parameter name.
 *
 * The query string is parsed with the URL Standard's `application/x-www-form-urlencoded` parser and
 * each decoded name and value is re-encoded, so that `+`, percent escapes, and newlines round- trip
 * to one unambiguous ASCII value. RFC 9421 requires an error when the name is absent, and requires
 * a name that occurs more than once to be left out of the signature entirely.
 */
function deriveQueryParameter(derived: TargetUriDerivation, encodedName: string): string {
  if (derived.queryParameters === undefined) {
    const queryStart = derived.target.indexOf('?')
    const query = queryStart === -1 ? '' : derived.target.slice(queryStart + 1)
    const parameters = new Map<string, string[]>()
    for (const [name, value] of new URLSearchParams(query)) {
      const encoded = formPercentEncode(name)
      const values = parameters.get(encoded)
      if (values === undefined) {
        parameters.set(encoded, [formPercentEncode(value)])
      } else {
        values.push(formPercentEncode(value))
      }
    }
    derived.queryParameters = parameters
  }

  const matches = derived.queryParameters.get(encodedName)
  if (matches === undefined) {
    fail(`Query parameter "${encodedName}" is not present`)
  }
  if (matches.length !== 1) {
    // RFC 9421 requires a repeated query parameter name to be left out of the signature entirely,
    // so the component cannot be resolved and the signature base generation fails.
    fail(`Query parameter "${encodedName}" occurs more than once`)
  }
  return matches[0]!
}

/**
 * Derives the value of a request-targeted RFC 9421 derived component.
 *
 * `@query`, `@query-param`, `@request-target`, and `@target-uri` read the target URI as a string so
 * that percent-encoded octets are preserved exactly, as the RFC's simple string comparison rules
 * require.
 *
 * The components that read the authority or the absolute path require a target URI that has an
 * authority. Every URI scheme RFC 9421 applies to has one, so a message whose URI does not, such as
 * a `data:` or `blob:` URL, fails rather than deriving an empty authority or a relative path.
 */
function deriveRequestComponentValue(
  identifier: MessageComponent,
  parameters: ReadonlyMap<string, ComponentParameterValue>,
  request: Request,
  derivations: TargetUriDerivations,
): string {
  const derived = deriveTargetUri(request, derivations)
  const { target, url } = derived
  // The absolute path is normalized to "/" when the target URI has no path, matching the "@path"
  // normalization required by RFC 9421 for both components.
  const path = url.pathname || '/'
  const queryStart = target.indexOf('?')
  switch (identifier.name) {
    case '@method':
      return request.method
    case '@target-uri':
      return target
    case '@authority':
      // The URL parser already lowercases hosts of the special schemes used by HTTP; lowercasing
      // again satisfies the RFC's normalization requirement for every other scheme too.
      return assertTargetUriAuthority(url, identifier.name).toLowerCase()
    case '@scheme':
      return url.protocol.slice(0, -1).toLowerCase()
    case '@request-target':
      assertTargetUriAuthority(url, identifier.name)
      return path + (queryStart === -1 ? '' : target.slice(queryStart))
    case '@path':
      assertTargetUriAuthority(url, identifier.name)
      return path
    case '@query':
      return queryStart === -1 ? '?' : target.slice(queryStart)
    case '@query-param':
      return deriveQueryParameter(derived, parameters.get('name') as string)
    default:
      return fail(`Derived component "${identifier.name}" does not apply to a request`)
  }
}

/**
 * Returns the authority of a target URI, rejecting a URI that has none.
 *
 * RFC 9421 derives `@authority` from "the fully qualified authority component of the request" and
 * `@path` from "the absolute path of the request target". A URI without an authority, which the URL
 * parser reports as an empty host, has neither, so the component value cannot be derived.
 */
function assertTargetUriAuthority(url: URL, name: string): string {
  if (url.host === '') {
    fail(`Derived component "${name}" requires a target URI with an authority`)
  }
  return url.host
}

/**
 * Removes the spaces and horizontal tabs at both ends of a field value.
 *
 * Scanning rather than replacing with a regular expression matters here: an unanchored alternation
 * such as `/^[ \t]+|[ \t]+$/` restarts at every position, which makes canonicalization quadratic in
 * the length of a field value that a peer controls.
 */
function trimFieldWhitespace(value: string): string {
  let start = 0
  let end = value.length
  while (start < end && (value[start] === ' ' || value[start] === '\t')) {
    start++
  }
  while (end > start && (value[end - 1] === ' ' || value[end - 1] === '\t')) {
    end--
  }
  return value.slice(start, end)
}

/**
 * Applies the RFC 9421 field value canonicalization to a single field line: strip leading and
 * trailing whitespace, then replace obsolete line folding with a single space.
 *
 * RFC 9112 defines obsolete line folding as `OWS CRLF RWS`, so the whitespace on both sides of the
 * CRLF belongs to the fold and collapses into the single replacement space with it. The split
 * pattern covers the CRLF and the whitespace after it, and the whitespace before it is trimmed from
 * the end of each preceding segment. Every match starts at a literal `\r\n`, which keeps the work
 * linear in the length of the value.
 *
 * A CRLF that is not followed by whitespace is not a fold, so it survives into the result and is
 * rejected by {@link assertFieldValue}.
 */
function normalizeFieldLine(value: string): string {
  const trimmed = trimFieldWhitespace(value)
  if (!trimmed.includes('\r\n')) {
    return trimmed
  }
  const segments = trimmed.split(/\r\n[ \t]+/)
  const last = segments.length - 1
  return segments
    .map((segment, index) => (index === last ? segment : trimFieldWhitespace(segment)))
    .join(' ')
}

/**
 * Rejects a field or component value containing a newline or any other control character that
 * cannot appear in a signature base line.
 */
function assertFieldValue(value: string, name: string): void {
  if (/[\r\n]/.test(value)) {
    fail(`HTTP field "${name}" contains a newline`)
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) {
    fail(`HTTP field "${name}" contains an invalid control character`)
  }
}

/**
 * Reads a field's occurrences from a Fetch message without an application adapter.
 *
 * Fetch combines repeated field lines into one value, so this returns at most one entry, except for
 * `set-cookie` in runtimes that expose `Headers.getSetCookie()`. That exception is reachable on the
 * server-side runtimes only: browsers strip `set-cookie` from requests and hide it on responses, so
 * there the field looks absent whichever way it is read. Trailers are never exposed by Fetch, so
 * they require the `fieldValues` option.
 */
function fieldValuesFromHeaders(
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

/**
 * Collects and canonicalizes a field's occurrences from the application adapter, or from Fetch when
 * no adapter is configured.
 *
 * An absent field fails signature base generation, as RFC 9421 requires.
 */
function collectFieldValues(
  message: Request | Response,
  name: string,
  trailers: boolean,
  relatedRequest: boolean,
  options: SignatureContext,
): string[] {
  const values =
    options.fieldValues === undefined
      ? fieldValuesFromHeaders(message, name, trailers)
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

/**
 * Converts an HTTP field value to its bytes for the `bs` component parameter, taking one octet per
 * code unit.
 *
 * Fetch models a field value as a byte string, so a value read from `Headers` normally has one code
 * unit per received octet and this recovers the received bytes exactly. Cloudflare Workers is the
 * exception: it decodes received field values as UTF-8, which loses the octets, and no
 * transformation here can recover them. Supply the `fieldValues` option with the raw octets when
 * `bs` has to interoperate with a non-ASCII field value there.
 */
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

/**
 * Resolves the Structured Field top-level type of an HTTP field.
 *
 * `Signature`, `Signature-Input`, and `Accept-Signature` are Dictionaries by definition. Every
 * other field's type is application knowledge, supplied through the `structuredFields` option, and
 * RFC 9421 requires an error when the type is unknown to the implementation.
 */
function resolveStructuredFieldType(
  name: string,
  options: SignatureContext,
): StructuredFieldType | undefined {
  if (name === 'signature-input' || name === 'signature' || name === 'accept-signature') {
    return 'dictionary'
  }
  if (options.structuredFields !== undefined) {
    // Own properties only. A component can name a field such as "constructor", which every plain
    // object inherits, and reading it would report a configured type that the application never
    // wrote. Both paths reject the component; this one names the actual reason.
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

/**
 * Derives the component value of an HTTP field, applying the `bs`, `key`, `sf`, and `tr` component
 * parameters.
 *
 * Without those parameters the occurrences are combined with `", "`. With `bs` each occurrence is
 * wrapped as a Byte Sequence so that separate lines cannot be confused with one combined line. With
 * `key` or `sf` the combined value is parsed and re-serialized strictly.
 */
function deriveFieldComponentValue(
  identifier: MessageComponent,
  message: Request | Response,
  relatedRequest: boolean,
  options: SignatureContext,
): string {
  const parameters = componentParameterMap(identifier)
  const sf = readComponentFlag(parameters, 'sf')
  const bs = readComponentFlag(parameters, 'bs')
  const trailers = readComponentFlag(parameters, 'tr')
  const key = parameters.get('key')

  const fetchExposesOccurrences =
    identifier.name === 'set-cookie' &&
    typeof (message.headers as Headers & { getSetCookie?: unknown }).getSetCookie === 'function'
  if (bs && options.fieldValues === undefined && !fetchExposesOccurrences) {
    fail(`"${identifier.name}";bs requires "fieldValues" because Fetch hides field occurrences`)
  }

  const values = collectFieldValues(message, identifier.name, trailers, relatedRequest, options)

  if (bs) {
    const list: SfList = values.map((value) => ({
      kind: 'item',
      value: { kind: 'binary', value: latin1Bytes(value, identifier.name) },
      parameters: [],
    }))
    return serializeList(list)
  }

  const combined = values.join(', ')
  if (key !== undefined) {
    const type = resolveStructuredFieldType(identifier.name, options)
    if (type !== undefined && type !== 'dictionary') {
      fail(
        `Structured Field type for "${identifier.name}" must be "dictionary" with the "key" parameter`,
      )
    }
    const dictionary = parseStructuredField(combined, 'dictionary') as SfDictionary
    const member = dictionary.find(([name]) => name === key)?.[1]
    if (member === undefined) {
      fail(`Structured Field "${identifier.name}" has no member "${key}"`)
    }
    return serializeMember(member)
  }

  if (sf) {
    const type = resolveStructuredFieldType(identifier.name, options)
    if (type === undefined) {
      fail(`Structured Field type for "${identifier.name}" is required by the "sf" parameter`)
    }
    return serializeStructuredField(parseStructuredField(combined, type), type)
  }

  return combined
}

/**
 * Derives the component value of one covered component from the target message, or from the related
 * request when the identifier carries `req`.
 *
 * Derived component values are additionally constrained by RFC 9421 to printable ASCII with no
 * leading or trailing space.
 */
function resolveComponentValue(
  identifier: MessageComponent,
  message: Request | Response,
  options: SignatureContext,
  derivations: TargetUriDerivations,
): string {
  validateComponentForMessage(identifier, message)
  const parameters = componentParameterMap(identifier)
  const relatedRequest = parameters.has('req')
  let source: Request | Response = message
  if (relatedRequest) {
    if (options.request === undefined) {
      fail(`Component "${identifier.name}";req requires the related request`)
    }
    assertMessage(options.request)
    if (!isRequest(options.request)) {
      fail('"request" must be the related Request')
    }
    source = options.request
  }

  let value: string
  if (identifier.name.startsWith('@')) {
    if (identifier.name === '@status') {
      const status = (source as Response).status
      if (!Number.isInteger(status) || status < 100 || status > 599) {
        fail('"@status" requires an unfiltered HTTP response status')
      }
      value = String(status)
    } else {
      if (!isRequest(source)) {
        fail(`Derived component "${identifier.name}" requires a request context`)
      }
      value = deriveRequestComponentValue(identifier, parameters, source, derivations)
    }
    if (!PRINTABLE_ASCII.test(value) || value.startsWith(' ') || value.endsWith(' ')) {
      fail(`Derived component "${identifier.name}" has an invalid value`)
    }
  } else {
    value = deriveFieldComponentValue(identifier, source, relatedRequest, options)
  }
  assertFieldValue(value, identifier.name)
  return value
}

/**
 * Builds the RFC 9421 signature base: one canonicalized line per covered component, followed by the
 * `@signature-params` line.
 *
 * The whole result must be ASCII, which is where a non-ASCII field value is rejected.
 *
 * Target URI derivations are memoized for this one base, so a long covered component list cannot
 * make URI and query string parsing quadratic. The memo is per call, so every rebuild performed by
 * {@link assertSignatureBaseUnchanged} re-reads the message.
 */
function buildSignatureBase(
  message: Request | Response,
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
  options: SignatureContext,
): string {
  assertUniqueComponents(components)
  const derivations: TargetUriDerivations = new Map()
  let output = ''
  for (const identifier of components) {
    const serializedIdentifier = serializeItem(componentToSfItem(identifier))
    const value = resolveComponentValue(identifier, message, options, derivations)
    output += `${serializedIdentifier}: ${value}\n`
  }
  output += `"@signature-params": ${serializeInnerList(
    signatureParametersInnerList(components, parameters),
  )}`
  assertAscii(output, 'Signature base')
  return output
}

/**
 * Rebuilds the signature base and rejects the operation unless it still matches the base that was
 * signed or verified.
 *
 * Called around every suspension point so that a message, related request, field adapter, or
 * trailer context that changes while an asynchronous provider or policy callback runs cannot
 * produce a signature over a message that was never observed as a whole.
 */
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
 * @example
 *
 * The signature base is the exact ASCII string handed to cryptography: one line per covered
 * component, then the `@signature-params` line. Compare it byte for byte with a peer implementation
 * before suspecting the cryptography.
 *
 * ```ts
 * const request = new Request('https://example.com/items?limit=10', {
 *   method: 'POST',
 *   headers: { 'example-field': '  value  ' },
 * })
 *
 * const base = FetchSig.createSignatureBase(request, {
 *   components: [
 *     '@method',
 *     '@authority',
 *     '@path',
 *     FetchSig.component('@query-param', [['name', 'limit']]),
 *     'example-field',
 *   ],
 *   parameters: [
 *     ['created', 1_735_689_600],
 *     ['keyid', 'interop-key'],
 *   ],
 * })
 *
 * // "@method": POST
 * // "@authority": example.com
 * // "@path": /items
 * // "@query-param";name="limit": 10
 * // "example-field": value
 * // "@signature-params": ("@method" "@authority" "@path" "@query-param";name="limit"
 * //   "example-field");created=1735689600;keyid="interop-key"
 * console.log(base)
 * ```
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
  assertSignatureContext(options)
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

/**
 * Interprets one `Signature-Input` Dictionary member as a labeled covered component list with its
 * signature metadata parameters.
 */
function parseSignatureInputMember(label: string, member: SfMember): ParsedSignatureInput {
  if (member.kind !== 'inner-list') {
    fail(`Signature-Input member "${label}" must be an Inner List`)
  }
  return { label, components: member.value.map(componentFromSfItem), parameters: member.parameters }
}

/**
 * Enforces the RFC 9421 rules a parsed `Signature-Input` member must satisfy: known parameter
 * types, valid component identifiers and parameters, and no duplicate covered component.
 */
function validateSignatureInput(input: ParsedSignatureInput): ParsedSignatureInput {
  validateKnownSignatureParameters(input.parameters, false)
  for (const identifier of input.components) {
    validateComponentParameters(identifier)
  }
  assertUniqueComponents(input.components)
  return input
}

/** Interprets one `Signature` Dictionary member as a signature byte sequence. */
function parseSignatureValueMember(label: string, member: SfMember): ParsedSignatureValue {
  if (member.kind !== 'item' || member.value.kind !== 'binary') {
    fail(`Signature member "${label}" must be a Byte Sequence`)
  }
  return { label, value: cloneBytes(member.value.value) }
}

/** Parses a `Signature-Input` field value into validated members, rejecting a repeated label. */
function parseSignatureInputInternal(value: string): ParsedSignatureInput[] {
  const dictionary = parseStructuredField(value, 'dictionary', true) as SfDictionary
  return dictionary.map(([label, member]) => {
    return validateSignatureInput(parseSignatureInputMember(label, member))
  })
}

/**
 * Parses a `Signature` field value into labeled signature byte sequences, rejecting a repeated
 * label.
 */
function parseSignatureInternal(value: string): ParsedSignatureValue[] {
  const dictionary = parseStructuredField(value, 'dictionary', true) as SfDictionary
  return dictionary.map(([label, member]) => parseSignatureValueMember(label, member))
}

/**
 * Parses a `Signature-Input` field value into its labeled covered component lists and signature
 * metadata parameters.
 *
 * Rejects a repeated label, an unknown derived component, an inapplicable component parameter, a
 * duplicate covered component, and a known signature metadata parameter of the wrong Structured
 * Field type. It does not look at any message and does not verify anything.
 *
 * @example
 *
 * Inspect what a field value claims, for routing or diagnostics. Nothing here is authenticated.
 *
 * ```ts
 * const [signature] = FetchSig.parseSignatureInput(
 *   'sig1=("@method" "@path" "example-dictionary";key="a");created=1735689600;keyid="client-key"',
 * )
 *
 * // sig1
 * console.log(signature!.label)
 *
 * // [ '@method', '@path', 'example-dictionary' ]
 * console.log(signature!.components.map(({ name }) => name))
 *
 * // [ [ 'created', 1735689600 ], [ 'keyid', 'client-key' ] ]
 * console.log(signature!.parameters)
 * ```
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
    parameters: signatureParametersFromSf(parameters),
  }))
}

/**
 * Parses a `Signature` field value into its labeled signature byte sequences.
 *
 * Rejects a repeated label and a member that is not a Byte Sequence. It does not look at any
 * message and does not verify anything.
 *
 * @example
 *
 * Decode the raw signature bytes carried under each label.
 *
 * ```ts
 * const signatures = FetchSig.parseSignature('sig1=:AQIDBA==:, sig2=:BQYHCA==:')
 *
 * // sig1 Uint8Array(4) [ 1, 2, 3, 4 ]
 * // sig2 Uint8Array(4) [ 5, 6, 7, 8 ]
 * for (const { label, signature } of signatures) {
 *   console.log(label, signature)
 * }
 * ```
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

/**
 * Reads an HTTP field whose value is a Structured Field Dictionary, reporting a field that is
 * present but empty as absent.
 *
 * RFC 9651 gives every Dictionary field a default empty value and represents an empty Dictionary by
 * omitting the field, so `Signature-Input: ` carries exactly as much as no `Signature-Input` at
 * all. Normalizing here keeps the reading and appending helpers from disagreeing about such a
 * message.
 */
function getDictionaryField(headers: Headers, name: string): string | null {
  const value = headers.get(name)
  return value === null || /^[ \t]*$/.test(value) ? null : value
}

/**
 * Parses the `Signature` and `Signature-Input` fields of a message and checks that they pair up.
 *
 * Both fields must be present or both absent, neither may repeat a label, and the two label sets
 * must be identical. A message that fails these checks is treated as malformed rather than as a
 * message carrying some usable signatures.
 */
function parseSignatureFieldDictionaries(headers: Headers): {
  readonly inputs: SfDictionary
  readonly values: SfDictionary
} {
  const signatureInput = getDictionaryField(headers, 'signature-input')
  const signature = getDictionaryField(headers, 'signature')
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

/**
 * Parses and validates every signature carried by a message's `Signature` and `Signature-Input`
 * fields.
 */
function parseSignatureFieldMembers(headers: Headers): {
  readonly inputs: ParsedSignatureInput[]
  readonly values: ParsedSignatureValue[]
} {
  const dictionaries = parseSignatureFieldDictionaries(headers)
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
 * Parses and pairs every signature carried by a Fetch message, so that an application can choose
 * which label to verify.
 *
 * Returns an empty array when the message carries neither field. Throws when the two fields do not
 * pair up: one present without the other, a repeated label, or a label in one field that is missing
 * from the other. Pairing is checked across the whole message, so one malformed member makes the
 * message unusable rather than yielding the remaining signatures.
 *
 * This reports what a message claims. Nothing here is authenticated until {@link verify} succeeds.
 *
 * @example
 *
 * Decide which label to verify, then verify it. Pick the label from trusted local configuration - a
 * label is an unsigned Dictionary key and cannot stand for a role or an identity.
 *
 * ```ts
 * declare const message: Request
 * declare const verifier: FetchSig.VerifierFactory
 *
 * // application [ [ 'created', 1735689600 ], [ 'keyid', 'client-key' ] ]
 * // audit [ [ 'created', 1735689600 ], [ 'keyid', 'audit-key' ] ]
 * for (const signature of FetchSig.getSignatures(message)) {
 *   console.log(signature.label, signature.parameters)
 * }
 *
 * await FetchSig.verify(message, {
 *   label: 'application',
 *   verifier,
 *   policy: {
 *     requiredComponents: ['@method', '@authority', '@path'],
 *     requiredParameters: ['created', 'keyid'],
 *     algorithms: ['ed25519'],
 *     maxAge: 60,
 *   },
 * })
 * ```
 *
 * @group Recipient
 */
export function getSignatures(message: Request | Response): ReadonlyArray<MessageSignature> {
  assertMessage(message)
  const { inputs, values } = parseSignatureFieldMembers(message.headers)
  return inputs.map(({ label, components, parameters }) => {
    const signature = values.find((entry) => entry.label === label)!.value
    return { label, components, parameters: signatureParametersFromSf(parameters), signature }
  })
}

/**
 * Selects the signature to verify and returns it in parsed, internal, and public forms.
 *
 * A label is required when the message carries more than one signature, because RFC 9421 labels are
 * not covered by any signature and therefore carry no application meaning on their own.
 */
function selectSignature(
  message: Request | Response,
  label: string | undefined,
): {
  readonly input: ParsedSignatureInput
  readonly signature: Uint8Array<ArrayBuffer>
  readonly public: MessageSignature
} {
  const { inputs, values } = parseSignatureFieldDictionaries(message.headers)
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
      parameters: signatureParametersFromSf(input.parameters),
      signature,
    },
  }
}

/**
 * Invokes a {@link SignerFactory} and rejects a return value that does not implement {@link Signer}.
 *
 * Any exception the factory throws becomes the `cause` of the reported error.
 */
function signerFromFactory(factory: SignerFactory): Readonly<Signer> {
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

/**
 * Invokes a {@link VerifierFactory} with the parsed signature and message context, and rejects a
 * return value that does not implement {@link Verifier}.
 *
 * The factory is the application's key-selection and trust boundary, so any exception it throws,
 * such as an unknown `keyid`, becomes the `cause` of the reported error.
 */
function verifierFromFactory(
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

/** Returns the value of one public signature metadata parameter, or `undefined` when it is absent. */
function findSignatureParameterValue(
  parameters: ReadonlyArray<readonly [string, SignatureParameterValue]>,
  name: string,
): SignatureParameterValue | undefined {
  return parameters.find(([candidate]) => candidate === name)?.[1]
}

/**
 * Copies one public signature metadata parameter value so that application code cannot reach the
 * value used by policy checks.
 */
function cloneSignatureParameterValue(value: SignatureParameterValue): SignatureParameterValue {
  if (isUint8Array(value)) {
    return cloneBytes(value)
  }
  if (value !== null && typeof value === 'object') {
    return { ...value }
  }
  return value
}

/**
 * Deep copies a parsed signature so that a verifier factory or policy callback cannot mutate the
 * data that verification and policy enforcement rely on.
 */
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

/**
 * Serializes one signature as the single-member `Signature-Input` and `Signature` Dictionary values
 * that can be appended to a message.
 */
function serializeSignatureFields(
  label: string,
  components: ReadonlyArray<MessageComponent>,
  parameters: SfParameters,
  signature: Uint8Array,
): { readonly signatureInput: string; readonly signatureField: string } {
  const inputDictionary: SfDictionary = [
    [label, signatureParametersInnerList(components, parameters)],
  ]
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

/**
 * Creates one signature and returns it together with a check that re-verifies the signing context.
 *
 * Refuses to cover the `Signature` and `Signature-Input` fields the signature is about to be
 * appended to, unless the identifier selects a different message or an existing labeled member with
 * `req`, `tr`, or `key`. Signing something that this operation is itself about to change could
 * never be reproduced by a verifier.
 */
async function createSignatureInternal(
  message: Request | Response,
  options: SignOptions,
): Promise<SignatureCreation> {
  assertMessage(message)
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  assertSignatureContext(options)
  const label = options.label ?? 'sig1'
  assertSfKey(label, 'Signature label')

  const existing = parseSignatureFieldDictionaries(message.headers)
  if (existing.inputs.some(([existingLabel]) => existingLabel === label)) {
    fail(`Signature label "${label}" is already present`)
  }

  const components = normalizeComponents(options.components)
  for (const identifier of components) {
    const componentParameters = componentParameterMap(identifier)
    if (
      (identifier.name === 'signature' || identifier.name === 'signature-input') &&
      componentParameters.get('req') !== true &&
      componentParameters.get('tr') !== true &&
      componentParameters.get('key') === undefined
    ) {
      fail('A signature cannot cover fields to which it is being appended')
    }
  }
  const parameters = normalizeSignatureParameters(options.parameters, unixTimestamp(options.now))

  const guard = createMessageMutationGuard(message, options)
  const base = buildSignatureBase(message, components, parameters, options)
  assertMessageUnchanged(guard, 'signing')

  const signer = signerFromFactory(options.signer)
  const algorithm = signer.alg
  assertSignatureBaseUnchanged(guard, components, parameters, options, base, 'signing')

  const signaledAlgorithm = findSfParameterValue(parameters, 'alg')
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
  const serializedFields = serializeSignatureFields(label, components, parameters, ownedSignature)
  const fields: SignatureFields = {
    label,
    components,
    parameters: signatureParametersFromSf(parameters),
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
 * @example
 *
 * Reach for this instead of {@link sign} when a framework owns message construction, or when the
 * source message's body must stay readable: nothing here touches the message or its body.
 *
 * ```ts
 * declare const signer: FetchSig.SignerFactory
 *
 * const request = new Request('https://api.example/orders', { method: 'POST', body: '{}' })
 *
 * const fields = await FetchSig.createSignature(request, {
 *   signer,
 *   label: 'application',
 *   components: ['@method', '@target-uri'],
 *   now: 1_735_689_600,
 * })
 *
 * // application=("@method" "@target-uri");created=1735689600
 * console.log(fields.signatureInput)
 *
 * // application=:<base64 signature bytes>:
 * console.log(fields.signatureField)
 *
 * // The source request is untouched, so its body is still readable here.
 * const headers = FetchSig.appendSignature(request.headers, fields)
 * ```
 *
 * @example
 *
 * `created` is added for you. Suppress it with `['created', false]`, or place it yourself to
 * control where it lands in the signed parameter order.
 *
 * ```ts
 * declare const message: Request
 * declare const signer: FetchSig.SignerFactory
 *
 * const withoutCreated = await FetchSig.createSignature(message, {
 *   signer,
 *   components: ['@method'],
 *   parameters: [
 *     ['created', false],
 *     ['keyid', 'client-key'],
 *   ],
 * })
 *
 * // sig1=("@method");keyid="client-key"
 * console.log(withoutCreated.signatureInput)
 *
 * const createdLast = await FetchSig.createSignature(message, {
 *   signer,
 *   components: ['@method'],
 *   parameters: [
 *     ['keyid', 'client-key'],
 *     ['created', 1_735_689_600],
 *   ],
 * })
 *
 * // sig1=("@method");keyid="client-key";created=1735689600
 * console.log(createdLast.signatureInput)
 * ```
 *
 * @group Sender
 */
export async function createSignature(
  message: Request | Response,
  options: SignOptions,
): Promise<SignatureFields> {
  return (await createSignatureInternal(message, options)).fields
}

/**
 * Rejects responses that the Fetch `Response` constructor cannot reproduce, so that the append
 * helpers report the reason instead of surfacing the constructor's own `RangeError`.
 *
 * Fetch reports opaque and network-error responses with status zero, and the `Response` constructor
 * only accepts statuses in the 200-599 range, so informational responses cannot be rebuilt either.
 */
function assertReconstructableResponse(response: Response, carried: string): void {
  if (response.status === 0) {
    fail(`Opaque and error responses cannot carry ${carried}`)
  }
  if (!Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
    fail(`Fetch cannot reconstruct a response with status ${response.status}`)
  }
}

/**
 * Returns the body to pass to the `Response` constructor when rebuilding a response.
 *
 * Fetch defines 204, 205, and 304 as null body statuses and its constructor rejects a body for
 * them. A response that came from the network can still expose a non-null body stream for those
 * statuses, and whether it does is runtime-dependent, so the body is dropped here rather than
 * passed on. The remaining null body statuses, 101 and 103, are already excluded by
 * {@link assertReconstructableResponse}.
 */
function reconstructableResponseBody(response: Response): ReadableStream<Uint8Array> | null {
  const { status } = response
  if (status === 204 || status === 205 || status === 304) {
    return null
  }
  return response.body
}

/**
 * Appends a member to an HTTP field whose value is a Structured Field Dictionary, combining it with
 * any existing members using `", "`.
 *
 * A field that is present but empty is replaced rather than extended, because prefixing `", "` to
 * an empty value would produce a Dictionary that starts with a comma and no longer parses.
 */
function appendToDictionaryField(headers: Headers, name: string, value: string): void {
  const existing = getDictionaryField(headers, name)
  headers.set(name, existing === null ? value : `${existing}, ${value}`)
}

/**
 * Copies `Headers` and appends one signature to the `Signature-Input` and `Signature` fields.
 *
 * The supplied field values are re-parsed and checked to contain exactly the one expected label,
 * and the combined fields are re-parsed afterwards, so a malformed or colliding input cannot
 * produce a message whose signature fields no longer pair up.
 */
function appendSignatureHeaders(headers: Headers, fields: SignatureFields): Headers {
  const output = new Headers(headers)
  const existing = parseSignatureFieldDictionaries(output)
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

  appendToDictionaryField(output, 'signature-input', fields.signatureInput)
  appendToDictionaryField(output, 'signature', fields.signatureField)
  parseSignatureFieldDictionaries(output)
  return output
}

/**
 * Adds one signature to `Headers` and returns a new `Headers` object.
 *
 * @example
 *
 * Existing signatures are kept, so several parties can sign the same message under distinct labels.
 * A label that is already present is rejected rather than overwritten.
 *
 * ```ts
 * declare const request: Request
 * declare const applicationSigner: FetchSig.SignerFactory
 * declare const auditSigner: FetchSig.SignerFactory
 *
 * const application = await FetchSig.createSignature(request, {
 *   label: 'application',
 *   signer: applicationSigner,
 *   components: ['@method', '@authority', '@path'],
 * })
 * let headers = FetchSig.appendSignature(request.headers, application)
 *
 * const audit = await FetchSig.createSignature(new Request(request, { headers }), {
 *   label: 'audit',
 *   signer: auditSigner,
 *   components: ['@method', '@target-uri'],
 * })
 * headers = FetchSig.appendSignature(headers, audit)
 *
 * // application=("@method" "@authority" "@path");created=…, audit=("@method" "@target-uri");created=…
 * console.log(headers.get('signature-input'))
 * ```
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
  assertReconstructableResponse(message, 'HTTP message signatures')
  return new Response(reconstructableResponseBody(message), {
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
 * @example
 *
 * Sign a request. Cover everything the recipient will base a decision on: the method so a `GET`
 * cannot be replayed as a `POST`, the destination, and the fields that change how the body is
 * interpreted.
 *
 * ```ts
 * declare const signer: FetchSig.SignerFactory
 *
 * const unsigned = new Request('https://api.example/orders?account=123', {
 *   method: 'POST',
 *   headers: {
 *     'content-type': 'application/json',
 *     'content-digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
 *   },
 *   body: '',
 * })
 *
 * const signed = await FetchSig.sign(unsigned, {
 *   signer,
 *   components: [
 *     '@method',
 *     '@authority',
 *     '@path',
 *     FetchSig.component('@query-param', [['name', 'account']]),
 *     'content-type',
 *     'content-digest',
 *   ],
 *   parameters: [
 *     ['alg', 'ed25519'],
 *     ['keyid', 'https://issuer.example/keys/current'],
 *     ['tag', 'order'],
 *   ],
 *   now: 1_735_689_600,
 * })
 *
 * // sig1=("@method" "@authority" "@path" "@query-param";name="account" "content-type"
 * //   "content-digest");created=1735689600;alg="ed25519"
 * //   ;keyid="https://issuer.example/keys/current";tag="order"
 * console.log(signed.headers.get('signature-input'))
 *
 * // Send the returned request; the source request must not be reused.
 * await fetch(signed)
 * ```
 *
 * @example
 *
 * Sign a response and bind it to the exact request that produced it. Request components need the
 * `req` parameter, and that request has to be supplied.
 *
 * ```ts
 * declare const signer: FetchSig.SignerFactory
 * declare const request: Request
 * declare const response: Response
 *
 * const signed = await FetchSig.sign(response, {
 *   signer,
 *   request,
 *   components: [
 *     '@status',
 *     'content-type',
 *     FetchSig.component('@method', [['req', true]]),
 *     FetchSig.component('@authority', [['req', true]]),
 *     FetchSig.component('@path', [['req', true]]),
 *   ],
 *   parameters: [['keyid', 'https://issuer.example/keys/current']],
 * })
 * ```
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

/**
 * A verification policy after {@link snapshotVerificationPolicy} has validated and normalized it.
 *
 * Narrowing the optional members lets policy enforcement rely on the checks having already run.
 */
interface NormalizedVerificationPolicy extends VerificationPolicy {
  readonly requiredComponents: ReadonlyArray<MessageComponent>
  readonly requiredParameters: ReadonlyArray<string>
  readonly algorithms: ReadonlyArray<string>
  readonly clockSkew: number
  readonly now?: number
}

/**
 * Validates everything about a verification policy that does not depend on a signature, and copies
 * it so that it cannot change during an asynchronous verification.
 *
 * Called when a Fetch wrapper is created as well as on every `verify()` call, so a malformed policy
 * is reported before any message is processed.
 */
function snapshotVerificationPolicy(policy: VerificationPolicy): NormalizedVerificationPolicy {
  if (policy === null || typeof policy !== 'object') {
    fail('"policy" must be an object')
  }
  // Every member is read exactly once, into a local, and only the local is validated and stored.
  // Reading a member again to store it would let an accessor return a different value than the one
  // that passed validation, which would defeat the point of snapshotting the policy.
  const requiredComponents = policy.requiredComponents
  const requiredParameters = policy.requiredParameters
  const algorithms = policy.algorithms
  const validate = policy.validate
  const clockSkew = policy.clockSkew ?? 0
  const maxAge = policy.maxAge
  const now = policy.now

  if (
    !Array.isArray(requiredComponents) ||
    !Array.isArray(requiredParameters) ||
    !Array.isArray(algorithms)
  ) {
    fail('"policy" must define requiredComponents, requiredParameters, and algorithms arrays')
  }
  if (validate !== undefined && typeof validate !== 'function') {
    fail('"policy.validate" must be a function')
  }
  if (algorithms.length === 0) {
    fail('"policy.algorithms" must not be empty')
  }
  if (algorithms.some((algorithm) => typeof algorithm !== 'string' || algorithm.length === 0)) {
    fail('"policy.algorithms" must contain non-empty strings')
  }
  for (const parameter of requiredParameters) {
    if (typeof parameter !== 'string') {
      fail('"policy.requiredParameters" must contain strings')
    }
    assertSfKey(parameter, 'Required signature parameter')
  }
  if (!Number.isFinite(clockSkew) || clockSkew < 0) {
    fail('"policy.clockSkew" must be a non-negative number')
  }
  if (maxAge !== undefined && (!Number.isFinite(maxAge) || maxAge < 0)) {
    fail('"policy.maxAge" must be a non-negative number')
  }
  return {
    requiredComponents: normalizeComponents(requiredComponents),
    requiredParameters: [...requiredParameters],
    algorithms: [...algorithms],
    maxAge,
    clockSkew,
    now: now === undefined ? undefined : unixTimestamp(now),
    validate,
  }
}

/**
 * Applies a validated policy to one parsed signature: algorithm allowlist, covered component
 * coverage, required metadata parameters, and timestamp acceptance.
 *
 * Run before and after cryptographic verification, and again after `policy.validate`, so that a
 * signature which expires while an asynchronous callback is running is still rejected.
 */
function enforceVerificationPolicy(
  signature: Readonly<MessageSignature>,
  policy: NormalizedVerificationPolicy,
): void {
  const signaledAlgorithm = findSignatureParameterValue(signature.parameters, 'alg')
  if (typeof signaledAlgorithm === 'string' && !policy.algorithms.includes(signaledAlgorithm)) {
    fail(`Algorithm "${signaledAlgorithm}" is not allowed by policy`)
  }

  for (const required of policy.requiredComponents) {
    if (!signature.components.some((covered) => sameComponent(required, covered))) {
      fail(`Required component "${required.name}" is not covered`)
    }
  }

  for (const parameter of policy.requiredParameters) {
    if (findSignatureParameterValue(signature.parameters, parameter) === undefined) {
      fail(`Required signature parameter "${parameter}" is missing`)
    }
  }

  const skew = policy.clockSkew
  // Re-read the clock on every call so that a signature which expires while an asynchronous
  // verifier or policy callback is running is still rejected.
  const now = unixTimestamp(policy.now)
  const created = findSignatureParameterValue(signature.parameters, 'created')
  const expires = findSignatureParameterValue(signature.parameters, 'expires')
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
    if (created === undefined) {
      fail('"policy.maxAge" requires the "created" signature parameter')
    }
    if (now - created > policy.maxAge + skew) {
      fail('HTTP message signature is older than policy permits')
    }
  }
}

/**
 * Checks the algorithm the verifier factory selected against the policy allowlist and against the
 * `alg` signature parameter.
 *
 * RFC 9421 requires the algorithms resolved from different sources to agree.
 */
function enforceVerificationAlgorithm(
  signature: Readonly<MessageSignature>,
  algorithm: string,
  policy: NormalizedVerificationPolicy,
): void {
  if (!policy.algorithms.includes(algorithm)) {
    fail(`Algorithm "${algorithm}" is not allowed by policy`)
  }

  const signaledAlgorithm = findSignatureParameterValue(signature.parameters, 'alg')
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
 * @example
 *
 * Verification needs all three of a key-resolving verifier factory, an explicit policy, and the
 * cryptographic check. There is no mode that accepts any cryptographically valid signature.
 *
 * ```ts
 * declare const request: Request
 * declare const verifier: FetchSig.VerifierFactory
 *
 * const verified = await FetchSig.verify(request, {
 *   verifier,
 *   policy: {
 *     // The exact components the application relies on, matched with their parameters.
 *     requiredComponents: ['@method', '@authority', '@path', 'content-digest'],
 *     requiredParameters: ['created', 'keyid', 'nonce'],
 *     algorithms: ['ed25519'],
 *     maxAge: 60,
 *     clockSkew: 5,
 *     async validate(signature, context) {
 *       // Runs only after the signature is cryptographically valid, so the nonce is authentic.
 *       const nonce = signature.parameters.find(([name]) => name === 'nonce')?.[1]
 *       if (typeof nonce !== 'string') {
 *         throw new Error('A nonce is required')
 *       }
 *       await claimNonceOnce(nonce, context.message)
 *     },
 *   },
 * })
 *
 * declare function claimNonceOnce(nonce: string, message: Request | Response): Promise<void>
 *
 * // ed25519 [ [ 'created', 1735689600 ], [ 'keyid', 'client-key' ], [ 'nonce', '…' ] ]
 * console.log(verified.algorithm, verified.parameters)
 * ```
 *
 * @example
 *
 * Verify a response and bind it to the request that produced it. Without the related request, a
 * signature covering `;req` components cannot be reproduced and verification fails.
 *
 * ```ts
 * declare const sentRequest: Request
 * declare const response: Response
 * declare const verifier: FetchSig.VerifierFactory
 *
 * await FetchSig.verify(response, {
 *   request: sentRequest,
 *   verifier,
 *   policy: {
 *     requiredComponents: [
 *       '@status',
 *       FetchSig.component('@method', [['req', true]]),
 *       FetchSig.component('@authority', [['req', true]]),
 *       FetchSig.component('@path', [['req', true]]),
 *     ],
 *     requiredParameters: ['created', 'keyid'],
 *     algorithms: ['ed25519'],
 *     maxAge: 60,
 *   },
 * })
 * ```
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
  assertSignatureContext(options)
  const policy = snapshotVerificationPolicy(options.policy)
  const selected = selectSignature(message, options.label)
  for (const identifier of selected.input.components) {
    validateComponentForMessage(identifier, message)
  }

  const signature = cloneMessageSignature(selected.public)
  enforceVerificationPolicy(signature, policy)
  const guard = createMessageMutationGuard(message, options)
  const base = buildSignatureBase(
    message,
    selected.input.components,
    selected.input.parameters,
    options,
  )
  assertMessageUnchanged(guard, 'verification')

  const context: VerificationContext = { message, request: options.request }
  const verifier = verifierFromFactory(options.verifier, cloneMessageSignature(signature), {
    ...context,
  })
  const algorithm = verifier.alg
  enforceVerificationAlgorithm(signature, algorithm, policy)

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
  enforceVerificationPolicy(signature, policy)
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
    enforceVerificationPolicy(signature, policy)
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

/**
 * Converts application-supplied `Accept-Signature` parameters into Structured Field parameters
 * using the request-side value types.
 */
function normalizeRequestedParameters(parameters: SignatureParameters | undefined): SfParameters {
  const output: SfParameters = []
  const seen = new Set<string>()
  for (const [name, input] of orderedParameterEntries(parameters)) {
    assertSfKey(name, 'Requested signature parameter name')
    if (seen.has(name)) {
      fail(`Duplicate requested signature parameter "${name}"`)
    }
    seen.add(name)
    const value = sfBareItemFromSignatureParameter(name, input)
    if (value !== undefined) {
      output.push([name, value])
    }
  }
  validateKnownSignatureParameters(output, true)
  return output
}

/**
 * Parses an `Accept-Signature` field value into validated signature requests, rejecting a repeated
 * label.
 */
function parseAcceptSignatureInternal(value: string): ParsedSignatureInput[] {
  const dictionary = parseStructuredField(value, 'dictionary', true) as SfDictionary
  return dictionary.map(([label, member]) => {
    if (member.kind !== 'inner-list') {
      fail(`Accept-Signature member "${label}" must be an Inner List`)
    }
    validateKnownSignatureParameters(member.parameters, true)
    const components = member.value.map(componentFromSfItem)
    for (const identifier of components) {
      validateComponentParameters(identifier)
    }
    assertUniqueComponents(components)
    return { label, components, parameters: member.parameters }
  })
}

/**
 * Parses an `Accept-Signature` field value into its labeled signature requests.
 *
 * Validates component identifiers and the value types of requested signature metadata parameters,
 * where `created` and `expires` carry no value because the signer chooses the timestamps. It does
 * not check the requested components against a message; use {@link getSignatureRequests} when the
 * message is available.
 *
 * @example
 *
 * A requested `created` carries no value, because the signer chooses the timestamp. A requested
 * `keyid` carries the value the signer is being asked to use.
 *
 * ```ts
 * const [request] = FetchSig.parseAcceptSignature(
 *   'response=("@status" "content-type" "@method";req);created;keyid="server-key"',
 * )
 *
 * // response
 * console.log(request!.label)
 *
 * // [ '@status', 'content-type', '@method' ]
 * console.log(request!.components.map(({ name }) => name))
 *
 * // [ [ 'created', true ], [ 'keyid', 'server-key' ] ]
 * console.log(request!.parameters)
 * ```
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
    parameters: signatureParametersFromSf(parameters),
  }))
}

/**
 * Parses every signature request carried by a Fetch message and checks that each requested
 * component applies to the message that would be signed.
 *
 * The target message is the other direction: `Accept-Signature` on a request asks for a signature
 * on the response, and on a response it asks for a signature on the client's next request. Returns
 * an empty array when the message carries no `Accept-Signature` field.
 *
 * @example
 *
 * A server decides which request it is willing to fulfill. The parsed request is untrusted input,
 * so check the label and the coverage against local policy before signing anything.
 *
 * ```ts
 * declare const incomingRequest: Request
 * declare const response: Response
 * declare const signer: FetchSig.SignerFactory
 *
 * const [signatureRequest] = FetchSig.getSignatureRequests(incomingRequest)
 * if (signatureRequest === undefined || signatureRequest.label !== 'response') {
 *   throw new Error('No supported signature request')
 * }
 *
 * const signed = await FetchSig.signRequested(response, signatureRequest, {
 *   signer,
 *   request: incomingRequest,
 *   parameters: [['keyid', 'server-key']],
 * })
 * ```
 *
 * @group Signature Negotiation
 */
export function getSignatureRequests(message: Request | Response): ReadonlyArray<SignatureRequest> {
  assertMessage(message)
  const value = getDictionaryField(message.headers, 'accept-signature')
  if (value === null) {
    return []
  }
  const requests = parseAcceptSignature(value)
  const targetIsRequest = !isRequest(message)
  for (const request of requests) {
    for (const identifier of request.components) {
      validateComponentForTarget(identifier, targetIsRequest)
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
 * @example
 *
 * `created: true` asks for a timestamp without dictating it. A parameter given a value, such as
 * `keyid`, is a value the signer must reproduce exactly.
 *
 * ```ts
 * const value = FetchSig.createAcceptSignature([
 *   {
 *     label: 'response',
 *     components: [
 *       '@status',
 *       'content-type',
 *       FetchSig.component('@method', [['req', true]]),
 *       FetchSig.component('@path', [['req', true]]),
 *     ],
 *     parameters: [
 *       ['created', true],
 *       ['keyid', 'server-key'],
 *     ],
 *   },
 * ])
 *
 * // response=("@status" "content-type" "@method";req "@path";req);created;keyid="server-key"
 * console.log(value)
 * ```
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
    for (const identifier of components) {
      validateComponentParameters(identifier)
    }
    assertUniqueComponents(components)
    const parameters = normalizeRequestedParameters(request.parameters)
    dictionary.push([request.label, signatureParametersInnerList(components, parameters)])
  }
  return serializeDictionary(dictionary)
}

/**
 * Copies `Headers` and appends `Accept-Signature` requests, re-parsing the combined value and re-
 * checking that every requested component applies to the message that would be signed.
 */
function appendAcceptSignatureHeaders(
  headers: Headers,
  value: string,
  targetIsRequest: boolean,
): Headers {
  const output = new Headers(headers)
  const existing = getDictionaryField(output, 'accept-signature')
  const combined = existing === null ? value : `${existing}, ${value}`
  const requests = parseAcceptSignatureInternal(combined)
  for (const request of requests) {
    for (const identifier of request.components) {
      validateComponentForTarget(identifier, targetIsRequest)
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
 * @example
 *
 * Ask the server to sign its response. Because the field is on a request, the requested components
 * are checked against a response, which is why the request components carry `req`.
 *
 * ```ts
 * const request = FetchSig.appendAcceptSignature(
 *   new Request('https://api.example/orders/123'),
 *   [
 *     {
 *       label: 'response',
 *       components: [
 *         '@status',
 *         'content-type',
 *         FetchSig.component('@method', [['req', true]]),
 *         FetchSig.component('@path', [['req', true]]),
 *       ],
 *       parameters: [
 *         ['created', true],
 *         ['keyid', 'server-key'],
 *       ],
 *     },
 *   ],
 * )
 *
 * // response=("@status" "content-type" "@method";req "@path";req);created;keyid="server-key"
 * console.log(request.headers.get('accept-signature'))
 * ```
 *
 * @example
 *
 * On a response the field asks the client to sign its next request, so the requested components are
 * checked against a request and `req` is not allowed.
 *
 * ```ts
 * const response = FetchSig.appendAcceptSignature(new Response('', { status: 401 }), [
 *   {
 *     label: 'client',
 *     components: ['@method', '@authority', '@path'],
 *     parameters: [['nonce', 'e4c7f2a1']],
 *   },
 * ])
 *
 * // client=("@method" "@authority" "@path");nonce="e4c7f2a1"
 * console.log(response.headers.get('accept-signature'))
 * ```
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
    for (const identifier of normalizeComponents(request.components)) {
      validateComponentForTarget(identifier, targetIsRequest)
    }
  }
  const headers = appendAcceptSignatureHeaders(message.headers, value, targetIsRequest)
  if (isRequest(message)) {
    return new Request(message, { headers })
  }
  assertReconstructableResponse(message, 'Accept-Signature')
  return new Response(reconstructableResponseBody(message), {
    headers,
    status: message.status,
    statusText: message.statusText,
  })
}

/**
 * Converts the public parameters of a parsed signature request back into Structured Field
 * parameters so that they can be compared with, and merged into, the parameters the signer
 * supplies.
 */
function signatureParametersToSf(
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
    const item = sfBareItemFromSignatureParameter(name, value)
    if (item === undefined) {
      fail(`Signature parameter "${name}" is undefined`)
    }
    output.push([name, item])
  }
  validateKnownSignatureParameters(output, true)
  return output
}

/**
 * Merges the parameters an `Accept-Signature` member requested with the values the signer supplied.
 *
 * RFC 9421 requires the fulfilling signature to process every requested parameter. A requested
 * `created` defaults to the signing clock, a requested `expires` or `keyid` must be chosen
 * explicitly by the signer, an extension parameter the implementation does not define must be
 * supplied explicitly, and a supplied value must not conflict with the requested one. Parameters
 * the signer adds on its own are appended afterwards, which the RFC permits.
 */
function mergeRequestedParameters(
  request: SignatureRequest,
  parameters: SignatureParameters | undefined,
  now: number,
): { readonly parameters: SfParameters; readonly omitDefaultCreated: boolean } {
  const requested = signatureParametersToSf(request.parameters)
  const suppliedEntries = orderedParameterEntries(parameters)
  const supplied = normalizeSignatureParameterEntries(suppliedEntries, undefined)
  const output: SfParameters = []
  const omitDefaultCreated = suppliedEntries.some(
    ([name, value]) => name === 'created' && value === false,
  )

  for (const [name, requestedValue] of requested) {
    const suppliedValue = findSfParameterValue(supplied, name)
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
    omitDefaultCreated: omitDefaultCreated && findSfParameterValue(output, 'created') === undefined,
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
  for (const identifier of components) {
    validateComponentForMessage(identifier, message)
  }
  const normalizedRequest: SignatureRequest = {
    label: request.label,
    components,
    parameters: request.parameters,
  }
  const now = unixTimestamp(options.now)
  const merged = mergeRequestedParameters(normalizedRequest, options.parameters, now)
  const parameters: SignatureParameter[] = signatureParametersFromSf(merged.parameters)
  if (merged.omitDefaultCreated) {
    parameters.push(['created', false])
  }
  return { ...options, label: normalizedRequest.label, components, parameters, now }
}

/**
 * Fulfills one parsed `Accept-Signature` request without modifying the target Fetch message.
 *
 * Signs exactly the requested label and covered components, and processes every requested signature
 * metadata parameter: a requested `created` defaults to the signing clock, a requested `expires` or
 * `keyid` must be supplied here, and a requested parameter this implementation does not define must
 * be supplied here with the same value. Additional parameters may be supplied and are appended.
 *
 * @example
 *
 * The label and covered components come from the request; the values that cannot be chosen from the
 * request alone come from the signer. Here `keyid` was requested and so must be selected
 * explicitly, and `expires` is a local policy decision rather than something the peer dictates.
 *
 * ```ts
 * declare const incomingRequest: Request
 * declare const response: Response
 * declare const signer: FetchSig.SignerFactory
 *
 * const [signatureRequest] = FetchSig.getSignatureRequests(incomingRequest)
 * if (signatureRequest === undefined) {
 *   throw new Error('No signature request')
 * }
 *
 * const fields = await FetchSig.createRequestedSignature(response, signatureRequest, {
 *   signer,
 *   request: incomingRequest,
 *   parameters: [
 *     ['keyid', 'server-key'],
 *     ['expires', 1_735_689_660],
 *   ],
 *   now: 1_735_689_600,
 * })
 *
 * // response=("@status" "content-type" "@method";req "@path";req)
 * //   ;created=1735689600;keyid="server-key";expires=1735689660
 * console.log(fields.signatureInput)
 * ```
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
 * @example
 *
 * A server-side handler that answers `Accept-Signature` on the request it just received.
 *
 * ```ts
 * declare const signer: FetchSig.SignerFactory
 *
 * async function handle(request: Request): Promise<Response> {
 *   const response = new Response('{"ok":true}', {
 *     status: 200,
 *     headers: { 'content-type': 'application/json' },
 *   })
 *
 *   const [signatureRequest] = FetchSig.getSignatureRequests(request)
 *   if (signatureRequest === undefined) {
 *     return response
 *   }
 *
 *   return FetchSig.signRequested(response, signatureRequest, {
 *     signer,
 *     request,
 *     parameters: [['keyid', 'server-key']],
 *   })
 * }
 * ```
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

/**
 * Copies the `structuredFields` mapping so that a Fetch wrapper cannot be reconfigured after it was
 * created.
 */
function snapshotStructuredFields(
  structuredFields: SignatureContext['structuredFields'],
): SignatureContext['structuredFields'] {
  if (structuredFields === undefined) {
    return undefined
  }
  return Object.fromEntries(Object.entries(structuredFields))
}

/**
 * Copies one signature metadata parameter input, including `Date` and `Uint8Array` values, so that
 * a Fetch wrapper cannot be reconfigured after it was created.
 */
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

/**
 * Copies signature metadata parameters into ordered entries so that a Fetch wrapper cannot be
 * reconfigured after it was created.
 */
function snapshotSignatureParameters(
  parameters: SignatureParameters | undefined,
): SignatureParameters | undefined {
  if (parameters === undefined) {
    return undefined
  }
  return orderedParameterEntries(parameters).map(([name, value]) => [
    name,
    snapshotSignatureParameterInput(value),
  ])
}

/** Copies and validates the signing configuration of a Fetch wrapper at construction time. */
function snapshotFetchWrapperSignOptions(
  options: Omit<SignOptions, 'request'>,
): Omit<SignOptions, 'request'> {
  if (options === null || typeof options !== 'object') {
    fail('"options.sign" must be an object')
  }
  assertSignatureContext(options)
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

/** Copies and validates the verification configuration of a Fetch wrapper at construction time. */
function snapshotFetchWrapperVerifyOptions(
  options: Omit<VerifyOptions, 'request'>,
): Omit<VerifyOptions, 'request'> {
  if (options === null || typeof options !== 'object') {
    fail('"options.verify" must be an object')
  }
  assertSignatureContext(options)
  return {
    verifier: options.verifier,
    policy: snapshotVerificationPolicy(options.policy),
    label: options.label,
    structuredFields: snapshotStructuredFields(options.structuredFields),
    fieldValues: options.fieldValues,
  }
}

/** Resolves the Fetch implementation a wrapper delegates to, defaulting to the global `fetch`. */
function resolveFetchImplementation(
  options: Readonly<{ fetch?: typeof globalThis.fetch }>,
): typeof globalThis.fetch {
  const implementation = options.fetch ?? globalThis.fetch
  if (typeof implementation !== 'function') {
    fail('"options.fetch" must be a Fetch implementation')
  }
  return implementation
}

/**
 * Builds the `Request` a Fetch wrapper will operate on, downgrading automatic redirects to manual
 * ones.
 *
 * Fetch cannot re-sign each request in a redirect chain and does not expose the request that
 * produced a response after following a redirect, so following redirects automatically would either
 * forward stale signature fields to another origin or verify a response against the wrong request.
 * An explicitly configured `redirect` mode is left as the caller set it.
 */
function createFetchRequest(input: RequestInfo | URL, init?: RequestInit): Request {
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
 * @example
 *
 * Drop-in replacement for `fetch` that signs on the way out. Use this one, rather than
 * {@link createSignedFetch}, when a bundler should be able to drop the verification code.
 *
 * ```ts
 * declare const privateKey: CryptoKey
 *
 * const signingFetch = FetchSig.createSigningFetch({
 *   sign: {
 *     signer: FetchSig.ed25519Signer(privateKey),
 *     components: ['@method', '@authority', '@path'],
 *     parameters: [
 *       ['alg', 'ed25519'],
 *       ['keyid', 'client-key'],
 *     ],
 *   },
 * })
 *
 * // Takes the same arguments as fetch.
 * const response = await signingFetch('https://api.example/orders', {
 *   method: 'POST',
 *   headers: { 'content-type': 'application/json' },
 *   body: '{}',
 * })
 * ```
 *
 * @example
 *
 * Components and parameters are copied when the wrapper is created and cannot be changed
 * afterwards. Key material can still rotate, because the signer factory runs once per signature.
 *
 * ```ts
 * declare const keys: { current: CryptoKey }
 * declare const upstreamFetch: typeof fetch
 *
 * const signingFetch = FetchSig.createSigningFetch({
 *   sign: {
 *     signer: () => FetchSig.ed25519Signer(keys.current)(),
 *     components: ['@method', '@authority', '@path'],
 *     parameters: [['alg', 'ed25519']],
 *   },
 *   // Delegate to something other than the global fetch, such as an instrumented client.
 *   fetch: upstreamFetch,
 * })
 * ```
 *
 * @group Fetch Integration
 */
export function createSigningFetch(options: SigningFetchOptions): typeof globalThis.fetch {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = resolveFetchImplementation(options)
  const signOptions = snapshotFetchWrapperSignOptions(options.sign)

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const signedRequest = await sign(createFetchRequest(input, init), signOptions)
    return implementation(signedRequest)
  }
}

/**
 * Creates a Fetch-compatible function that verifies every response against its exact request.
 *
 * Automatic redirects are changed to manual redirects because Fetch does not expose the request
 * that produced a response after following a redirect.
 *
 * @example
 *
 * Verify every response without signing anything on the way out. The wrapper passes the exact
 * request it sent as the related request, which is what makes `;req` components verifiable.
 *
 * ```ts
 * declare const verifier: FetchSig.VerifierFactory
 *
 * const verifyingFetch = FetchSig.createVerifyingFetch({
 *   verify: {
 *     verifier,
 *     policy: {
 *       requiredComponents: [
 *         '@status',
 *         FetchSig.component('@method', [['req', true]]),
 *         FetchSig.component('@path', [['req', true]]),
 *       ],
 *       requiredParameters: ['created', 'keyid'],
 *       algorithms: ['ed25519'],
 *       maxAge: 60,
 *     },
 *   },
 * })
 *
 * // Rejects rather than resolving when the response is unsigned or the signature does not verify.
 * const response = await verifyingFetch('https://api.example/orders')
 *
 * // The body is untouched by verification, and its integrity is not implied by it: check
 * // Content-Digest separately if the response covers one.
 * const orders = await response.json()
 * ```
 *
 * @group Fetch Integration
 */
export function createVerifyingFetch(options: VerifyingFetchOptions): typeof globalThis.fetch {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = resolveFetchImplementation(options)
  const verifyOptions = snapshotFetchWrapperVerifyOptions(options.verify)

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = createFetchRequest(input, init)
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
 * @example
 *
 * Both directions in one wrapper. Prefer this over nesting {@link createSigningFetch} inside
 * {@link createVerifyingFetch}, which would verify against a different request object and can
 * reconstruct a streaming request an extra time.
 *
 * ```ts
 * declare const privateKey: CryptoKey
 * declare const verifier: FetchSig.VerifierFactory
 *
 * const signedFetch = FetchSig.createSignedFetch({
 *   sign: {
 *     signer: FetchSig.ed25519Signer(privateKey),
 *     components: ['@method', '@authority', '@path'],
 *     parameters: [['keyid', 'client-key']],
 *   },
 *   verify: {
 *     verifier,
 *     policy: {
 *       // The response is bound to the request this wrapper signed.
 *       requiredComponents: [
 *         '@status',
 *         FetchSig.component('@method', [['req', true]]),
 *         FetchSig.component('@path', [['req', true]]),
 *       ],
 *       requiredParameters: ['created', 'keyid'],
 *       algorithms: ['ed25519'],
 *       maxAge: 60,
 *     },
 *   },
 * })
 *
 * const response = await signedFetch('https://api.example/orders')
 * ```
 *
 * @group Fetch Integration
 */
export function createSignedFetch(options: SignedFetchOptions): typeof globalThis.fetch {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = resolveFetchImplementation(options)
  const signOptions = snapshotFetchWrapperSignOptions(options.sign)
  const verifyOptions =
    options.verify === undefined ? undefined : snapshotFetchWrapperVerifyOptions(options.verify)

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const signedRequest = await sign(createFetchRequest(input, init), signOptions)
    const response = await implementation(signedRequest)
    if (verifyOptions !== undefined) {
      await verify(response, { ...verifyOptions, request: signedRequest })
    }
    return response
  }
}
