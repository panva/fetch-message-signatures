/**
 * HTTP Message Signatures for the Fetch API.
 *
 * Implements the sender, recipient, and `Accept-Signature` operations from [RFC
 * 9421](https://www.rfc-editor.org/info/rfc9421/) on top of `Request`, `Response`, `Headers`, and
 * `fetch`. The module constructs and parses the required Structured Fields, includes Web
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
/**
 * A Web Cryptography key, resolved from the host runtime.
 *
 * The host's own `CryptoKey` type is aliased whenever one is declared, so keys flow freely to and
 * from Web Cryptography's `SubtleCrypto` APIs and this package never introduces a competing nominal
 * type. It is resolved through `globalThis` rather than named directly because not every supported
 * configuration declares a `CryptoKey` **type**: `@types/node` declares only the constructor value,
 * so a Node.js consumer compiling with `"lib": ["esnext"]` and no DOM lib would otherwise get a
 * type error from these declarations. Such a consumer gets {@link CryptoKeyStructuralFallback}
 * instead, which is still checked.
 */
export type CryptoKey = typeof globalThis extends {
    crypto: {
        subtle: {
            generateKey(...args: any[]): Promise<infer R>;
        };
    };
} ? Extract<R, {
    type: string;
}> : CryptoKeyStructuralFallback;
/**
 * Used as {@link CryptoKey} when the host runtime's `crypto` global is not exposed on `typeof
 * globalThis`, including when it is absent from ambient types or declared with `const` or `let`. It
 * stays structurally compatible with host `CryptoKey` declarations.
 */
export interface CryptoKeyStructuralFallback {
    readonly algorithm: {
        name: string;
    };
    readonly extractable: boolean;
    readonly type: string;
    readonly usages: string[];
}
/**
 * A Web Cryptography key pair, resolved from the host runtime the same way {@link CryptoKey} is.
 *
 * Declared structurally because no supported runtime exposes a global `CryptoKeyPair` **type** on
 * every configuration: the DOM lib declares one, `@types/node` does not declare one at all.
 */
export interface CryptoKeyPair {
    readonly privateKey: CryptoKey;
    readonly publicKey: CryptoKey;
}
/** The top-level type of an HTTP Structured Field. */
export type StructuredFieldType = 'dictionary' | 'list' | 'item';
/** A Structured Field Token. Plain JavaScript strings represent Structured Field Strings. */
export interface StructuredFieldToken {
    readonly type: 'token';
    readonly value: string;
}
/** A Structured Field Decimal, including integral decimal values such as `1.0`. */
export interface StructuredFieldDecimal {
    readonly type: 'decimal';
    readonly value: number;
}
/** A Structured Field Date represented as integer UNIX seconds. */
export interface StructuredFieldDate {
    readonly type: 'date';
    readonly value: number;
}
/** A Structured Field Display String. */
export interface StructuredFieldDisplayString {
    readonly type: 'display-string';
    readonly value: string;
}
/** A value that can be used as an HTTP signature metadata parameter. */
export type SignatureParameterValue = string | number | boolean | Uint8Array | StructuredFieldToken | StructuredFieldDecimal | StructuredFieldDate | StructuredFieldDisplayString;
/**
 * A signature metadata parameter input.
 *
 * `Date` values are converted to integer UNIX timestamps. `false` is useful only for the `created`
 * parameter, where it explicitly disables the default creation timestamp.
 */
export type SignatureParameterInput = SignatureParameterValue | Date | undefined;
/** An ordered signature metadata parameter. */
export type SignatureParameter = readonly [name: string, value: SignatureParameterInput];
/**
 * Ordered parameters are recommended because their order is covered by the signature. Object
 * property insertion order is preserved when a record is supplied.
 */
export type SignatureParameters = ReadonlyArray<SignatureParameter> | Readonly<Record<string, SignatureParameterInput>>;
/** A value supported by an HTTP message component parameter. */
export type ComponentParameterValue = string | boolean;
/** An ordered HTTP message component parameter. */
export type ComponentParameter = readonly [name: string, value: ComponentParameterValue];
/**
 * Ordered parameters are recommended because their serialization order is covered by the signature.
 * Object property insertion order is preserved when a record is supplied.
 */
export type ComponentParameters = ReadonlyArray<ComponentParameter> | Readonly<Record<string, ComponentParameterValue>>;
/** A parameterized HTTP message component identifier. */
export interface ParameterizedComponent {
    readonly name: string;
    readonly parameters?: ComponentParameters;
}
/**
 * An HTTP message component identifier.
 *
 * A string is shorthand for an identifier without parameters.
 */
export type ComponentIdentifier = string | ParameterizedComponent;
/** A normalized HTTP message component identifier with ordered parameters. */
export interface MessageComponent {
    readonly name: string;
    readonly parameters: ReadonlyArray<ComponentParameter>;
}
/** Context supplied while deriving HTTP message components. */
export interface FieldValueContext {
    /** Whether the value is requested from the trailer section. */
    readonly trailers: boolean;
    /** Whether the value is requested from the related request of a response. */
    readonly relatedRequest: boolean;
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
export type FieldValues = (message: Request | Response, name: string, context: FieldValueContext) => ReadonlyArray<string> | undefined;
/** Options shared by signature-base creation, signing, and verification. */
export interface SignatureContext {
    /** The exact request that triggered a response. Required when a response signature uses `;req`. */
    readonly request?: Request;
    /** Structured Field top-level types, indexed by lowercase HTTP field name. */
    readonly structuredFields?: Readonly<Record<string, StructuredFieldType>>;
    /** Adapter for raw field occurrences and trailers. */
    readonly fieldValues?: FieldValues;
}
/** Target-message context supplied to a verifier factory. */
export interface VerificationContext {
    /** The target message carrying the signature. */
    readonly message: Request | Response;
    /** The exact related request, when response/request binding is in use. */
    readonly request?: Request;
}
/** Authenticated context supplied to additional application policy. */
export interface VerifiedSignatureContext extends VerificationContext {
    /** The algorithm selected by the verifier factory. */
    readonly algorithm: string;
}
/** A parsed HTTP message signature. */
export interface MessageSignature {
    readonly label: string;
    readonly components: ReadonlyArray<MessageComponent>;
    readonly parameters: ReadonlyArray<readonly [name: string, value: SignatureParameterValue]>;
    readonly signature: Uint8Array<ArrayBuffer>;
}
/** The result of creating one signature, ready to be added to the corresponding HTTP fields. */
export interface SignatureFields extends MessageSignature {
    /** A one-member `Signature-Input` Structured Field Dictionary. */
    readonly signatureInput: string;
    /** A one-member `Signature` Structured Field Dictionary. */
    readonly signatureField: string;
}
/**
 * A Promise-based signer implementation returned by a synchronous factory.
 *
 * Synchronous cryptographic libraries can be adapted by declaring `sign` as an `async` method.
 */
export interface Signer {
    readonly type: 'signer';
    /** The algorithm selected by configuration or key metadata. */
    readonly alg: string;
    sign(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array>;
}
/** A synchronous factory returning a signer implementation. */
export type SignerFactory = () => Readonly<Signer>;
/** A Promise-based verifier implementation returned by a synchronous factory. */
export interface Verifier {
    readonly type: 'verifier';
    /** The algorithm selected by configuration or key metadata. */
    readonly alg: string;
    verify(data: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>): Promise<boolean>;
}
/**
 * A synchronous factory that selects trusted verification key material and an algorithm.
 *
 * The factory is the application's key-resolution and trust-policy boundary. It MUST reject unknown
 * or inappropriate key identifiers and algorithms instead of returning a verifier for them.
 */
export type VerifierFactory = (signature: Readonly<MessageSignature>, context: Readonly<VerificationContext>) => Readonly<Verifier>;
/** Sender options. */
export interface SignOptions extends SignatureContext {
    readonly signer: SignerFactory;
    readonly components: ReadonlyArray<ComponentIdentifier>;
    readonly parameters?: SignatureParameters;
    readonly label?: string;
    /** Injectable clock used for the default `created` parameter. */
    readonly now?: number | Date;
}
/** Explicit application policy required before a cryptographically valid signature is accepted. */
export interface VerificationPolicy {
    /** Every listed component identifier must be covered by the signature. */
    readonly requiredComponents: ReadonlyArray<ComponentIdentifier>;
    /** Every listed metadata parameter must be present. */
    readonly requiredParameters: ReadonlyArray<string>;
    /** Non-empty allowlist matched against the algorithm selected by the verifier factory. */
    readonly algorithms: ReadonlyArray<string>;
    /** Maximum signature age in seconds. Requires a `created` parameter. */
    readonly maxAge?: number;
    /** Permitted timestamp skew in seconds. Defaults to zero. */
    readonly clockSkew?: number;
    /** Injectable verification clock. */
    readonly now?: number | Date;
    /**
     * Additional application policy, such as nonce uniqueness, expected tags, field semantics, and
     * key/message authorization.
     */
    validate?(signature: Readonly<MessageSignature>, context: Readonly<VerifiedSignatureContext>): void | Promise<void>;
}
/** Recipient options. */
export interface VerifyOptions extends SignatureContext {
    readonly verifier: VerifierFactory;
    readonly policy: VerificationPolicy;
    /**
     * The signature label to verify. Required when the message contains more than one signature.
     * Labels are not signed and MUST NOT be assigned application semantics.
     */
    readonly label?: string;
}
/** A successfully verified signature. */
export interface VerifiedSignature extends MessageSignature {
    readonly algorithm: string;
}
/** Options for direct signature-base creation. */
export interface SignatureBaseOptions extends SignatureContext {
    readonly components: ReadonlyArray<ComponentIdentifier>;
    readonly parameters?: SignatureParameters;
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
export declare function generateEcdsaP256Sha256KeyPair(extractable?: boolean): Promise<CryptoKeyPair>;
/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p256-sha256`.
 *
 * Signatures use the RFC-required 64-byte raw `r || s` representation.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-256 private key with `sign` usage.
 * @group Cryptographic Algorithms
 */
export declare function ecdsaP256Sha256Signer(key: CryptoKey): SignerFactory;
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
export declare function ecdsaP256Sha256Verifier(key: CryptoKey): VerifierFactory;
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
export declare function generateEcdsaP384Sha384KeyPair(extractable?: boolean): Promise<CryptoKeyPair>;
/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ecdsa-p384-sha384`.
 *
 * Signatures use the RFC-required 96-byte raw `r || s` representation.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-384 private key with `sign` usage.
 * @group Cryptographic Algorithms
 */
export declare function ecdsaP384Sha384Signer(key: CryptoKey): SignerFactory;
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
export declare function ecdsaP384Sha384Verifier(key: CryptoKey): VerifierFactory;
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
export declare function generateEd25519KeyPair(extractable?: boolean): Promise<CryptoKeyPair>;
/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `ed25519`.
 *
 * The message is signed directly with Ed25519, without an external pre-hash.
 *
 * @param key - Web Cryptography's `CryptoKey` for an Ed25519 private key with `sign` usage.
 * @group Cryptographic Algorithms
 */
export declare function ed25519Signer(key: CryptoKey): SignerFactory;
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
export declare function ed25519Verifier(key: CryptoKey): VerifierFactory;
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
export declare function token(value: string): StructuredFieldToken;
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
export declare function decimal(value: number): StructuredFieldDecimal;
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
export declare function date(value: number | Date): StructuredFieldDate;
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
export declare function displayString(value: string): StructuredFieldDisplayString;
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
export declare function component(name: string, parameters?: ComponentParameters): ParameterizedComponent;
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
export declare function createSignatureBase(message: Request | Response, options: SignatureBaseOptions): string;
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
export declare function parseSignatureInput(value: string): ReadonlyArray<Omit<MessageSignature, 'signature'>>;
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
export declare function parseSignature(value: string): ReadonlyArray<Readonly<{
    label: string;
    signature: Uint8Array<ArrayBuffer>;
}>>;
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
export declare function getSignatures(message: Request | Response): ReadonlyArray<MessageSignature>;
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
export declare function createSignature(message: Request | Response, options: SignOptions): Promise<SignatureFields>;
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
export declare function appendSignature(headers: Headers, fields: SignatureFields): Headers;
/**
 * Adds one signature to a `Request` and returns a new `Request`.
 *
 * The returned message passes the source body to a new Fetch message without explicitly cloning or
 * buffering it. The source body's observable state is runtime-dependent. Consume the returned
 * request and do not rely on the source request afterward. Use {@link createSignature} and construct
 * the final message explicitly when both bodies must remain readable.
 */
export declare function appendSignature(headers: Request, fields: SignatureFields): Request;
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
export declare function appendSignature(headers: Response, fields: SignatureFields): Response;
export declare function appendSignature(headers: Headers | Request | Response, fields: SignatureFields): Headers | Request | Response;
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
export declare function sign(message: Request, options: SignOptions): Promise<Request>;
export declare function sign(message: Response, options: SignOptions): Promise<Response>;
export declare function sign(message: Request | Response, options: SignOptions): Promise<Request | Response>;
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
export declare function verify(message: Request | Response, options: VerifyOptions): Promise<VerifiedSignature>;
/** A requested HTTP message signature parsed from `Accept-Signature`. */
export interface SignatureRequest {
    readonly label: string;
    readonly components: ReadonlyArray<MessageComponent>;
    readonly parameters: ReadonlyArray<readonly [name: string, value: SignatureParameterValue]>;
}
/** Input used to create an `Accept-Signature` member. */
export interface SignatureRequestInput {
    readonly label: string;
    readonly components: ReadonlyArray<ComponentIdentifier>;
    readonly parameters?: SignatureParameters;
}
/** Options for fulfilling an `Accept-Signature` member. */
export interface RequestedSignOptions extends SignatureContext {
    readonly signer: SignerFactory;
    /**
     * Values that satisfy requested parameters and any additional parameters selected by the signer.
     * An `expires` request requires an explicit `expires` value here.
     */
    readonly parameters?: SignatureParameters;
    readonly now?: number | Date;
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
export declare function parseAcceptSignature(value: string): ReadonlyArray<SignatureRequest>;
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
export declare function getSignatureRequests(message: Request | Response): ReadonlyArray<SignatureRequest>;
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
export declare function createAcceptSignature(requests: ReadonlyArray<SignatureRequestInput>): string;
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
export declare function appendAcceptSignature(message: Request, requests: ReadonlyArray<SignatureRequestInput>): Request;
export declare function appendAcceptSignature(message: Response, requests: ReadonlyArray<SignatureRequestInput>): Response;
export declare function appendAcceptSignature(message: Request | Response, requests: ReadonlyArray<SignatureRequestInput>): Request | Response;
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
export declare function createRequestedSignature(message: Request | Response, request: SignatureRequest, options: RequestedSignOptions): Promise<SignatureFields>;
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
export declare function signRequested(message: Request, request: SignatureRequest, options: RequestedSignOptions): Promise<Request>;
export declare function signRequested(message: Response, request: SignatureRequest, options: RequestedSignOptions): Promise<Response>;
export declare function signRequested(message: Request | Response, request: SignatureRequest, options: RequestedSignOptions): Promise<Request | Response>;
/** Options for a Fetch-compatible function that signs requests. */
export interface SigningFetchOptions {
    readonly sign: Omit<SignOptions, 'request'>;
    readonly fetch?: typeof globalThis.fetch;
}
/** Options for a Fetch-compatible function that verifies responses against their requests. */
export interface VerifyingFetchOptions {
    readonly verify: Omit<VerifyOptions, 'request'>;
    readonly fetch?: typeof globalThis.fetch;
}
/** Options for a Fetch-compatible function that signs requests and optionally verifies responses. */
export interface SignedFetchOptions {
    readonly sign: Omit<SignOptions, 'request'>;
    readonly verify?: Omit<VerifyOptions, 'request'>;
    readonly fetch?: typeof globalThis.fetch;
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
export declare function createSigningFetch(options: SigningFetchOptions): typeof globalThis.fetch;
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
export declare function createVerifyingFetch(options: VerifyingFetchOptions): typeof globalThis.fetch;
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
export declare function createSignedFetch(options: SignedFetchOptions): typeof globalThis.fetch;
//# sourceMappingURL=index.d.ts.map