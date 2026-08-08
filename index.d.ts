/**
 * HTTP Message Signatures for the Fetch API.
 *
 * Implements the sender, recipient, and `Accept-Signature` operations from [RFC
 * 9421](https://www.rfc-editor.org/info/rfc9421/) on top of `Request`, `Response`, `Headers`, and
 * `fetch`. The module constructs and parses the required Structured Fields, includes Web
 * Cryptography implementations of the ECDSA, Ed25519, and RSA signature algorithms, and supports
 * custom cryptographic providers.
 *
 * @module fetch-message-signatures














































































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
 * by `context.trailers`. RFC 9421 forbids combining same-name header and trailer values for
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
 * A signer implementation returned by a {@link SignerFactory}.
 *
 * `sign()` may return the signature bytes directly or a Promise of them, so a synchronous
 * cryptographic library needs no wrapper. Web Cryptography is asynchronous, so every signer this
 * package builds returns a Promise.
 */
export interface Signer {
    readonly type: 'signer';
    /** The algorithm selected by configuration or key metadata. */
    readonly alg: string;
    sign(data: Uint8Array<ArrayBuffer>): Uint8Array | Promise<Uint8Array>;
}
/** A synchronous factory returning a signer implementation. */
export type SignerFactory = () => Readonly<Signer>;
/**
 * A verifier implementation returned by a {@link VerifierFactory}.
 *
 * `verify()` may return the result directly or a Promise of it, so a synchronous cryptographic
 * library needs no wrapper. Web Cryptography is asynchronous, so every verifier this package builds
 * returns a Promise.
 */
export interface Verifier {
    readonly type: 'verifier';
    /** The algorithm selected by configuration or key metadata. */
    readonly alg: string;
    verify(data: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>): boolean | Promise<boolean>;
}
/**
 * A factory that selects trusted verification key material and an algorithm.
 *
 * The factory is the application's key-resolution and trust-policy boundary. It MUST reject unknown
 * or inappropriate key identifiers and algorithms instead of returning a verifier for them.
 *
 * It receives the parsed signature before any cryptography runs, so selection can depend on
 * `keyid`, `alg`, the covered component list, or the message itself. Use
 * {@link getSignatureParameter} to read a metadata parameter.
 *
 * It may return a Promise, so a key that has to be fetched or refreshed on rotation can be awaited
 * here. A `keyid` is unauthenticated at this point, so resolve it through trusted configuration and
 * never treat it as a location to fetch. The signature base is rebuilt after the factory settles,
 * so a message that changes while a key is being fetched is rejected rather than verified.
 */
export type VerifierFactory = (signature: Readonly<MessageSignature>, context: Readonly<VerificationContext>) => Readonly<Verifier> | Promise<Readonly<Verifier>>;
/**
 * A {@link VerifierFactory} that resolves its verifier without suspending.
 *
 * Every factory this package returns is synchronous, and says so, so that composing one keeps
 * working without an `await`. It remains assignable to {@link VerifierFactory}.
 */
export type SynchronousVerifierFactory = (signature: Readonly<MessageSignature>, context: Readonly<VerificationContext>) => Readonly<Verifier>;
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
 * not perform `keyid` lookup or authorization. Select it from trusted application configuration
 * when more than one verification key can be used.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-256 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export declare function ecdsaP256Sha256Verifier(key: CryptoKey): SynchronousVerifierFactory;
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
 * not perform `keyid` lookup or authorization. Select it from trusted application configuration
 * when more than one verification key can be used.
 *
 * @param key - Web Cryptography's `CryptoKey` for an ECDSA P-384 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export declare function ecdsaP384Sha384Verifier(key: CryptoKey): SynchronousVerifierFactory;
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
 * factory does not perform `keyid` lookup or authorization. Select it from trusted application
 * configuration when more than one verification key can be used.
 *























 * @param key - Web Cryptography's `CryptoKey` for an Ed25519 public key with `verify` usage.
 * @group Cryptographic Algorithms
 */
export declare function ed25519Verifier(key: CryptoKey): SynchronousVerifierFactory;
/**
 * Generates an RSA key pair for the RFC 9421 `rsa-pss-sha512` algorithm.
 *
 * The generated public key is represented by Web Cryptography's `CryptoKey` and is always
 * extractable. RSA keys usually come from existing key management rather than from this generator,
 * and {@link rsaPssSha512Signer} and {@link rsaPssSha512Verifier} accept an RSA-PSS key of any
 * modulus length.
 *
 * SHA-512 with a 64-byte salt needs at least a 1040-bit modulus to encode a signature at all, so a
 * shorter key fails when it is used rather than when it is generated.
 *














 * @param extractable - Whether the private key can be exported. Defaults to `false`.
 * @param modulusLength - Modulus length in bits. Defaults to `2048`.
 *
 * @returns A randomly generated signing and verification key pair.
 * @group Cryptographic Algorithms
 */
export declare function generateRsaPssSha512KeyPair(extractable?: boolean, modulusLength?: number): Promise<CryptoKeyPair>;
/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `rsa-pss-sha512`.
 *
 * Signatures use MGF1 with SHA-512 and the RFC-required 64-byte salt. The salt length is not
 * carried by the key, so a provider that leaves it at another value produces signatures no
 * conforming recipient accepts.
 *
 * @param key - Web Cryptography's `CryptoKey` for an RSA-PSS private key with SHA-512 and `sign`
 *   usage.
 * @group Cryptographic Algorithms
 */
export declare function rsaPssSha512Signer(key: CryptoKey): SignerFactory;
/**
 * Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `rsa-pss-sha512`.
 *
 * Signatures use MGF1 with SHA-512 and the RFC-required 64-byte salt. This fixed-key factory does
 * not perform `keyid` lookup or authorization. Select it from trusted application configuration
 * when more than one verification key can be used.
 *
 * @param key - Web Cryptography's `CryptoKey` for an RSA-PSS public key with SHA-512 and `verify`
 *   usage.
 * @group Cryptographic Algorithms
 */
export declare function rsaPssSha512Verifier(key: CryptoKey): SynchronousVerifierFactory;
/**
 * Generates an RSA key pair for the RFC 9421 `rsa-v1_5-sha256` algorithm.
 *
 * The generated public key is represented by Web Cryptography's `CryptoKey` and is always
 * extractable. RSA keys usually come from existing key management rather than from this generator,
 * and {@link rsaV1_5Sha256Signer} and {@link rsaV1_5Sha256Verifier} accept an RSASSA-PKCS1-v1_5 key
 * of any modulus length.
 *
 * Prefer `rsa-pss-sha512` or `ed25519` for a new design. This algorithm is provided for peers that
 * require PKCS#1 v1.5, which RFC 9421 describes as the weaker RSA option.
 *
 * @param extractable - Whether the private key can be exported. Defaults to `false`.
 * @param modulusLength - Modulus length in bits. Defaults to `2048`.
 *
 * @returns A randomly generated signing and verification key pair.
 * @group Cryptographic Algorithms
 */
export declare function generateRsaV1_5Sha256KeyPair(extractable?: boolean, modulusLength?: number): Promise<CryptoKeyPair>;
/**
 * Creates a fixed-key signer factory backed by Web Cryptography for RFC 9421 `rsa-v1_5-sha256`.
 *
 * Prefer {@link rsaPssSha512Signer} or {@link ed25519Signer} for a new design. This algorithm is
 * provided for peers that require PKCS#1 v1.5, which RFC 9421 describes as the weaker RSA option.
 *
 * @param key - Web Cryptography's `CryptoKey` for an RSASSA-PKCS1-v1_5 private key with SHA-256 and
 *   `sign` usage.
 * @group Cryptographic Algorithms
 */
export declare function rsaV1_5Sha256Signer(key: CryptoKey): SignerFactory;
/**
 * Creates a fixed-key verifier factory backed by Web Cryptography for RFC 9421 `rsa-v1_5-sha256`.
 *
 * This fixed-key factory does not perform `keyid` lookup or authorization. Select it from trusted
 * application configuration when more than one verification key can be used.
 *
 * Accept this algorithm only for peers that require PKCS#1 v1.5, and keep it out of the policy
 * allowlist everywhere else. RFC 9421 describes it as the weaker RSA option and warns about
 * {@link https://www.rfc-editor.org/info/rfc9421/#section-7.3.6 | algorithm downgrade attacks}.
 *
 * @param key - Web Cryptography's `CryptoKey` for an RSASSA-PKCS1-v1_5 public key with SHA-256 and
 *   `verify` usage.
 * @group Cryptographic Algorithms
 */
export declare function rsaV1_5Sha256Verifier(key: CryptoKey): SynchronousVerifierFactory;
/**
 * Creates a validated Structured Field Token, for use as an extension signature metadata parameter
 * value.
 *
 * Plain JavaScript strings are Structured Field Strings, so this wrapper is how a value is marked
 * as a Token instead.
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




















 * @group Components and Structured Fields
 */
export declare function date(value: number | Date): StructuredFieldDate;
/**
 * Creates a validated Structured Field Display String.
 *
 * The value must contain only Unicode scalar values. Serialization UTF-8 encodes characters that
 * are not safe ASCII and represents their bytes using lowercase percent encoding. Display Strings
 * are intended for text shown to users. Use a regular Structured Field String when Unicode display
 * text is not required.
 *














 * @group Components and Structured Fields
 */
export declare function displayString(value: string): StructuredFieldDisplayString;
/**
 * Creates a component identifier while preserving the supplied parameter order.
 *
 * HTTP field names are normalized to lowercase. Derived component names are case-sensitive.
 *






















































 * @group Components and Structured Fields
 */
export declare function component(name: string, parameters?: ComponentParameters): ParameterizedComponent;
/**
 * Reports whether a list of component identifiers contains one particular identifier.
 *
 * Both sides are normalized first, so a string and the equivalent {@link component} call match, HTTP
 * field names compare case-insensitively, and component parameters are compared as an unordered
 * set. The complete identifier has to match: `"@authority"` and `FetchSig.component('@authority',
 * {req: true})` are different components, and only the exact one is found.
 *
 * The list is not required to be a valid covered component list, so an identifier that arrived on
 * the wire returns `false` rather than throwing. The identifier being looked for comes from the
 * application and is validated.
 *
 * Use this in a {@link VerificationPolicy.validate} callback for a coverage rule
 * {@link VerificationPolicy.requiredComponents} cannot express, such as requiring one of two
 * components or requiring a component only when the message carries a particular field. Comparing
 * names alone would treat `"@authority"` and `"@authority";req` as the same component.
 *













































 * @param components - Identifiers to search, such as {@link MessageSignature.components} or a
 *   covered component list an application is about to sign.
 * @param component - The identifier to look for.
 * @group Components and Structured Fields
 */
export declare function includesComponent(components: ReadonlyArray<ComponentIdentifier>, component: ComponentIdentifier): boolean;
/**
 * Creates the RFC 9421 signature base for a Fetch `Request` or `Response`.
 *
 * Unlike {@link createSignature}, this low-level function does not add a default `created`
 * parameter.
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



















 * @group Recipient
 */
export declare function parseSignatureInput(value: string): ReadonlyArray<Omit<MessageSignature, 'signature'>>;
/**
 * Parses a `Signature` field value into its labeled signature byte sequences.
 *
 * Rejects a repeated label and a member that is not a Byte Sequence. It does not look at any
 * message and does not verify anything.
 *














 * @group Recipient
 */
export declare function parseSignature(value: string): ReadonlyArray<Readonly<{
    label: string;
    signature: Uint8Array<ArrayBuffer>;
}>>;
/**
 * Returns one signature metadata parameter by name, or `undefined` when the signature omits it.
 *
 * The parameters are an ordered list rather than an object, because RFC 9421 covers their order in
 * the signature base. This looks one up without having to reproduce that shape at the call site.
 *
 * A parameter read here is unauthenticated when it comes from a {@link VerifierFactory}, which runs
 * before the signature has been checked. Treat `keyid` as a lookup key into trusted configuration,
 * and `alg` as a claim that {@link VerificationPolicy.algorithms} still has to allow.
 *






















 * @group Recipient
 */
export declare function getSignatureParameter(signature: Readonly<MessageSignature>, name: string): SignatureParameterValue | undefined;
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



























 * @group Recipient
 */
export declare function getSignatures(message: Request | Response): ReadonlyArray<MessageSignature>;
/**
 * Creates one HTTP message signature without modifying or cloning the Fetch message.
 *
 * The returned one-member field values can be attached while constructing a message or passed to
 * {@link appendSignature}. A `created` timestamp is added by default. Pass `created: false` in
 * `parameters` to explicitly omit it.
 *





























































 * @group Sender
 */
export declare function createSignature(message: Request | Response, options: SignOptions): Promise<SignatureFields>;
/**
 * Adds one signature to `Headers` and returns a new `Headers` object.
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
 * not check the requested components against a message. Use {@link getSignatureRequests} when the
 * message is available.
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






















 * @group Signature Negotiation
 */
export declare function getSignatureRequests(message: Request | Response): ReadonlyArray<SignatureRequest>;
/**
 * Serializes one or more signature requests as an `Accept-Signature` Structured Field Dictionary.
 *
 * Use {@link appendAcceptSignature} when the sender message is available so component applicability
 * can also be checked against the type of the requested target message.
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
 * Drop-in `fetch` that signs outgoing requests only. Responses are returned unverified.
 *
 * Use this when the peer verifies what you send but does not sign what it returns. To verify
 * responses as well, use {@link createSignedFetch}. To verify without signing, use
 * {@link createVerifyingFetch}.
 *
 * Automatic redirects are changed to manual redirects because Fetch cannot re-sign each redirected
 * request and could otherwise forward stale signature fields to a different origin.
 *















































 * @group Fetch Wrappers
 */
export declare function createSigningFetch(options: SigningFetchOptions): typeof globalThis.fetch;
/**
 * Drop-in `fetch` that verifies responses only. Requests are sent unsigned.
 *
 * Use this when the peer signs what it returns but does not require a signature from you. To sign
 * outgoing requests as well, use {@link createSignedFetch}. To sign without verifying, use
 * {@link createSigningFetch}.
 *
 * Automatic redirects are changed to manual redirects because Fetch does not expose the request
 * that produced a response after following a redirect.
 *
































 * @group Fetch Wrappers
 */
export declare function createVerifyingFetch(options: VerifyingFetchOptions): typeof globalThis.fetch;
/**
 * Drop-in `fetch` that signs outgoing requests and verifies responses, in both directions.
 *
 * Use this when both peers sign. Response verification is optional, so leaving `verify` out gives
 * the same behavior as {@link createSigningFetch} from one wrapper. To do only one direction and let
 * a bundler drop the other, use {@link createSigningFetch} or {@link createVerifyingFetch}.
 *
 * Automatic redirects are changed to manual redirects because Fetch cannot re-sign each redirected
 * request and could otherwise forward stale signature fields to a different origin.
 *



































 * @group Fetch Wrappers
 */
export declare function createSignedFetch(options: SignedFetchOptions): typeof globalThis.fetch;
//# sourceMappingURL=index.d.ts.map