




















































































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
































































































































































































































































































































































































































function fail(message        )        {
  throw new TypeError(message)
}



















function resolveExtractableOption(extractable                     )          {
  if (extractable === undefined) {
    return false
  }
  if (typeof extractable !== 'boolean') {
    fail('"extractable" must be a boolean')
  }
  return extractable
}








function resolveModulusLengthOption(modulusLength                    )         {
  if (modulusLength === undefined) {
    return 2048
  }
  if (typeof modulusLength !== 'number' || !Number.isInteger(modulusLength) || modulusLength <= 0) {
    fail('"modulusLength" must be a positive integer')
  }
  return modulusLength
}







function readProperty(value         , property        )          {
  if (value === null || typeof value !== 'object') {
    return undefined
  }
  return (value                           )[property]
}










function isAlgorithmKey(key           , expected                         )          {
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
  if (
    expected.namedCurve !== undefined &&
    readProperty(algorithm, 'namedCurve') !== expected.namedCurve
  ) {
    return false
  }
  return (
    expected.hash === undefined ||
    readProperty(readProperty(algorithm, 'hash'), 'name') === expected.hash
  )
}





function assertAlgorithmKey(key           , expected                         )       {
  if (!isAlgorithmKey(key, expected)) {
    fail(
      `"key" must be Web Cryptography's ${expected.type} CryptoKey for "${expected.identifier}" with "${expected.usage}" usage`,
    )
  }
}







function createWebCryptoSignerFactory(
  key           ,
  expected                         ,
  operation                             ,
)                {
  assertAlgorithmKey(key, expected)
  return () => ({
    type: 'signer',
    alg: expected.identifier,
    async sign(data) {
      return new Uint8Array(await globalThis.crypto.subtle.sign(operation, key, data))
    },
  })
}








function createWebCryptoVerifierFactory(
  key           ,
  expected                         ,
  operation                             ,
)                             {
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
  algorithm                                 ,
  extractable                     ,
)                         {
  return (await globalThis.crypto.subtle.generateKey(
    algorithm,
    resolveExtractableOption(extractable),
    ['sign', 'verify'],
  ))                 
}



























export async function generateEcdsaP256Sha256KeyPair(
  extractable          ,
)                         {
  return generateWebCryptoKeyPair({ name: 'ECDSA', namedCurve: 'P-256' }, extractable)
}









export function ecdsaP256Sha256Signer(key           )                {
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











export function ecdsaP256Sha256Verifier(key           )                             {
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







































export async function generateEcdsaP384Sha384KeyPair(
  extractable          ,
)                         {
  return generateWebCryptoKeyPair({ name: 'ECDSA', namedCurve: 'P-384' }, extractable)
}









export function ecdsaP384Sha384Signer(key           )                {
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











export function ecdsaP384Sha384Verifier(key           )                             {
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


























export async function generateEd25519KeyPair(extractable          )                         {
  return generateWebCryptoKeyPair('Ed25519', extractable)
}









export function ed25519Signer(key           )                {
  return createWebCryptoSignerFactory(
    key,
    { identifier: 'ed25519', type: 'private', usage: 'sign', algorithm: 'Ed25519' },
    'Ed25519',
  )
}


































export function ed25519Verifier(key           )                             {
  return createWebCryptoVerifierFactory(
    key,
    { identifier: 'ed25519', type: 'public', usage: 'verify', algorithm: 'Ed25519' },
    'Ed25519',
  )
}
































export async function generateRsaPssSha512KeyPair(
  extractable          ,
  modulusLength         ,
)                         {
  return generateWebCryptoKeyPair(
    {
      name: 'RSA-PSS',
      modulusLength: resolveModulusLengthOption(modulusLength),
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-512',
    },
    extractable,
  )
}












export function rsaPssSha512Signer(key           )                {
  return createWebCryptoSignerFactory(
    key,
    {
      identifier: 'rsa-pss-sha512',
      type: 'private',
      usage: 'sign',
      algorithm: 'RSA-PSS',
      hash: 'SHA-512',
    },
    { name: 'RSA-PSS', saltLength: 64 },
  )
}












export function rsaPssSha512Verifier(key           )                             {
  return createWebCryptoVerifierFactory(
    key,
    {
      identifier: 'rsa-pss-sha512',
      type: 'public',
      usage: 'verify',
      algorithm: 'RSA-PSS',
      hash: 'SHA-512',
    },
    { name: 'RSA-PSS', saltLength: 64 },
  )
}


















export async function generateRsaV1_5Sha256KeyPair(
  extractable          ,
  modulusLength         ,
)                         {
  return generateWebCryptoKeyPair(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: resolveModulusLengthOption(modulusLength),
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    extractable,
  )
}











export function rsaV1_5Sha256Signer(key           )                {
  return createWebCryptoSignerFactory(
    key,
    {
      identifier: 'rsa-v1_5-sha256',
      type: 'private',
      usage: 'sign',
      algorithm: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    'RSASSA-PKCS1-v1_5',
  )
}















export function rsaV1_5Sha256Verifier(key           )                             {
  return createWebCryptoVerifierFactory(
    key,
    {
      identifier: 'rsa-v1_5-sha256',
      type: 'public',
      usage: 'verify',
      algorithm: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    'RSASSA-PKCS1-v1_5',
  )
}






function isRequest(message                    )                     {
  return typeof (message           ).method === 'string'
}







function isHeaders(value         )                   {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value           ).append === 'function' &&
    typeof (value           ).delete === 'function' &&
    typeof (value           ).get === 'function' &&
    typeof (value           ).has === 'function' &&
    typeof (value           ).set === 'function'
  )
}








function isDate(value         )                {
  try {
    Date.prototype.getTime.call(value        )
    return true
  } catch {
    return false
  }
}





const typedArrayName = /* @__PURE__ */ Object.getOwnPropertyDescriptor(
  /* @__PURE__ */ Object.getPrototypeOf(Uint8Array.prototype),
  Symbol.toStringTag,
) .get                                          









function isUint8Array(value         )                      {
  return typedArrayName.call(value) === 'Uint8Array'
}







function assertMessage(message         )                                        {
  const candidate = message                             
  if (
    candidate === null ||
    typeof candidate !== 'object' ||
    typeof candidate.headers?.get !== 'function'
  ) {
    fail('"message" must be a Request or Response')
  }
  if (isRequest(candidate)) {


    if (typeof candidate.url !== 'string') {
      fail('"message" must be a Request or Response')
    }
    return
  }
  if (typeof (candidate            ).status !== 'number') {
    fail('"message" must be a Request or Response')
  }
}






function assertSignatureContext(context                            )       {
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





function assertSfKey(value        , description        )       {
  if (typeof value !== 'string' || !SF_KEY.test(value)) {
    fail(`${description} must be a Structured Field key`)
  }
}


function assertAscii(value        , description        )       {
  if (!ASCII.test(value)) {
    fail(`${description} must contain only ASCII characters`)
  }
}





function cloneBytes(value            )                          {
  return new Uint8Array(value)
}
















function createMessageMutationGuard(
  message                    ,
  context                  ,
)                       {
  let request                     
  let requestHeaders                     
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


function headersEqual(left         , right         )          {
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
  guard                      ,
  operation                            ,
)       {
  if (
    !headersEqual(guard.headers, guard.message.headers) ||
    (guard.request !== undefined && !headersEqual(guard.requestHeaders , guard.request.headers))
  ) {
    throw new Error(`HTTP message headers changed during signature ${operation}`)
  }
}







function bytesEqual(left            , right            )          {
  if (left.byteLength !== right.byteLength) {
    return false
  }
  let different = 0
  for (let i = 0; i < left.byteLength; i++) {
    different |= left[i]  ^ right[i] 
  }
  return different === 0
}













function base64Encode(value            )         {
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
















function base64Decode(value        )                          {
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

    throw new TypeError('Invalid Structured Field Byte Sequence', { cause })
  }
}


function skipSp(state            )       {
  while (state.input[state.index] === ' ') {
    state.index++
  }
}





function skipOws(state            )       {
  while (state.input[state.index] === ' ' || state.input[state.index] === '\t') {
    state.index++
  }
}


function parseKey(state            )         {
  const start = state.index
  const first = state.input[state.index]
  if (first === undefined || !/[a-z*]/.test(first)) {
    fail('Invalid Structured Field key')
  }
  state.index++
  while (state.index < state.input.length && /[a-z0-9_.*-]/.test(state.input[state.index] )) {
    state.index++
  }
  return state.input.slice(start, state.index)
}








function setOrderedEntry                                      (
  entries     ,
  positions                     ,
  entry   ,
  duplicateKeys           ,
)       {
  const position = positions.get(entry[0])
  if (position === undefined) {
    positions.set(entry[0], entries.length)
    entries.push(entry)
  } else {
    duplicateKeys?.push(entry[0])
    entries[position] = entry
  }
}


function parseNumber(state            )             {
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


function parseString(state            )             {
  if (state.input[state.index] !== '"') {
    fail('Invalid Structured Field String')
  }
  state.index++
  let value = ''
  while (state.index < state.input.length) {
    const character = state.input[state.index++] 
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


function parseToken(state            )             {
  const start = state.index
  const first = state.input[state.index]
  if (first === undefined || !/[A-Za-z*]/.test(first)) {
    fail('Invalid Structured Field Token')
  }
  state.index++
  while (
    state.index < state.input.length &&
    /[!#$%&'*+\-.^_`|~A-Za-z0-9:/*]/.test(state.input[state.index] )
  ) {
    state.index++
  }
  return { kind: 'token', value: state.input.slice(start, state.index) }
}


function parseBinary(state            )             {
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


function parseBoolean(state            )             {
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


function parseDate(state            )             {
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





function parseDisplayString(state            )             {
  if (state.input[state.index] !== '%' || state.input[state.index + 1] !== '"') {
    fail('Invalid Structured Field Display String')
  }
  state.index += 2
  const bytes           = []
  while (state.index < state.input.length) {
    const character = state.input[state.index++] 
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


function parseBareItem(state            )             {
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


function parseParameters(state            )               {
  const parameters               = []
  const positions = new Map                ()
  while (state.input[state.index] === ';') {
    state.index++
    skipSp(state)
    const name = parseKey(state)
    let value             = { kind: 'boolean', value: true }
    if (state.input[state.index] === '=') {
      state.index++
      value = parseBareItem(state)
    }
    setOrderedEntry(parameters, positions, [name, value])
  }
  return parameters
}


function parseItem(state            )         {
  return { kind: 'item', value: parseBareItem(state), parameters: parseParameters(state) }
}





function parseInnerList(state            )              {
  if (state.input[state.index] !== '(') {
    fail('Invalid Structured Field Inner List')
  }
  state.index++
  const value           = []
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


function parseMember(state            )           {
  return state.input[state.index] === '(' ? parseInnerList(state) : parseItem(state)
}


function parseList(state            )         {
  const output         = []
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


function parseDictionary(state            )               {
  const output               = []
  const positions = new Map                ()
  while (state.index < state.input.length) {
    const name = parseKey(state)
    let value          
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
    setOrderedEntry(output, positions, [name, value], state.duplicateKeys)
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









function parseSfTopLevel(
  input        ,
  type                     ,
  rejectDuplicateKeys = false,
)             {
  assertAscii(input, 'Structured Field value')
  const state             = { input, index: 0, duplicateKeys: [] }
  skipSp(state)
  let output            
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


function serializeKey(value        )         {
  assertSfKey(value, 'Structured Field key')
  return value
}


function serializeString(value        )         {
  if (!PRINTABLE_ASCII.test(value)) {
    fail('Structured Field String must contain only printable ASCII characters')
  }
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`
}







function assertUnicodeScalarValues(value        )       {
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





function serializeDisplayString(value        )         {
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








function serializeDecimal(value        )         {
  if (!Number.isFinite(value)) {
    fail('Structured Field Decimal must be finite')
  }

  const absolute = Math.abs(value)
  const [mantissa, exponentInput] = absolute.toString().toLowerCase().split('e')
  const exponent = exponentInput === undefined ? 0 : Number(exponentInput)
  const point = mantissa .indexOf('.')
  const fractionDigits = point === -1 ? 0 : mantissa .length - point - 1
  const digits = point === -1 ? mantissa  : mantissa .slice(0, point) + mantissa .slice(point + 1)
  let numerator = BigInt(digits)
  const power = exponent - fractionDigits + 3
  let scaled        
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


function serializeBareItem(item            )         {
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


function serializeParameters(parameters              )         {
  let output = ''
  for (const [name, value] of parameters) {
    output += `;${serializeKey(name)}`
    if (value.kind !== 'boolean' || !value.value) {
      output += `=${serializeBareItem(value)}`
    }
  }
  return output
}


function serializeItem(item        )         {
  return serializeBareItem(item.value) + serializeParameters(item.parameters)
}


function serializeInnerList(value             )         {
  return `(${value.value.map(serializeItem).join(' ')})${serializeParameters(value.parameters)}`
}


function serializeMember(value          )         {
  return value.kind === 'inner-list' ? serializeInnerList(value) : serializeItem(value)
}


function serializeList(value        )         {
  return value.map(serializeMember).join(', ')
}


function serializeDictionary(value              )         {
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







function serializeSfTopLevel(value            , type                     )         {
  switch (type) {
    case 'dictionary':
      return serializeDictionary(value                )
    case 'list':
      return serializeList(value          )
    case 'item':
      return serializeItem(value          )
  }
}



























export function token(value        )                       {
  if (typeof value !== 'string' || !SF_TOKEN.test(value)) {
    fail('"value" must be a Structured Field Token')
  }
  return { type: 'token', value }
}




























export function decimal(value        )                         {
  return { type: 'decimal', value: Number(serializeDecimal(value)) }
}































export function date(value               )                      {
  let seconds        
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

























export function displayString(value        )                               {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  serializeDisplayString(value)
  return { type: 'display-string', value }
}


function structuredFieldItemFromSf(item        )                      {
  return {
    type: 'item',
    value: signatureParameterValueFromSfBareItem(item.value),
    parameters: structuredFieldParametersFromSf(item.parameters),
  }
}


function structuredFieldParametersFromSf(parameters              )                             {
  return parameters.map(([name, value]) => [name, signatureParameterValueFromSfBareItem(value)])
}


function structuredFieldMemberFromSf(member          )                        {
  if (member.kind === 'item') {
    return structuredFieldItemFromSf(member)
  }
  return {
    type: 'inner-list',
    value: member.value.map(structuredFieldItemFromSf),
    parameters: structuredFieldParametersFromSf(member.parameters),
  }
}







function sfParametersFromStructuredField(
  parameters                                                     ,
  path        ,
)               {
  if (parameters === undefined) {
    return []
  }
  if (!Array.isArray(parameters)) {
    fail(`${path} parameters must be an array`)
  }
  const output               = []
  const seen = new Set        ()
  for (const entry of parameters) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      fail(`${path} parameters must be [name, value] entries`)
    }
    const [name, value] = entry                                     
    assertSfKey(name, `${path} parameter name`)
    if (seen.has(name)) {
      fail(`Duplicate ${path} parameter "${name}"`)
    }
    seen.add(name)
    const bare = sfBareItemFromSignatureParameter(`${path} parameter "${name}"`, value)
    if (bare === undefined) {
      fail(`${path} parameter "${name}" has an unsupported value`)
    }
    output.push([name, bare])
  }
  return output
}


function sfItemFromStructuredField(item                     , path        )         {
  if (item === null || typeof item !== 'object' || item.type !== 'item') {
    fail(`${path} must be a Structured Field Item`)
  }
  const value = sfBareItemFromSignatureParameter(path, item.value)
  if (value === undefined) {
    fail(`${path} has an unsupported value`)
  }
  return { kind: 'item', value, parameters: sfParametersFromStructuredField(item.parameters, path) }
}


function sfMemberFromStructuredField(member                       , path        )           {
  if (member === null || typeof member !== 'object') {
    fail(`${path} must be a Structured Field Item or Inner List`)
  }
  if (member.type === 'inner-list') {
    if (!Array.isArray(member.value)) {
      fail(`${path} Inner List value must be an array`)
    }
    return {
      kind: 'inner-list',
      value: member.value.map((entry, index) =>
        sfItemFromStructuredField(entry, `${path} member ${index}`),
      ),
      parameters: sfParametersFromStructuredField(member.parameters, path),
    }
  }
  return sfItemFromStructuredField(member                       , path)
}










































export function parseStructuredField(
  value        ,
  type                     ,
)                       {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  assertStructuredFieldType(type)
  const parsed = parseSfTopLevel(value, type)
  switch (type) {
    case 'dictionary':
      return (parsed                ).map(([name, member]) => [
        name,
        structuredFieldMemberFromSf(member),
      ])
    case 'list':
      return (parsed          ).map(structuredFieldMemberFromSf)
    case 'item':
      return structuredFieldItemFromSf(parsed          )
  }
}













































export function serializeStructuredField(
  value                      ,
  type                     ,
)         {
  assertStructuredFieldType(type)
  if (type === 'item') {
    return serializeSfTopLevel(
      sfItemFromStructuredField(value                       , 'Item'),
      type,
    )
  }
  if (!Array.isArray(value)) {
    fail(`A Structured Field ${type} must be an array`)
  }
  if (type === 'list') {
    return serializeSfTopLevel(
      (value                       ).map((member, index) =>
        sfMemberFromStructuredField(member, `List member ${index}`),
      ),
      type,
    )
  }
  const entries               = []
  const seen = new Set        ()
  for (const entry of value                             ) {
    if (!Array.isArray(entry) || entry.length !== 2) {
      fail('A Structured Field Dictionary must contain [name, value] entries')
    }
    const [name, member] = entry                                   
    assertSfKey(name, 'Structured Field Dictionary key')
    if (seen.has(name)) {
      fail(`Duplicate Structured Field Dictionary key "${name}"`)
    }
    seen.add(name)
    entries.push([name, sfMemberFromStructuredField(member, `Dictionary member "${name}"`)])
  }
  return serializeSfTopLevel(entries, type)
}


function assertStructuredFieldType(type                     )       {
  if (type !== 'dictionary' && type !== 'list' && type !== 'item') {
    fail('"type" must be "dictionary", "list", or "item"')
  }
}






























































export function component(
  name        ,
  parameters                      = [],
)                         {
  if (typeof name !== 'string') {
    fail('"name" must be a string')
  }
  return { name: name.startsWith('@') ? name : name.toLowerCase(), parameters }
}




































































export function includesComponent(
  components                                    ,
  identifier                     ,
)          {
  if (!Array.isArray(components)) {
    fail('"components" must be an array')
  }
  const wanted = toMessageComponent(identifier)
  validateComponentParameters(wanted)
  return components.some((candidate) => sameComponent(wanted, toMessageComponent(candidate)))
}




















































export function findComponents(
  components                                    ,
  name        ,
)                     {
  if (!Array.isArray(components)) {
    fail('"components" must be an array')
  }
  if (typeof name !== 'string') {
    fail('"name" must be a string')
  }
  const wanted = toMessageComponent(name)
  validateComponentName(wanted)
  return components
    .map((candidate) => toMessageComponent(candidate))
    .filter((candidate) => candidate.name === wanted.name)
}








function orderedParameterEntries   (
  parameters                                                                               ,
)                     {
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
  return Object.entries(parameters)                      
}








function sfBareItemFromSignatureParameter(
  name        ,
  input                         ,
)                         {
  if (input === undefined) {
    return undefined
  }

  let value                         
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





function signatureParameterValueFromSfBareItem(item            )                          {
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
  parameters                                 ,
  defaultCreated                    ,
)               {
  return normalizeSignatureParameterEntries(orderedParameterEntries(parameters), defaultCreated)
}








function normalizeSignatureParameterEntries(
  entries                                          ,
  defaultCreated                    ,
)               {
  const output               = []
  const seen = new Set        ()

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


function findSfParameterValue(parameters              , name        )                         {
  return parameters.find(([candidate]) => candidate === name)?.[1]
}









function validateKnownSignatureParameters(parameters              , requested         )       {
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





function normalizeComponentParameters(parameters                                 )               {
  const entries = orderedParameterEntries(parameters)
  const output               = []
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





function componentParameterFromSfBareItem(value            )                          {
  if (value.kind === 'string' || value.kind === 'boolean') {
    return value.value
  }
  return fail('Component parameters must be Strings or Booleans')
}





function componentFromSfItem(item        )                   {
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





function serializeComponentIdentifier(identifier                  )         {



  let output = `"${identifier.name}"`
  for (const [name, value] of identifier.parameters) {
    output += `;${serializeKey(name)}`
    if (value === true) {
      continue
    }
    output += typeof value === 'string' ? `=${serializeString(value)}` : '=?0'
  }
  return output
}









function serializeSignatureParams(
  identifiers                       ,
  parameters              ,
)         {
  return `(${identifiers.join(' ')})${serializeParameters(parameters)}`
}

function componentToSfItem(identifier                  )         {
  return {
    kind: 'item',
    value: { kind: 'string', value: identifier.name },
    parameters: identifier.parameters.map(([name, value]) => [
      name,
      typeof value === 'string' ? { kind: 'string', value } : { kind: 'boolean', value },
    ]),
  }
}








function toMessageComponent(input                     )                   {
  let name        
  let parameters                                 
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
  return {
    name,
    parameters: normalizeComponentParameters(parameters).map(([parameterName, value]) => [
      parameterName,
      componentParameterFromSfBareItem(value),
    ]),
  }
}





function normalizeComponents(components                                    )                     {
  if (!Array.isArray(components)) {
    fail('"components" must be an array')
  }
  return components.map((input) => {
    const normalized = toMessageComponent(input)
    validateComponentName(normalized)
    return normalized
  })
}






function validateComponentName(identifier                  )       {
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


function componentParameterMap(identifier                  )                                       {
  return new Map(identifier.parameters)
}







function readComponentFlag(
  parameters                                      ,
  name        ,
)          {
  const value = parameters.get(name)
  if (value === undefined) {
    return false
  }
  if (value !== true) {
    fail(`Component parameter "${name}" must be a bare Boolean true`)
  }
  return true
}


















function assertSignableComponents(
  components                                 ,
  label        ,
)       {
  assertUniqueComponents(components)
  for (const identifier of components) {
    validateComponentParameters(identifier)
    if (identifier.name !== 'signature' && identifier.name !== 'signature-input') {
      continue
    }
    const componentParameters = componentParameterMap(identifier)
    if (componentParameters.get('req') === true || componentParameters.get('tr') === true) {
      continue
    }
    const key = componentParameters.get('key')
    if (key === undefined) {
      fail('A signature cannot cover fields to which it is being appended')
    }
    if (identifier.name === 'signature' && key === label) {
      fail(`A signature cannot cover its own "signature" Dictionary member "${label}"`)
    }
  }
}









function validateComponentParameters(identifier                  )          {
  validateComponentName(identifier)
  const parameters = componentParameterMap(identifier)

  if (identifier.name.startsWith('@')) {
    const allowed = new Set        ()
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







function validateComponentForTarget(identifier                  , request         )       {
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


function validateComponentForMessage(
  identifier                  ,
  message                    ,
)       {
  validateComponentForTarget(identifier, isRequest(message))
}


function sameBareItem(left            , right            )          {
  if (left.kind !== right.kind) {
    return false
  }
  if (left.kind === 'binary' && right.kind === 'binary') {
    return bytesEqual(left.value, right.value)
  }
  return left.value === right.value
}






function sameComponent(left                  , right                  )          {
  if (left.name !== right.name || left.parameters.length !== right.parameters.length) {
    return false
  }


  return left.parameters.every(([name, value]) =>
    right.parameters.some(([otherName, otherValue]) => otherName === name && otherValue === value),
  )
}









function assertUniqueComponents(components                                 )       {



  const identifiers = new Set        ()
  const dictionaryKeys = new Set        ()

  for (const identifier of components) {
    const parameters = componentParameterMap(identifier)




    const canonical =
      identifier.parameters.length === 0
        ? identifier.name
        : JSON.stringify([
            identifier.name,
            [...parameters].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)),
          ])
    if (identifiers.has(canonical)) {
      fail(`Duplicate covered component "${identifier.name}"`)
    }
    identifiers.add(canonical)

    const key = parameters.get('key')
    if (typeof key === 'string') {


      const context = JSON.stringify([
        identifier.name,
        key,
        parameters.get('req'),
        parameters.get('tr'),
      ])
      if (dictionaryKeys.has(context)) {
        fail(`Duplicate covered dictionary key "${identifier.name}";key="${key}"`)
      }
      dictionaryKeys.add(context)
    }
  }
}





function signatureParametersInnerList(
  components                                 ,
  parameters              ,
)              {
  return { kind: 'inner-list', value: components.map(componentToSfItem), parameters }
}





function signatureParametersFromSf(
  parameters              ,
)                                                    {
  return parameters.map(([name, value]) => [name, signatureParameterValueFromSfBareItem(value)])
}


function unixTimestamp(input                           )         {
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







function getTargetUri(request         )         {
  const hash = request.url.indexOf('#')
  const value = hash === -1 ? request.url : request.url.slice(0, hash)
  if (!ASCII.test(value)) {
    fail('Request target URI must contain only ASCII characters')
  }
  return value
}










function parseTargetUri(target        )      {
  let url     
  try {
    url = new URL(target)
  } catch (cause) {
    throw new TypeError('Request does not have a valid target URI', { cause })
  }
  if (url.username !== '' || url.password !== '') {
    fail('Request target URI must not include credentials')
  }
  return url
}
























































function createBaseDerivations()                  {
  return { targetUris: new Map(), fields: new Map() }
}








function deriveField(
  message                    ,
  name        ,
  trailers         ,
  relatedRequest         ,
  options                  ,
  derivations                 ,
)                  {
  let byName = derivations.fields.get(message)
  if (byName === undefined) {
    byName = new Map()
    derivations.fields.set(message, byName)
  }

  const key = `${trailers ? 'trailer' : 'header'} ${name}`
  let derived = byName.get(key)
  if (derived === undefined) {
    const values = collectFieldValues(message, name, trailers, relatedRequest, options)
    derived = { values, combined: values.join(', ') }
    byName.set(key, derived)
  }
  return derived
}


function deriveTargetUri(request         , derivations                      )                      {
  let derived = derivations.get(request)
  if (derived === undefined) {
    const target = getTargetUri(request)
    derived = { target, url: parseTargetUri(target) }
    derivations.set(request, derived)
  }
  return derived
}








function formPercentEncode(value        )         {
  return encodeURIComponent(value).replace(/[!'()~]/g, (character) => {
    return `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  })
}









function deriveQueryParameter(derived                     , encodedName        )         {
  if (derived.queryParameters === undefined) {
    const queryStart = derived.target.indexOf('?')
    const query = queryStart === -1 ? '' : derived.target.slice(queryStart + 1)
    const parameters = new Map                  ()
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


    fail(`Query parameter "${encodedName}" occurs more than once`)
  }
  return matches[0] 
}












function deriveRequestComponentValue(
  identifier                  ,
  parameters                                              ,
  request         ,
  derivations                 ,
)         {
  const derived = deriveTargetUri(request, derivations.targetUris)
  const { target, url } = derived


  const path = url.pathname || '/'
  const queryStart = target.indexOf('?')
  switch (identifier.name) {
    case '@method':
      return request.method
    case '@target-uri':
      return target
    case '@authority':


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
      return deriveQueryParameter(derived, parameters.get('name')          )
    default:
      return fail(`Derived component "${identifier.name}" does not apply to a request`)
  }
}








function assertTargetUriAuthority(url     , name        )         {
  if (url.host === '') {
    fail(`Derived component "${name}" requires a target URI with an authority`)
  }
  return url.host
}








function trimFieldWhitespace(value        )         {
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














function normalizeFieldLine(value        )         {
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





function assertFieldValue(value        , name        )       {
  if (/[\r\n]/.test(value)) {
    fail(`HTTP field "${name}" contains a newline`)
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) {
    fail(`HTTP field "${name}" contains an invalid control character`)
  }
}









function assertBaseValue(value        , name        )       {
  if (!/[^\t\x20-\x7e]/.test(value)) {
    return
  }
  assertFieldValue(value, name)
  fail(`HTTP field "${name}" contains a non-ASCII character`)
}










function fieldValuesFromHeaders(
  message                    ,
  name        ,
  trailers         ,
)                                    {
  if (trailers) {
    fail(`Trailer field "${name}" is not exposed by Fetch; provide the "fieldValues" option`)
  }
  if (!message.headers.has(name)) {
    return undefined
  }
  if (name === 'set-cookie') {
    const headers = message.headers                                               
    if (typeof headers.getSetCookie === 'function') {
      return headers.getSetCookie()
    }
  }
  return [message.headers.get(name) ]
}







function collectFieldValues(
  message                    ,
  name        ,
  trailers         ,
  relatedRequest         ,
  options                  ,
)           {
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











function latin1Bytes(value        , name        )             {
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








function resolveStructuredFieldType(
  name        ,
  options                  ,
)                                  {
  if (name === 'signature-input' || name === 'signature' || name === 'accept-signature') {
    return 'dictionary'
  }
  if (options.structuredFields !== undefined) {



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









function deriveFieldComponentValue(
  identifier                  ,
  message                    ,
  relatedRequest         ,
  options                  ,
  derivations                 ,
)         {
  const parameters = componentParameterMap(identifier)
  const sf = readComponentFlag(parameters, 'sf')
  const bs = readComponentFlag(parameters, 'bs')
  const trailers = readComponentFlag(parameters, 'tr')
  const key = parameters.get('key')

  const fetchExposesOccurrences =
    identifier.name === 'set-cookie' &&
    typeof (message.headers                                        ).getSetCookie === 'function'
  if (bs && options.fieldValues === undefined && !fetchExposesOccurrences) {
    fail(`"${identifier.name}";bs requires "fieldValues" because Fetch hides field occurrences`)
  }

  const field = deriveField(
    message,
    identifier.name,
    trailers,
    relatedRequest,
    options,
    derivations,
  )

  if (bs) {
    const list         = field.values.map((value) => ({
      kind: 'item',
      value: { kind: 'binary', value: latin1Bytes(value, identifier.name) },
      parameters: [],
    }))
    return serializeList(list)
  }

  if (key !== undefined) {
    const type = resolveStructuredFieldType(identifier.name, options)
    if (type !== undefined && type !== 'dictionary') {
      fail(
        `Structured Field type for "${identifier.name}" must be "dictionary" with the "key" parameter`,
      )
    }

    if (field.members === undefined) {
      const dictionary = parseSfTopLevel(field.combined, 'dictionary')                
      field.members = new Map(dictionary)
    }
    const member = field.members.get(key          )
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
    field.serialized ??= serializeSfTopLevel(parseSfTopLevel(field.combined, type), type)
    return field.serialized
  }

  return field.combined
}








function resolveComponentValue(
  identifier                  ,
  message                    ,
  options                  ,
  derivations                 ,
)         {
  validateComponentForMessage(identifier, message)
  const parameters = componentParameterMap(identifier)
  const relatedRequest = parameters.has('req')
  let source                     = message
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

  let value        
  if (identifier.name.startsWith('@')) {
    if (identifier.name === '@status') {
      const status = (source            ).status
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
    value = deriveFieldComponentValue(identifier, source, relatedRequest, options, derivations)
  }
  assertBaseValue(value, identifier.name)
  return value
}

















function buildSignatureBase(
  message                    ,
  components                                 ,
  parameters              ,
  options                  ,
)         {
  assertUniqueComponents(components)
  const derivations = createBaseDerivations()
  const identifiers           = []
  let output = ''
  for (const identifier of components) {
    const serializedIdentifier = serializeComponentIdentifier(identifier)
    identifiers.push(serializedIdentifier)
    output += `${serializedIdentifier}: ${resolveComponentValue(identifier, message, options, derivations)}\n`
  }
  output += `"@signature-params": ${serializeSignatureParams(identifiers, parameters)}`
  return output
}









function assertSignatureBaseUnchanged(
  guard                      ,
  components                                 ,
  parameters              ,
  options                  ,
  expected        ,
  operation                            ,
)       {
  assertMessageUnchanged(guard, operation)
  let current        
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













































export function createSignatureBase(
  message                    ,
  options                      ,
)         {
  assertMessage(message)
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  assertSignatureContext(options)
  const components = normalizeComponents(options.components)
  const parameters = normalizeSignatureParameters(options.parameters, undefined)
  return buildSignatureBase(message, components, parameters, options)
}













































export function createSignatureFields(options                        )                  {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const label = options.label ?? 'sig1'
  assertSfKey(label, 'Signature label')
  if (!isUint8Array(options.signature)) {
    fail('"signature" must be a Uint8Array')
  }

  const components = normalizeComponents(options.components)
  assertSignableComponents(components, label)
  const parameters = normalizeSignatureParameters(options.parameters, undefined)

  const signature = cloneBytes(options.signature)
  return {
    label,
    components,
    parameters: signatureParametersFromSf(parameters),
    signature,
    ...serializeSignatureFields(label, components, parameters, signature),
  }
}
















function parseSignatureInputMember(label        , member          )                       {
  if (member.kind !== 'inner-list') {
    fail(`Signature-Input member "${label}" must be an Inner List`)
  }
  return { label, components: member.value.map(componentFromSfItem), parameters: member.parameters }
}





function validateSignatureInput(input                      )                       {
  validateKnownSignatureParameters(input.parameters, false)
  for (const identifier of input.components) {
    validateComponentParameters(identifier)
  }
  assertUniqueComponents(input.components)
  return input
}


function parseSignatureValueMember(label        , member          )                       {
  if (member.kind !== 'item' || member.value.kind !== 'binary') {
    fail(`Signature member "${label}" must be a Byte Sequence`)
  }
  return { label, value: cloneBytes(member.value.value) }
}


function parseSignatureInputInternal(value        )                         {
  const dictionary = parseSfTopLevel(value, 'dictionary', true)                
  return dictionary.map(([label, member]) => {
    return validateSignatureInput(parseSignatureInputMember(label, member))
  })
}





function parseSignatureInternal(value        )                         {
  const dictionary = parseSfTopLevel(value, 'dictionary', true)                
  return dictionary.map(([label, member]) => parseSignatureValueMember(label, member))
}






























export function parseSignatureInput(
  value        ,
)                                                     {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  return parseSignatureInputInternal(value).map(({ label, components, parameters }) => ({
    label,
    components,
    parameters: signatureParametersFromSf(parameters),
  }))
}























export function parseSignature(
  value        ,
)                                                                                 {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  return parseSignatureInternal(value).map(({ label, value: signature }) => ({ label, signature }))
}










function getDictionaryField(headers         , name        )                {
  const value = headers.get(name)
  return value === null || /^[ \t]*$/.test(value) ? null : value
}








function parseSignatureFieldDictionaries(headers         )   


  {
  const signatureInput = getDictionaryField(headers, 'signature-input')
  const signature = getDictionaryField(headers, 'signature')
  if (signatureInput === null && signature === null) {
    return { inputs: [], values: [] }
  }
  if (signatureInput === null || signature === null) {
    fail('Signature and Signature-Input fields must both be present')
  }
  const inputs = parseSfTopLevel(signatureInput, 'dictionary', true)                
  const values = parseSfTopLevel(signature, 'dictionary', true)                
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





function parseSignatureFieldMembers(headers         )   


  {
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



































export function getSignatureParameter(
  signature                            ,
  name        ,
)                                      {
  if (signature === null || typeof signature !== 'object' || !Array.isArray(signature.parameters)) {
    fail('"signature" must be a MessageSignature object')
  }
  if (typeof name !== 'string') {
    fail('"name" must be a string')
  }
  return findSignatureParameterValue(signature.parameters, name)
}









































export function getSignatures(message                    )                                  {
  assertMessage(message)
  const { inputs, values } = parseSignatureFieldMembers(message.headers)



  const byLabel = new Map(values.map((entry) => [entry.label, entry.value]))
  return inputs.map(({ label, components, parameters }) => ({
    label,
    components,
    parameters: signatureParametersFromSf(parameters),
    signature: byLabel.get(label) ,
  }))
}







function selectSignature(
  message                    ,
  label                    ,
)   



  {
  const { inputs, values } = parseSignatureFieldDictionaries(message.headers)
  if (inputs.length === 0) {
    fail('Message does not contain an HTTP message signature')
  }
  let inputMember                               
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
  const valueMember = values.find(([candidate]) => candidate === input.label) 
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






function signerFromFactory(factory               )                   {
  if (typeof factory !== 'function') {
    fail('"signer" must be a factory function')
  }
  let signer                  
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








async function verifierFromFactory(
  factory                 ,
  signature                            ,
  context                               ,
)                              {
  if (typeof factory !== 'function') {
    fail('"verifier" must be a factory function')
  }
  let verifier                    
  try {
    verifier = await factory(signature, context)
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


function findSignatureParameterValue(
  parameters                                                           ,
  name        ,
)                                      {
  return parameters.find(([candidate]) => candidate === name)?.[1]
}





function cloneSignatureParameterValue(value                         )                          {
  if (isUint8Array(value)) {
    return cloneBytes(value)
  }
  if (value !== null && typeof value === 'object') {
    return { ...value }
  }
  return value
}





function cloneMessageSignature(signature                            )                   {
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





function serializeSignatureFields(
  label        ,
  components                                 ,
  parameters              ,
  signature            ,
)                                                                       {
  const inputDictionary               = [
    [label, signatureParametersInnerList(components, parameters)],
  ]
  const signatureDictionary               = [
    [label, { kind: 'item', value: { kind: 'binary', value: signature }, parameters: [] }],
  ]
  return {
    signatureInput: serializeDictionary(inputDictionary),
    signatureField: serializeDictionary(signatureDictionary),
  }
}














async function createSignatureInternal(
  message                    ,
  options             ,
)                             {
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
  assertSignableComponents(components, label)
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

  let signature            
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
  const fields                  = {
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







































































export async function createSignature(
  message                    ,
  options             ,
)                           {
  return (await createSignatureInternal(message, options)).fields
}

















function reconstructRequest(request         , headers         , carried        )          {
  if (request.mode === 'no-cors') {
    fail(`A "no-cors" request cannot carry ${carried} because Fetch drops the fields`)
  }
  return new Request(request, {
    headers,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
  })
}








function assertReconstructableResponse(response          , carried        )       {
  if (response.status === 0) {
    fail(`Opaque and error responses cannot carry ${carried}`)
  }
  if (!Number.isInteger(response.status) || response.status < 200 || response.status > 599) {
    fail(`Fetch cannot reconstruct a response with status ${response.status}`)
  }
}










function reconstructableResponseBody(response          )                                    {
  const { status } = response
  if (status === 204 || status === 205 || status === 304) {
    return null
  }
  return response.body
}








function appendToDictionaryField(headers         , name        , value        )       {
  const existing = getDictionaryField(headers, name)
  headers.set(name, existing === null ? value : `${existing}, ${value}`)
}








function appendSignatureHeaders(headers         , fields                 )          {
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
    input[0] .label !== fields.label ||
    signature[0] .label !== fields.label
  ) {
    fail('"fields" does not contain exactly one matching signature label')
  }

  appendToDictionaryField(output, 'signature-input', fields.signatureInput)
  appendToDictionaryField(output, 'signature', fields.signatureField)
  parseSignatureFieldDictionaries(output)
  return output
}






























































export function appendSignature(
  message                              ,
  fields                 ,
)                               {
  if (fields === null || typeof fields !== 'object') {
    fail('"fields" must be a SignatureFields object')
  }
  if (isHeaders(message)) {
    return appendSignatureHeaders(message, fields)
  }
  assertMessage(message)
  const headers = appendSignatureHeaders(message.headers, fields)
  if (isRequest(message)) {
    return reconstructRequest(message, headers, 'HTTP message signatures')
  }
  assertReconstructableResponse(message, 'HTTP message signatures')
  return new Response(reconstructableResponseBody(message), {
    headers,
    status: message.status,
    statusText: message.statusText,
  })
}





















































































export async function sign(
  message                    ,
  options             ,
)                              {
  const created = await createSignatureInternal(message, options)
  created.assertUnchanged()
  return isRequest(message)
    ? appendSignature(message, created.fields)
    : appendSignature(message, created.fields)
}





















function snapshotVerificationPolicy(policy                    )                               {
  if (policy === null || typeof policy !== 'object') {
    fail('"policy" must be an object')
  }



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








function enforceVerificationPolicy(
  signature                            ,
  policy                              ,
)       {
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







function enforceVerificationAlgorithm(
  signature                            ,
  algorithm        ,
  policy                              ,
)       {
  if (!policy.algorithms.includes(algorithm)) {
    fail(`Algorithm "${algorithm}" is not allowed by policy`)
  }

  const signaledAlgorithm = findSignatureParameterValue(signature.parameters, 'alg')
  if (signaledAlgorithm !== undefined && signaledAlgorithm !== algorithm) {
    fail('The verifier algorithm does not match the "alg" signature parameter')
  }
}







































































export async function verify(
  message                    ,
  options               ,
)                             {
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

  const context                      = { message, request: options.request }
  const verifier = await verifierFromFactory(options.verifier, cloneMessageSignature(signature), {
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
  let valid         
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






























function normalizeRequestedParameters(parameters                                 )               {
  const output               = []
  const seen = new Set        ()
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





function parseAcceptSignatureInternal(value        )                         {
  const dictionary = parseSfTopLevel(value, 'dictionary', true)                
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































export function parseAcceptSignature(value        )                                  {
  if (typeof value !== 'string') {
    fail('"value" must be a string')
  }
  return parseAcceptSignatureInternal(value).map(({ label, components, parameters }) => ({
    label,
    components,
    parameters: signatureParametersFromSf(parameters),
  }))
}

































export function getSignatureRequests(message                    )                                  {
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



































export function createAcceptSignature(requests                                      )         {
  if (!Array.isArray(requests) || requests.length === 0) {
    fail('"requests" must be a non-empty array')
  }
  const dictionary               = []
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





function appendAcceptSignatureHeaders(
  headers         ,
  value        ,
  targetIsRequest         ,
)          {
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











































































export function appendAcceptSignature(
  message                    ,
  requests                                      ,
)                     {
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
    return reconstructRequest(message, headers, 'Accept-Signature')
  }
  assertReconstructableResponse(message, 'Accept-Signature')
  return new Response(reconstructableResponseBody(message), {
    headers,
    status: message.status,
    statusText: message.statusText,
  })
}






function signatureParametersToSf(
  parameters                                                           ,
)               {
  if (!Array.isArray(parameters)) {
    fail('Signature request parameters must be an array')
  }
  const seen = new Set        ()
  const output               = []
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










function mergeRequestedParameters(
  request                  ,
  parameters                                 ,
  now        ,
)                                                                              {
  const requested = signatureParametersToSf(request.parameters)
  const suppliedEntries = orderedParameterEntries(parameters)
  const supplied = normalizeSignatureParameterEntries(suppliedEntries, undefined)
  const output               = []
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


function requestedSignatureOptions(
  message                    ,
  request                  ,
  options                      ,
)              {
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
  const normalizedRequest                   = {
    label: request.label,
    components,
    parameters: request.parameters,
  }
  const now = unixTimestamp(options.now)
  const merged = mergeRequestedParameters(normalizedRequest, options.parameters, now)
  const parameters                       = signatureParametersFromSf(merged.parameters)
  if (merged.omitDefaultCreated) {
    parameters.push(['created', false])
  }
  return { ...options, label: normalizedRequest.label, components, parameters, now }
}










































export async function createRequestedSignature(
  message                    ,
  request                  ,
  options                      ,
)                           {
  return createSignature(message, requestedSignatureOptions(message, request, options))
}






















































export async function signRequested(
  message                    ,
  request                  ,
  options                      ,
)                              {
  const created = await createSignatureInternal(
    message,
    requestedSignatureOptions(message, request, options),
  )
  created.assertUnchanged()
  return isRequest(message)
    ? appendSignature(message, created.fields)
    : appendSignature(message, created.fields)
}
























function snapshotStructuredFields(
  structuredFields                                      ,
)                                       {
  if (structuredFields === undefined) {
    return undefined
  }
  return Object.fromEntries(Object.entries(structuredFields))
}





function snapshotSignatureParameterInput(value                         )                          {
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
  parameters                                 ,
)                                  {
  if (parameters === undefined) {
    return undefined
  }
  return orderedParameterEntries(parameters).map(([name, value]) => [
    name,
    snapshotSignatureParameterInput(value),
  ])
}


function snapshotFetchWrapperSignOptions(
  options                              ,
)                               {
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


function snapshotFetchWrapperVerifyOptions(
  options                                ,
)                                 {
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


function resolveFetchImplementation(
  options                                               ,
)                          {
  const implementation = options.fetch ?? globalThis.fetch
  if (typeof implementation !== 'function') {
    fail('"options.fetch" must be a Fetch implementation')
  }
  return implementation
}










function createFetchRequest(input                   , init              )          {
  let request = new Request(input, init)
  if (request.redirect === 'follow') {
    request = new Request(request, {
      redirect: 'manual',
      referrer: request.referrer,
      referrerPolicy: request.referrerPolicy,
    })
  }
  return request
}


const STANDARD_REQUEST_INIT = new Set([
  'body',
  'cache',
  'credentials',
  'duplex',
  'headers',
  'integrity',
  'keepalive',
  'method',
  'mode',
  'priority',
  'redirect',
  'referrer',
  'referrerPolicy',
  'signal',
  'window',
])








const RUNTIME_FETCH_OPTIONS = [

  'cf',

  'client',

  'dispatcher',

  'decompress',
  'protocol',
  'proxy',
  's3',
  'tls',
  'unix',
  'verbose',
]







function findInitMember(source        , name        )                                 {
  for (
    let current                = source;
    current !== null;
    current = Object.getPrototypeOf(current)
  ) {
    const descriptor = Object.getOwnPropertyDescriptor(current, name)
    if (descriptor !== undefined) {
      return descriptor
    }
  }
  return undefined
}









































function runtimeFetchOptions(request         , init              )                          {

  if (init === null || (typeof init !== 'object' && typeof init !== 'function')) {
    return undefined
  }

  const source = init                           


  let forwarded                                     
  const carry = (name        , descriptor                    ) => {
    forwarded ??= Object.create(null)                           
    Object.defineProperty(
      forwarded,
      name,


      Object.hasOwn(descriptor, 'value')
        ? { configurable: true, enumerable: true, value: descriptor.value, writable: true }
        : { configurable: true, enumerable: true, get: () => source[name] },
    )
  }
  const handled = new Set        ()


  for (const name of Object.keys(source)) {
    handled.add(name)



    if (STANDARD_REQUEST_INIT.has(name) || name === '__proto__') {
      continue
    }
    const descriptor = Object.getOwnPropertyDescriptor(source, name)
    if (descriptor !== undefined) {
      carry(name, descriptor)
    }
  }





  for (const name of RUNTIME_FETCH_OPTIONS) {
    if (handled.has(name)) {
      continue
    }
    const descriptor = findInitMember(source, name)
    if (descriptor !== undefined) {
      carry(name, descriptor)
    }
  }

  if (forwarded === undefined) {
    return undefined
  }
  forwarded['referrer'] = request.referrer
  forwarded['referrerPolicy'] = request.referrerPolicy
  return forwarded               
}









function settleBeforeAbort   (
  operation                  ,
  signal                    ,
  onLoss                                 ,
)             {


  if (signal?.aborted) {
    return Promise.reject(signal.reason)
  }
  const pending = operation()
  if (signal === null || signal === undefined) {
    return pending
  }



  const consume = () => {
    pending.then(
      (value) => onLoss?.(value),
      () => onLoss?.(undefined),
    )
  }




  if (signal.aborted) {
    consume()
    return Promise.reject(signal.reason)
  }

  return new Promise   ((resolve, reject) => {
    const onAbort = () => {
      consume()
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
    pending.then(
      (value) => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      (error         ) => {
        signal.removeEventListener('abort', onAbort)
        reject(error         )
      },
    )
  })
}









function cancelUndeliveredBody(message                    )       {
  try {
    const { body } = message



    if (body !== null && !body.locked) {



      void body.cancel().catch(() => {})
    }
  } catch {}
}




























































export function createSigningFetch(options                     )                          {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = resolveFetchImplementation(options)
  const signOptions = snapshotFetchWrapperSignOptions(options.sign)

  return async (input                   , init              )                    => {
    const request = createFetchRequest(input, init)
    const forwarded = runtimeFetchOptions(request, init)
    let signedRequest         
    try {
      signedRequest = await settleBeforeAbort(
        () => sign(request, signOptions),
        request.signal,
        (signed) => {
          if (signed !== undefined) {
            cancelUndeliveredBody(signed)
          }
        },
      )
    } catch (error) {
      cancelUndeliveredBody(request)
      throw error
    }
    return forwarded === undefined
      ? implementation(signedRequest)
      : implementation(signedRequest, forwarded)
  }
}













































export function createVerifyingFetch(options                       )                          {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = resolveFetchImplementation(options)
  const verifyOptions = snapshotFetchWrapperVerifyOptions(options.verify)

  return async (input                   , init              )                    => {
    const request = createFetchRequest(input, init)
    const forwarded = runtimeFetchOptions(request, init)
    const response =
      forwarded === undefined
        ? await implementation(request)
        : await implementation(request, forwarded)
    try {
      await settleBeforeAbort(
        () => verify(response, { ...verifyOptions, request }),
        request.signal,
        () => cancelUndeliveredBody(response),
      )
    } catch (error) {
      cancelUndeliveredBody(response)
      throw error
    }
    return response
  }
}
















































export function createSignedFetch(options                    )                          {
  if (options === null || typeof options !== 'object') {
    fail('"options" must be an object')
  }
  const implementation = resolveFetchImplementation(options)
  const signOptions = snapshotFetchWrapperSignOptions(options.sign)
  const verifyOptions =
    options.verify === undefined ? undefined : snapshotFetchWrapperVerifyOptions(options.verify)

  return async (input                   , init              )                    => {
    const request = createFetchRequest(input, init)
    const forwarded = runtimeFetchOptions(request, init)
    let signedRequest         
    try {
      signedRequest = await settleBeforeAbort(
        () => sign(request, signOptions),
        request.signal,
        (signed) => {
          if (signed !== undefined) {
            cancelUndeliveredBody(signed)
          }
        },
      )
    } catch (error) {
      cancelUndeliveredBody(request)
      throw error
    }
    const response =
      forwarded === undefined
        ? await implementation(signedRequest)
        : await implementation(signedRequest, forwarded)
    if (verifyOptions !== undefined) {
      try {
        await settleBeforeAbort(
          () => verify(response, { ...verifyOptions, request: signedRequest }),
          signedRequest.signal,
          () => cancelUndeliveredBody(response),
        )
      } catch (error) {
        cancelUndeliveredBody(response)
        throw error
      }
    }
    return response
  }
}
