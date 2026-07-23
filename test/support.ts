import assert from 'node:assert/strict'

import type {
  MessageSignature,
  SignerFactory,
  VerificationPolicy,
  VerifierFactory,
} from '../index.ts'

/** Decodes padded standard base64 using only globals that every target runtime provides. */
export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

/** Encodes padded standard base64 using only globals that every target runtime provides. */
export function bytesToBase64(value: Uint8Array): string {
  let binary = ''
  for (const byte of value) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/**
 * Converts a PEM document to the DER bytes that `SubtleCrypto.importKey()` takes.
 *
 * The tests carry the RFC 9421 example keys in PEM because that is how the RFC publishes them, and
 * unwrapping them here keeps the suite free of `node:crypto` so it can also run in browsers and
 * Cloudflare Workers.
 */
export function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  return base64ToBytes(pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s+/g, ''))
}

export const RFC_CREATED = 1_618_884_473
export const RFC_SHARED_SECRET = base64ToBytes(
  'uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==',
)
export const RFC_HMAC_SIGNATURE = base64ToBytes('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=')

export const RFC_REQUEST_BASE = [
  '"date": Tue, 20 Apr 2021 02:07:55 GMT',
  '"@authority": example.com',
  '"content-type": application/json',
  '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
].join('\n')

const RFC_REQUEST_URL = 'https://example.com/foo?param=Value&Pet=dog'
const RFC_REQUEST_HEADERS = {
  'content-digest':
    'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
  'content-length': '18',
  'content-type': 'application/json',
  date: 'Tue, 20 Apr 2021 02:07:55 GMT',
} as const

/**
 * Reports whether this runtime lets script put every RFC 9421 example field on a `Request`.
 *
 * `Date` and `Content-Length` are forbidden header names, so a browser silently drops them from a
 * `Request` built by page script. A standalone `Headers` object has no guard and keeps them, which
 * is how the fixtures below stay usable in a browser.
 */
const requestKeepsForbiddenHeaders = /* @__PURE__ */ (() => {
  try {
    return new Request('https://example.com/', { headers: { date: 'x' } }).headers.has('date')
  } catch {
    return false
  }
})()

/**
 * Whether script can build a `Request` carrying every RFC 9421 example field.
 *
 * Browsers treat `Date` and `Content-Length` as forbidden header names and drop them from a request
 * built by page script. {@link fixtureRequest} works around that with an unguarded `Headers` on a
 * structural message, but a structural message is not a `Request`, so anything that passes it back
 * through the `Request` constructor cannot use it. Signing and appending do exactly that, so the
 * few cases that both cover a forbidden field and rebuild the message check this first.
 *
 * The limitation is the browser's, not this package's, and is documented in guides/fetch.md.
 */
export const REQUEST_CARRIES_FORBIDDEN_FIELDS = /* @__PURE__ */ (() =>
  requestKeepsForbiddenHeaders)()

/**
 * Builds a request fixture, keeping the fields a runtime would otherwise drop.
 *
 * The signature layer reads a message structurally, so where `Request` refuses to carry a covered
 * field the fixture becomes a plain object with an unguarded `Headers` instead. Use
 * {@link withRequestFields} rather than `new Request(fixture, ...)` to add fields to one, because
 * the fallback is not a `Request` and the constructor would treat it as a URL.
 */
export function fixtureRequest(
  url: string,
  init: { method?: string; headers?: HeadersInit; body?: string } = {},
): Request {
  if (requestKeepsForbiddenHeaders) {
    return new Request(url, init as RequestInit)
  }
  return { method: init.method ?? 'GET', url, headers: new Headers(init.headers) } as Request
}

/** Returns a copy of a request fixture carrying additional fields, preserving the fixture's kind. */
export function withRequestFields(
  request: Request,
  fields: Readonly<Record<string, string>>,
): Request {
  const headers = new Headers(request.headers)
  for (const [name, value] of Object.entries(fields)) {
    headers.set(name, value)
  }
  if (requestKeepsForbiddenHeaders) {
    return new Request(request, { headers })
  }
  return { method: request.method, url: request.url, headers } as Request
}

export function rfcRequest(): Request {
  return fixtureRequest(RFC_REQUEST_URL, {
    method: 'POST',
    headers: RFC_REQUEST_HEADERS,
    body: '{"hello": "world"}',
  })
}

export function rfcResponse(status = 200): Response {
  return new Response('{"message": "good dog"}', {
    status,
    headers: {
      'content-digest':
        'sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:',
      'content-length': '23',
      'content-type': 'application/json',
      date: 'Tue, 20 Apr 2021 02:07:56 GMT',
    },
  })
}

function signatureParameter(signature: Readonly<MessageSignature>, name: string): unknown {
  return signature.parameters.find(([candidate]) => candidate === name)?.[1]
}

function assertExpectedKey(
  signature: Readonly<MessageSignature>,
  expectedKeyId: string | undefined,
): void {
  if (expectedKeyId !== undefined) {
    assert.equal(signatureParameter(signature, 'keyid'), expectedKeyId)
  }
}

function webCryptoHmac(secret: Uint8Array<ArrayBuffer>): {
  sign(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array>
  verify(data: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>): Promise<boolean>
} {
  const key = crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ])
  return {
    async sign(data) {
      return new Uint8Array(await crypto.subtle.sign('HMAC', await key, data))
    },
    async verify(data, signature) {
      return crypto.subtle.verify('HMAC', await key, signature, data)
    },
  }
}

export function webCryptoSigner(
  secret: Uint8Array<ArrayBuffer> = RFC_SHARED_SECRET,
  alg = 'hmac-sha256',
): SignerFactory {
  const hmac = webCryptoHmac(secret)
  return () => ({
    type: 'signer',
    alg,
    async sign(data) {
      return hmac.sign(data)
    },
  })
}

export function webCryptoVerifier(
  secret: Uint8Array<ArrayBuffer> = RFC_SHARED_SECRET,
  expectedKeyId?: string,
  alg = 'hmac-sha256',
): VerifierFactory {
  const hmac = webCryptoHmac(secret)
  return (signature) => {
    assertExpectedKey(signature, expectedKeyId)
    return {
      type: 'verifier',
      alg,
      async verify(data, value) {
        return hmac.verify(data, value)
      },
    }
  }
}

export function verificationPolicy(
  overrides: Partial<VerificationPolicy> = {},
): VerificationPolicy {
  return {
    requiredComponents: [],
    requiredParameters: [],
    algorithms: ['hmac-sha256'],
    now: RFC_CREATED,
    ...overrides,
  }
}

/**
 * Runs `body` with the optional `Uint8Array` base64 methods hidden, so that tests can exercise the
 * `btoa()`/`atob()` fallback the implementation uses on runtimes that lack them.
 *
 * `body` must be synchronous: the methods are restored as soon as it returns. The original property
 * descriptors are restored rather than reassigned, because both methods are non-enumerable.
 */
export function withoutUint8ArrayBase64<T>(body: () => T): T {
  const encode = Object.getOwnPropertyDescriptor(Uint8Array.prototype, 'toBase64')
  const decode = Object.getOwnPropertyDescriptor(Uint8Array, 'fromBase64')
  try {
    delete (Uint8Array.prototype as { toBase64?: unknown }).toBase64
    delete (Uint8Array as { fromBase64?: unknown }).fromBase64
    return body()
  } finally {
    if (encode !== undefined) {
      Object.defineProperty(Uint8Array.prototype, 'toBase64', encode)
    }
    if (decode !== undefined) {
      Object.defineProperty(Uint8Array, 'fromBase64', decode)
    }
  }
}
