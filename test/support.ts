import assert from 'node:assert/strict'
import { createHmac, timingSafeEqual, webcrypto } from 'node:crypto'

import type {
  MessageSignature,
  SignerFactory,
  VerificationPolicy,
  VerifierFactory,
} from '../index.ts'

export const RFC_CREATED = 1_618_884_473
export const RFC_SHARED_SECRET = new Uint8Array(
  Buffer.from(
    'uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==',
    'base64',
  ),
)
export const RFC_HMAC_SIGNATURE = new Uint8Array(
  Buffer.from('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=', 'base64'),
)

export const RFC_REQUEST_BASE = [
  '"date": Tue, 20 Apr 2021 02:07:55 GMT',
  '"@authority": example.com',
  '"content-type": application/json',
  '"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
].join('\n')

export function rfcRequest(): Request {
  return new Request('https://example.com/foo?param=Value&Pet=dog', {
    method: 'POST',
    headers: {
      'content-digest':
        'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
      'content-length': '18',
      'content-type': 'application/json',
      date: 'Tue, 20 Apr 2021 02:07:55 GMT',
    },
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

function webCryptoHmac(secret: Uint8Array): {
  sign(data: Uint8Array): Promise<Uint8Array>
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>
} {
  const key = webcrypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ])
  return {
    async sign(data) {
      return new Uint8Array(await webcrypto.subtle.sign('HMAC', await key, data))
    },
    async verify(data, signature) {
      return webcrypto.subtle.verify('HMAC', await key, signature, data)
    },
  }
}

export function webCryptoSigner(
  secret: Uint8Array = RFC_SHARED_SECRET,
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
  secret: Uint8Array = RFC_SHARED_SECRET,
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

function syncHmac(secret: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha256', secret).update(data).digest())
}

/** The provider method is Promise-based while the cryptographic primitive it adapts is synchronous. */
export function syncCryptoSigner(
  secret: Uint8Array = RFC_SHARED_SECRET,
  alg = 'hmac-sha256',
): SignerFactory {
  return () => ({
    type: 'signer',
    alg,
    async sign(data) {
      return syncHmac(secret, data)
    },
  })
}

/** The provider method is Promise-based while the cryptographic primitive it adapts is synchronous. */
export function syncCryptoVerifier(
  secret: Uint8Array = RFC_SHARED_SECRET,
  expectedKeyId?: string,
  alg = 'hmac-sha256',
): VerifierFactory {
  return (signature) => {
    assertExpectedKey(signature, expectedKeyId)
    return {
      type: 'verifier',
      alg,
      async verify(data, value) {
        const expected = syncHmac(secret, data)
        return expected.byteLength === value.byteLength && timingSafeEqual(expected, value)
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
