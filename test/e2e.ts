import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from 'node:http'
import { after, before, describe, it } from 'node:test'

import {
  appendAcceptSignature,
  component,
  createSigningFetch,
  createSignedFetch,
  getSignatureRequests,
  signRequested,
  verify,
} from '../index.ts'
import type { ComponentIdentifier, SignatureRequest } from '../index.ts'
import { RFC_CREATED, verificationPolicy, webCryptoSigner, webCryptoVerifier } from './support.ts'

const requestComponents: ReadonlyArray<ComponentIdentifier> = [
  '@method',
  '@target-uri',
  '@authority',
  '@path',
  '@query',
  'content-type',
  'content-digest',
  'x-request-id',
  'accept-signature',
]

const responseComponents: ReadonlyArray<ComponentIdentifier> = [
  '@status',
  'content-type',
  'content-digest',
  'x-response-id',
  component('@method', { req: true }),
  component('@authority', { req: true }),
  component('@path', { req: true }),
  component('x-request-id', { req: true }),
  component('accept-signature', { req: true }),
]

function contentDigest(content: string): string {
  const digest = createHash('sha256').update(content).digest('base64')
  return `sha-256=:${digest}:`
}

function fetchHeaders(source: IncomingHttpHeaders): Headers {
  const headers = new Headers()
  for (const [name, value] of Object.entries(source)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        headers.append(name, item)
      }
    } else if (value !== undefined) {
      headers.append(name, value)
    }
  }
  return headers
}

async function toFetchRequest(message: IncomingMessage, origin: string): Promise<Request> {
  const chunks: Buffer[] = []
  for await (const chunk of message) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  const method = message.method ?? 'GET'
  const init: RequestInit & { duplex?: 'half' } = { method, headers: fetchHeaders(message.headers) }
  if (method !== 'GET' && method !== 'HEAD') {
    init.body = Buffer.concat(chunks).toString()
    init.duplex = 'half'
  }
  return new Request(`${origin}${message.url ?? '/'}`, init)
}

async function sendFetchResponse(
  target: ServerResponse,
  response: Response,
  mutateHeaders?: (headers: Headers) => void,
): Promise<void> {
  const headers = new Headers(response.headers)
  mutateHeaders?.(headers)
  target.statusCode = response.status
  target.statusMessage = response.statusText
  for (const [name, value] of headers) {
    target.setHeader(name, value)
  }
  target.end(Buffer.from(await response.arrayBuffer()))
}

function sendJson(target: ServerResponse, status: number, body: unknown): void {
  const value = JSON.stringify(body)
  target.statusCode = status
  target.setHeader('content-type', 'application/json')
  target.setHeader('content-length', Buffer.byteLength(value))
  target.end(value)
}

describe('end-to-end signatures through a local HTTP server', () => {
  let server: Server
  let origin: string

  before(async () => {
    server = createServer((incoming, outgoing) => {
      void (async () => {
        const request = await toFetchRequest(incoming, origin)
        try {
          await verify(request, {
            verifier: webCryptoVerifier(undefined, 'client-key'),
            policy: verificationPolicy({
              requiredComponents: requestComponents,
              requiredParameters: ['created', 'keyid', 'alg', 'nonce'],
              maxAge: 60,
            }),
          })
        } catch (error) {
          sendJson(outgoing, 401, {
            error: error instanceof Error ? error.message : 'request verification failed',
          })
          return
        }

        const body = await request.clone().text()
        if (request.headers.get('content-digest') !== contentDigest(body)) {
          sendJson(outgoing, 422, { error: 'content digest mismatch' })
          return
        }

        const signatureRequest = getSignatureRequests(request)[0]
        if (signatureRequest === undefined) {
          sendJson(outgoing, 400, { error: 'Accept-Signature is required' })
          return
        }

        const responseBody = JSON.stringify({
          ok: true,
          requestId: request.headers.get('x-request-id'),
        })
        const response = new Response(responseBody, {
          status: 201,
          headers: {
            'content-type': 'application/json',
            'content-digest': contentDigest(responseBody),
            'x-response-id': 'response-456',
          },
        })

        if (new URL(request.url).pathname === '/unsigned-response') {
          await sendFetchResponse(outgoing, response)
          return
        }

        let relatedRequest = request
        if (new URL(request.url).pathname === '/wrong-related-request') {
          relatedRequest = new Request(`${origin}/different-path`, {
            method: request.method,
            headers: request.headers,
          })
        }
        const signedResponse = await signRequested(response, signatureRequest, {
          request: relatedRequest,
          signer: webCryptoSigner(),
          parameters: { keyid: 'server-key' },
          now: RFC_CREATED,
        })

        switch (new URL(request.url).pathname) {
          case '/tampered-response-header':
            await sendFetchResponse(outgoing, signedResponse, (headers) => {
              headers.set('x-response-id', 'attacker-controlled')
            })
            break
          case '/tampered-response-signature':
            await sendFetchResponse(outgoing, signedResponse, (headers) => {
              const value = headers.get('signature')!
              headers.set(
                'signature',
                value.replace(/=:([A-Za-z0-9+/])/, (_, character: string) =>
                  character === 'A' ? '=:B' : '=:A',
                ),
              )
            })
            break
          default:
            await sendFetchResponse(outgoing, signedResponse)
        }
      })().catch((error) => {
        if (!outgoing.headersSent) {
          sendJson(outgoing, 500, {
            error: error instanceof Error ? error.message : 'server failure',
          })
        } else {
          outgoing.destroy(error instanceof Error ? error : undefined)
        }
      })
    })
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject)
        const address = server.address()
        assert.ok(address && typeof address === 'object')
        origin = `http://127.0.0.1:${address.port}`
        resolve()
      })
    })
  })

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error)
        } else {
          resolve()
        }
      })
    })
  })

  function message(path: string): Request {
    const body = JSON.stringify({ hello: 'network' })
    const request = new Request(`${origin}${path}?Pet=dog`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-digest': contentDigest(body),
        'x-request-id': 'request-123',
      },
      body,
    })
    return appendAcceptSignature(request, [
      {
        label: 'server',
        components: responseComponents,
        parameters: {
          created: true,
          alg: 'hmac-sha256',
          keyid: 'server-key',
          nonce: 'server-challenge',
        },
      },
    ])
  }

  function options(fetchImplementation: typeof fetch = fetch) {
    return {
      sign: {
        signer: webCryptoSigner(),
        components: requestComponents,
        parameters: {
          created: RFC_CREATED,
          alg: 'hmac-sha256',
          keyid: 'client-key',
          nonce: 'client-once',
        },
        label: 'client',
      },
      verify: {
        verifier: webCryptoVerifier(undefined, 'server-key'),
        policy: verificationPolicy({
          requiredComponents: responseComponents,
          requiredParameters: ['created', 'alg', 'keyid', 'nonce'],
          maxAge: 60,
        }),
      },
      fetch: fetchImplementation,
    } as const
  }

  it('signs a real request, verifies it server-side, fulfills Accept-Signature, and verifies the response', async () => {
    const response = await createSignedFetch(options())(message('/success'))

    assert.equal(response.status, 201)
    const body = await response.text()
    assert.deepEqual(JSON.parse(body), { ok: true, requestId: 'request-123' })
    assert.equal(response.headers.get('content-digest'), contentDigest(body))
    assert.ok(response.headers.has('signature-input'))
    assert.ok(response.headers.has('signature'))
  })

  it('rejects a covered request header changed after signing', async () => {
    const tamperingFetch: typeof fetch = async (input) => {
      const signed = input as Request
      const headers = new Headers(signed.headers)
      headers.set('x-request-id', 'attacker-controlled')
      return fetch(new Request(signed, { headers }))
    }
    const response = await createSigningFetch({ sign: options().sign, fetch: tamperingFetch })(
      message('/request-header-tamper'),
    )

    assert.equal(response.status, 401)
    assert.match(await response.text(), /signature verification failed/i)
  })

  it('requires application content-digest checking to catch body substitution', async () => {
    const tamperingFetch: typeof fetch = async (input) => {
      const signed = input as Request
      const body = `${await signed.text()} attacker data`
      return fetch(
        new Request(signed.url, {
          method: signed.method,
          headers: signed.headers,
          body,
          redirect: signed.redirect,
        }),
      )
    }
    const response = await createSigningFetch({ sign: options().sign, fetch: tamperingFetch })(
      message('/request-body-tamper'),
    )

    assert.equal(response.status, 422)
    assert.match(await response.text(), /content digest mismatch/)
  })

  it('rejects a covered response header changed after signing', async () => {
    await assert.rejects(
      createSignedFetch(options())(message('/tampered-response-header')),
      /HTTP message signature verification failed/,
    )
  })

  it('rejects a corrupted response signature value', async () => {
    await assert.rejects(
      createSignedFetch(options())(message('/tampered-response-signature')),
      /HTTP message signature verification failed/,
    )
  })

  it('rejects a response signed against a different related request', async () => {
    await assert.rejects(
      createSignedFetch(options())(message('/wrong-related-request')),
      /HTTP message signature verification failed/,
    )
  })

  it('rejects an unsigned response when verification is configured', async () => {
    await assert.rejects(
      createSignedFetch(options())(message('/unsigned-response')),
      /Message does not contain an HTTP message signature/,
    )
  })

  it('exposes the requested response signature to the server as a parsed request', () => {
    const requests = getSignatureRequests(message('/inspect'))
    assert.equal(requests.length, 1)
    const request: SignatureRequest = requests[0]!
    assert.equal(request.label, 'server')
    assert.deepEqual(request.components, responseComponents.map(normalizeForAssertion))
  })
})

function normalizeForAssertion(componentValue: ComponentIdentifier) {
  return typeof componentValue === 'string'
    ? { name: componentValue, parameters: [] }
    : {
        name: componentValue.name,
        parameters: Array.isArray(componentValue.parameters)
          ? componentValue.parameters
          : Object.entries(componentValue.parameters ?? {}),
      }
}
