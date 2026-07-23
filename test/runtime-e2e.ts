import { describe, it } from 'node:test'

import {
  appendAcceptSignature,
  component,
  createSignedFetch,
  ed25519Signer,
  ed25519Verifier,
  generateEd25519KeyPair,
  getSignatureRequests,
  signRequested,
  verify,
} from '../index.ts'
import type {
  ComponentIdentifier,
  MessageSignature,
  SignatureParameterValue,
  VerifierFactory,
} from '../index.ts'

type FetchHandler = (request: Request) => Response | Promise<Response>

interface DenoServer {
  readonly addr: { readonly hostname: string; readonly port: number }
  shutdown(): Promise<void>
}

interface DenoRuntime {
  serve(
    options: { readonly hostname: string; readonly port: number; readonly onListen: () => void },
    handler: FetchHandler,
  ): DenoServer
}

interface BunServer {
  readonly url: URL
  stop(closeActiveConnections?: boolean): void | Promise<void>
}

interface BunRuntime {
  serve(options: {
    readonly hostname: string
    readonly port: number
    readonly fetch: FetchHandler
  }): BunServer
}

const runtime = globalThis as typeof globalThis & {
  readonly Deno?: DenoRuntime
  readonly Bun?: BunRuntime
  readonly process?: { readonly versions?: { readonly node?: string } }
}

const requestComponents: ReadonlyArray<ComponentIdentifier> = [
  '@method',
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

function assertion(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message)
  }
}

function parameter(
  signature: Readonly<MessageSignature>,
  name: string,
): SignatureParameterValue | undefined {
  return signature.parameters.find(([parameterName]) => parameterName === name)?.[1]
}

function verifierForKey(
  key: CryptoKey,
  expectedKeyId: string,
  onVerified: () => void,
): VerifierFactory {
  const verifier = ed25519Verifier(key)
  return (signature, context) => {
    assertion(
      parameter(signature, 'keyid') === expectedKeyId,
      `expected signature keyid "${expectedKeyId}"`,
    )
    const selected = verifier(signature, context)
    return {
      ...selected,
      async verify(data, value) {
        const valid = await selected.verify(data, value)
        if (valid) {
          onVerified()
        }
        return valid
      },
    }
  }
}

function base64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

async function contentDigest(content: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content))
  return `sha-256=:${base64(new Uint8Array(digest))}:`
}

function describeError(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error)
}

async function nativeEndToEnd(
  startServer: (handler: FetchHandler) => Promise<string>,
): Promise<void> {
  const [clientKeys, serverKeys] = await Promise.all([
    generateEd25519KeyPair(),
    generateEd25519KeyPair(),
  ])

  assertion(!clientKeys.privateKey.extractable, 'client private key must not be extractable')
  assertion(!serverKeys.privateKey.extractable, 'server private key must not be extractable')

  let requestVerified = false
  let responseSigned = false
  let responseVerified = false
  let serverFailure: unknown

  const clientVerifier = verifierForKey(clientKeys.publicKey, 'client-key', () => {
    requestVerified = true
  })
  const serverVerifier = verifierForKey(serverKeys.publicKey, 'server-key', () => {
    responseVerified = true
  })

  const origin = await startServer(async (request) => {
    try {
      await verify(request, {
        verifier: clientVerifier,
        policy: {
          requiredComponents: requestComponents,
          requiredParameters: ['created', 'keyid', 'alg', 'nonce'],
          algorithms: ['ed25519'],
          maxAge: 60,
        },
      })

      const requestBody = await request.clone().text()
      assertion(
        request.headers.get('content-digest') === (await contentDigest(requestBody)),
        'request Content-Digest does not match its body',
      )

      const signatureRequest = getSignatureRequests(request)[0]
      assertion(signatureRequest !== undefined, 'request does not contain Accept-Signature')

      const responseBody = JSON.stringify({
        ok: true,
        requestId: request.headers.get('x-request-id'),
      })
      const response = new Response(responseBody, {
        status: 201,
        headers: {
          'content-type': 'application/json',
          'content-digest': await contentDigest(responseBody),
          'x-response-id': 'response-456',
        },
      })
      const signedResponse = await signRequested(response, signatureRequest, {
        request,
        signer: ed25519Signer(serverKeys.privateKey),
        parameters: { keyid: 'server-key' },
      })
      responseSigned = true
      return signedResponse
    } catch (error) {
      serverFailure = error
      return new Response(JSON.stringify({ error: describeError(error) }), {
        status: 500,
        headers: { 'content-type': 'application/json' },
      })
    }
  })

  const requestBody = JSON.stringify({ hello: 'native Fetch server' })
  const unsignedRequest = new Request(`${origin}/orders/123?mode=runtime`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'content-digest': await contentDigest(requestBody),
      'x-request-id': 'request-123',
    },
    body: requestBody,
  })
  const request = appendAcceptSignature(unsignedRequest, [
    {
      label: 'server',
      components: responseComponents,
      parameters: { created: true, alg: 'ed25519', keyid: 'server-key', nonce: 'server-challenge' },
    },
  ])

  const signedFetch = createSignedFetch({
    sign: {
      signer: ed25519Signer(clientKeys.privateKey),
      components: requestComponents,
      parameters: { alg: 'ed25519', keyid: 'client-key', nonce: 'client-once' },
      label: 'client',
    },
    verify: {
      verifier: serverVerifier,
      policy: {
        requiredComponents: responseComponents,
        requiredParameters: ['created', 'keyid', 'alg', 'nonce'],
        algorithms: ['ed25519'],
        maxAge: 60,
      },
    },
  })

  let response: Response
  try {
    response = await signedFetch(request)
  } catch (error) {
    if (serverFailure !== undefined) {
      throw new Error(`native server failed: ${describeError(serverFailure)}`, {
        cause: serverFailure,
      })
    }
    throw error
  }

  if (serverFailure !== undefined) {
    throw new Error(`native server failed: ${describeError(serverFailure)}`, {
      cause: serverFailure,
    })
  }

  assertion(response.status === 201, `expected response status 201, received ${response.status}`)
  assertion(requestVerified, 'server did not verify the signed request')
  assertion(responseSigned, 'server did not sign its response')
  assertion(responseVerified, 'client did not verify the signed response')
  assertion(response.headers.has('signature-input'), 'response is missing Signature-Input')
  assertion(response.headers.has('signature'), 'response is missing Signature')

  const responseBody = await response.text()
  assertion(
    response.headers.get('content-digest') === (await contentDigest(responseBody)),
    'response Content-Digest does not match its body',
  )
  const payload = JSON.parse(responseBody) as { ok?: unknown; requestId?: unknown }
  assertion(payload.ok === true, 'response payload does not contain ok: true')
  assertion(payload.requestId === 'request-123', 'response payload has the wrong request ID')
}

const deno = runtime.Deno
const bun = runtime.Bun
const node =
  deno === undefined && bun === undefined && typeof runtime.process?.versions?.node === 'string'
const runtimeName =
  deno === undefined ? (bun === undefined ? (node ? 'Node' : undefined) : 'Bun') : 'Deno'

async function nodeEndToEnd(overrideGlobalObjects: boolean): Promise<void> {
  const requestConstructor = globalThis.Request
  const responseConstructor = globalThis.Response
  const { serve } = await import('@hono/node-server')
  let server: ReturnType<typeof serve> | undefined

  try {
    await nativeEndToEnd(
      (handler) =>
        new Promise<string>((resolve, reject) => {
          const onError = (error: Error) => {
            server?.off('error', onError)
            reject(error)
          }
          server = serve(
            { fetch: handler, hostname: '127.0.0.1', port: 0, overrideGlobalObjects },
            ({ port }) => {
              server?.off('error', onError)
              resolve(`http://127.0.0.1:${port}`)
            },
          )
          server.once('error', onError)

          if (overrideGlobalObjects) {
            assertion(
              globalThis.Request !== requestConstructor,
              'Request global was not overridden',
            )
            assertion(
              globalThis.Response !== responseConstructor,
              'Response global was not overridden',
            )
          } else {
            assertion(globalThis.Request === requestConstructor, 'Request global was overridden')
            assertion(globalThis.Response === responseConstructor, 'Response global was overridden')
          }
        }),
    )
  } finally {
    if (server !== undefined) {
      await new Promise<void>((resolve, reject) => {
        server!.close((error) => {
          if (error) {
            reject(error)
          } else {
            resolve()
          }
        })
      })
    }
  }
}

describe('native Request/Response server end-to-end', () => {
  if (node) {
    it('Node verifies a request and returns a signed response', async (context) => {
      await context.test('without overriding Fetch globals', () => nodeEndToEnd(false))
      await context.test('with overridden Fetch globals', () => nodeEndToEnd(true))
    })
    return
  }

  it(
    `${runtimeName ?? 'unsupported runtime'} verifies a request and returns a signed response`,
    { skip: runtimeName === undefined },
    async () => {
      if (deno !== undefined) {
        let server: DenoServer | undefined
        try {
          await nativeEndToEnd(async (handler) => {
            server = deno.serve({ hostname: '127.0.0.1', port: 0, onListen() {} }, handler)
            return `http://${server.addr.hostname}:${server.addr.port}`
          })
        } finally {
          await server?.shutdown()
        }
        return
      }

      assertion(bun !== undefined, 'native Fetch server runtime is unavailable')
      let server: BunServer | undefined
      try {
        await nativeEndToEnd(async (handler) => {
          server = bun.serve({ hostname: '127.0.0.1', port: 0, fetch: handler })
          return server.url.origin
        })
      } finally {
        await server?.stop()
      }
    },
  )
})
