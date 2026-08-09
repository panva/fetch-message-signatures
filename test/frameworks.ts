// Proves the message descriptor against the server shapes it exists for.
//
// Every case runs a real server, sends a real signed request over the loopback interface, verifies
// it inside the handler, signs the response, and verifies that response on the client. Nothing here
// constructs a Fetch `Request` or `Response` on the server side: each handler builds a plain
// descriptor out of whatever its framework happens to expose.
//
// Node.js only, because it starts servers. It is deliberately absent from test/runners/suite.ts.

import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { after, describe, it } from 'node:test'

import {
  component,
  createSignature,
  ed25519Signer,
  ed25519Verifier,
  generateEd25519KeyPair,
  sign,
  verify,
} from '../index.ts'
import type { SignableRequest, SignatureFields, SignerFactory, VerifierFactory } from '../index.ts'

const { privateKey, publicKey } = await generateEd25519KeyPair()
const signer: SignerFactory = ed25519Signer(privateKey)
const verifier: VerifierFactory = ed25519Verifier(publicKey)

const REQUEST_COMPONENTS = ['@method', '@authority', '@path', '@query', 'content-type']
const RESPONSE_COMPONENTS = ['@status', component('@authority', { req: true })]

function now(): number {
  return Math.floor(Date.now() / 1000)
}

/** The two field values a handler attaches to its response, however its framework spells that. */
async function signResponse(request: SignableRequest, status: number): Promise<SignatureFields> {
  return createSignature(
    { status, headers: { 'content-type': 'text/plain' } },
    {
      signer,
      request,
      components: RESPONSE_COMPONENTS,
      parameters: { created: now(), keyid: 'server-key', alg: 'ed25519' },
    },
  )
}

/**
 * The whole server side, sharing one descriptor shape across every framework.
 *
 * A handler supplies the four values it can reach and a way to reply. Nothing framework-specific
 * reaches this function, which is the point being tested.
 */
async function handle(
  descriptor: SignableRequest,
  reply: (status: number, headers: Record<string, string>, body: string) => void,
): Promise<void> {
  let verified
  try {
    verified = await verify(descriptor, {
      verifier,
      policy: {
        requiredComponents: REQUEST_COMPONENTS,
        requiredParameters: ['created', 'keyid'],
        algorithms: ['ed25519'],
        maxAge: 60,
      },
    })
  } catch (error) {
    reply(401, { 'content-type': 'text/plain' }, (error as Error).message)
    return
  }

  const fields = await signResponse(descriptor, 200)
  reply(
    200,
    {
      'content-type': 'text/plain',
      'signature-input': fields.signatureInput,
      signature: fields.signatureField,
    },
    verified.label,
  )
}

/** Signs an outgoing request the way a client would, and returns it as headers plus a body. */
async function clientRequest(url: string): Promise<{ headers: Headers; body: string }> {
  const signed = await sign(
    new Request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"ok":true}',
    }),
    {
      signer,
      components: REQUEST_COMPONENTS,
      parameters: { created: now(), keyid: 'client-key', alg: 'ed25519' },
    },
  )
  return { headers: signed.headers, body: '{"ok":true}' }
}

const servers: Server[] = []
after(() => {
  for (const server of servers) {
    server.closeAllConnections()
    server.close()
  }
})

function port(server: Server): number {
  const address = server.address()
  assert.ok(address !== null && typeof address === 'object')
  return address.port
}

/** Drives one server end to end and asserts both directions verified. */
async function roundTrip(server: Server): Promise<void> {
  servers.push(server)
  const url = `http://127.0.0.1:${port(server)}/orders?page=2`
  const { headers, body } = await clientRequest(url)

  const response = await fetch(url, { method: 'POST', headers, body })
  const text = await response.text()
  assert.equal(response.status, 200, text)
  assert.equal(text, 'sig1')

  // The response carries its own signature, bound to the request that produced it.
  const verified = await verify(response, {
    verifier,
    request: new Request(url, { method: 'POST' }),
    policy: {
      requiredComponents: RESPONSE_COMPONENTS,
      requiredParameters: ['created', 'keyid'],
      algorithms: ['ed25519'],
      maxAge: 60,
    },
  })
  assert.equal(verified.algorithm, 'ed25519')
}

/** Resolves once a server is accepting connections, whichever way its framework starts one. */
function started(listen: (done: () => void) => Server): Promise<Server> {
  return new Promise((resolve) => {
    const server = listen(() => resolve(server))
  })
}

describe('server frameworks without Request and Response', () => {
  it('node:http', async () => {
    const server = createServer((request, response) => {
      void handle(
        {
          method: request.method!,
          url: `http://${request.headers.host}${request.url}`,
          headers: request.headers,
        },
        (status, headers, body) => {
          response.writeHead(status, headers)
          response.end(body)
        },
      )
    })
    await roundTrip(await started((done) => server.listen(0, '127.0.0.1', done)))
  })

  it('express', async () => {
    const { default: express } = await import('express')
    const app = express()
    app.post('*splat', (request, response) => {
      void handle(
        {
          method: request.method,
          url: `http://${request.headers.host}${request.originalUrl}`,
          headers: request.headers,
        },
        (status, headers, body) => response.status(status).set(headers).send(body),
      )
    })
    await roundTrip(await started((done) => app.listen(0, '127.0.0.1', done) as unknown as Server))
  })

  it('koa', async () => {
    const { default: Koa } = await import('koa')
    const app = new Koa()
    app.use(async (context) => {
      await handle(
        {
          method: context.method,
          url: `http://${context.host}${context.originalUrl}`,
          headers: context.headers,
        },
        (status, headers, body) => {
          context.status = status
          context.set(headers)
          context.body = body
        },
      )
    })
    await roundTrip(await started((done) => app.listen(0, '127.0.0.1', done) as unknown as Server))
  })

  it('fastify', async () => {
    const { default: Fastify } = await import('fastify')
    const app = Fastify()
    app.post('/*', (request, reply) =>
      handle(
        {
          method: request.method,
          url: `http://${request.headers.host}${request.url}`,
          headers: request.headers,
        },
        (status, headers, body) => {
          void reply.code(status).headers(headers).send(body)
        },
      ),
    )
    await app.listen({ port: 0, host: '127.0.0.1' })
    await roundTrip(app.server)
  })
})
