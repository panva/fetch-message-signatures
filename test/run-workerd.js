import {
  component,
  ecdsaP256Sha256Signer,
  ecdsaP256Sha256Verifier,
  generateEcdsaP256Sha256KeyPair,
  sign,
  verify,
} from 'fetch-message-signatures'

const algorithm = 'ecdsa-p256-sha256'
const created = 1_618_884_473

function assert(condition, message) {
  if (!condition) {
    throw new Error(message)
  }
}

function policy(requiredComponents) {
  return {
    requiredComponents,
    requiredParameters: ['created', 'alg', 'keyid'],
    algorithms: [algorithm],
    now: created,
  }
}

export default {
  async test() {
    const { privateKey, publicKey } = await generateEcdsaP256Sha256KeyPair()
    const signer = ecdsaP256Sha256Signer(privateKey)
    const verifier = ecdsaP256Sha256Verifier(publicKey)

    const requestComponents = ['@method', '@authority', '@path', 'content-type']
    const request = new Request('https://worker.example/messages/1', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"hello":"workerd"}',
    })
    const signedRequest = await sign(request, {
      signer,
      components: requestComponents,
      parameters: { created, alg: algorithm, keyid: 'workerd-test-key' },
    })

    assert(request.headers.get('signature') === null, 'signing changed the source request')
    assert(signedRequest.headers.has('signature-input'), 'signed request has no Signature-Input')
    assert(signedRequest.headers.has('signature'), 'signed request has no Signature')

    const verifiedRequest = await verify(signedRequest, {
      verifier,
      policy: policy(requestComponents),
    })
    assert(verifiedRequest.algorithm === algorithm, 'request used an unexpected algorithm')

    const responseComponents = [
      '@status',
      'content-type',
      component('@method', { req: true }),
      component('@path', { req: true }),
    ]
    const response = new Response('{"accepted":true}', {
      status: 202,
      headers: { 'content-type': 'application/json' },
    })
    const signedResponse = await sign(response, {
      request: signedRequest,
      signer,
      components: responseComponents,
      parameters: { created, alg: algorithm, keyid: 'workerd-test-key' },
    })

    assert(response.headers.get('signature') === null, 'signing changed the source response')
    assert(signedResponse.headers.has('signature-input'), 'signed response has no Signature-Input')
    assert(signedResponse.headers.has('signature'), 'signed response has no Signature')

    const verifiedResponse = await verify(signedResponse, {
      request: signedRequest,
      verifier,
      policy: policy(responseComponents),
    })
    assert(verifiedResponse.algorithm === algorithm, 'response used an unexpected algorithm')

    console.log('workerd request and response signature round trips passed')
  },
}
