// The portable test files, imported for their `describe`/`it` registrations.
//
// This is the single list of what runs in every target runtime. Node.js, Deno, and Bun additionally
// run the files left out below, which depend on capabilities browsers and Cloudflare Workers do not
// have:
//
//   algorithms.ts    cross-verifies against node:crypto, which is the point of the test
//   e2e.ts           needs a Node.js HTTP server
//   runtime-e2e.ts   needs each runtime's own server API
//   types.ts         type-level assertions only, checked by `node --run test:types`

import '../accept-signature-boundaries.ts'
import '../accept-signature.ts'
import '../fields.ts'
import '../rfc9421-appendix.ts'
import '../rfc9421.ts'
import '../robustness.ts'
import '../signatures.ts'
import '../structured-fields-display-string.ts'
import '../structured-fields.ts'

export { runRegisteredTests } from './harness.ts'
export type { SuiteResults } from './harness.ts'
