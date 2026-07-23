#!/bin/bash
set -euo pipefail

COMPATIBILITY_DATE=$(node -p "const d = require('workerd').compatibilityDate, t = new Date().toISOString().slice(0,10); d > t ? t : d")

echo "Using compatibility date $COMPATIBILITY_DATE"

node --run build
node test/runners/bundle.js workerd

cat <<EOT > "$(pwd)/test/.workerd.capnp"
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .testWorker),
  ],
);

const testWorker :Workerd.Worker = (
  modules = [
    (name = "worker", esModule = embed "runners/run-workerd.bundle.js")
  ],
  compatibilityDate = "$COMPATIBILITY_DATE",
);
EOT

workerd test --verbose "$(pwd)/test/.workerd.capnp"
