#!/bin/bash
set -euo pipefail

WORKERD_BIN=${WORKERD_BIN:-"$(pwd)/test/workerd/node_modules/.bin/workerd"}
WORKERD_MODULE=${WORKERD_MODULE:-"$(pwd)/test/workerd/node_modules/workerd"}

COMPATIBILITY_DATE=$(WORKERD_MODULE="$WORKERD_MODULE" node -p "const d = require(process.env.WORKERD_MODULE).compatibilityDate, t = new Date().toISOString().slice(0,10); d > t ? t : d")
WORKERD_VERSION=$(WORKERD_MODULE="$WORKERD_MODULE" node -p "require(process.env.WORKERD_MODULE + '/package.json').version")

echo "Using workerd $WORKERD_VERSION, compatibility date $COMPATIBILITY_DATE"

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

"$WORKERD_BIN" test --verbose "$(pwd)/test/.workerd.capnp"
