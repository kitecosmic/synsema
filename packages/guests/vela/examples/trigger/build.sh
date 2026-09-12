#!/bin/sh
# Builds PoolTrigger against Vela's base contracts and deploys it with the deployer account.
# Needs foundry (forge + cast) and git — the starter kit's `chain` container has both:
#
#   docker cp examples/trigger vela-skit-chain:/trigger
#   docker exec vela-skit-chain sh -c 'cd /trigger && ./build.sh'
#
# Env: RPC_URL (default http://127.0.0.1:8545), PRIVATE_KEY (default Anvil #0),
#      PROCESSOR (default the starter kit's ProcessorEndpoint), VELA_TAG (default v0.2.0).
set -eu
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
PROCESSOR="${PROCESSOR:-0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9}"
VELA_TAG="${VELA_TAG:-v0.2.0}"

cd "$(dirname "$0")"
if [ ! -d lib/vela ]; then
  git clone --depth 1 --branch "$VELA_TAG" https://github.com/HorizenOfficial/vela.git lib/vela
fi
forge build
forge create src/PoolTrigger.sol:PoolTrigger \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast \
  --constructor-args "$PROCESSOR" | tee deploy.log
grep -o 'Deployed to: 0x[0-9a-fA-F]*' deploy.log | cut -d' ' -f3 > trigger.address
echo "PoolTrigger at $(cat trigger.address)"
