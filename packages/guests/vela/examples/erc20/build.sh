#!/bin/sh
# Deploys TestToken (1 000 000 TST, 6 decimals, all to the deployer) and allowlists it on the
# starter kit's TokenAllowlist with the ADMIN account. Needs foundry (forge + cast):
#
#   docker run --rm --entrypoint sh -v "$PWD/examples/erc20:/erc20" -w /erc20 \
#     -e RPC_URL=http://host.docker.internal:8545 horizen/cce-chain:v0.2.0 -c 'sh build.sh'
#
# Env: RPC_URL (default http://127.0.0.1:8545), PRIVATE_KEY (default Anvil #0 = ADMIN),
#      ALLOWLIST (default the starter kit's TokenAllowlist).
set -eu
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
ALLOWLIST="${ALLOWLIST:-0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9}"
SUPPLY="${SUPPLY:-1000000000000}"   # 1 000 000 TST with 6 decimals

cd "$(dirname "$0")"
forge build
forge create src/TestToken.sol:TestToken \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast \
  --constructor-args "$SUPPLY" | tee deploy.log
TOKEN=$(grep -o 'Deployed to: 0x[0-9a-fA-F]*' deploy.log | cut -d' ' -f3)
echo "$TOKEN" > token.address
cast send "$ALLOWLIST" "addAllowedToken(address)" "$TOKEN" \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" > /dev/null
echo "TestToken at $TOKEN, allowlisted: $(cast call "$ALLOWLIST" "isAllowedToken(address)(bool)" "$TOKEN" --rpc-url "$RPC_URL")"
