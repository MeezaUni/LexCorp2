#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "Cleaning up previous network data..."
rm -rf networkFiles data

echo "Generating generic Besu QBFT blockchain configuration..."
mkdir -p networkFiles/keys

docker run --rm \
  -v "/${DIR}/ibft-config.json:/opt/besu/ibft-config.json" \
  -v "/${DIR}/networkFiles:/opt/besu/networkFiles" \
  hyperledger/besu:latest operator generate-blockchain-config \
    --config-file=/opt/besu/ibft-config.json \
    --to=/opt/besu/networkFiles \
    --private-key-file-name=key

# Move keys to deterministic folders for node1, node2, node3
mkdir -p networkFiles/keys/node1 networkFiles/keys/node2 networkFiles/keys/node3
DIRS=(networkFiles/keys/0x*)

# Handle case where directory names aren't sorted nicely or missing
if [ -d "${DIRS[0]}" ]; then cp ${DIRS[0]}/* networkFiles/keys/node1/; fi
if [ -d "${DIRS[1]}" ]; then cp ${DIRS[1]}/* networkFiles/keys/node2/; fi
if [ -d "${DIRS[2]}" ]; then cp ${DIRS[2]}/* networkFiles/keys/node3/; fi

NODE1_PUB_KEY=$(cat networkFiles/keys/node1/key.pub | sed 's/^0x//')
echo "Node 1 Public Key: $NODE1_PUB_KEY"

# Windows compat sed replacement for docker-compose.yml
cat docker-compose.yml | sed "s|enode://@172.18.0.10:30303|enode://${NODE1_PUB_KEY}@172.18.0.10:30303|g" > docker-compose-active.yml

echo "Besu Network initialized. You can now run 'docker-compose -f docker-compose-active.yml up -d'"
