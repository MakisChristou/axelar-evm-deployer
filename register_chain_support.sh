#!/bin/bash

# Check if CHAIN is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <chain>"
    echo "Example: $0 monad"
    exit 1
fi

CHAIN="$1"

for i in $(seq 0 21); do
    echo "Registering chain support for worker $i..."
    kubectl exec "ampd-axelar-amplifier-worker-$i" -n testnet-amplifiers -c ampd -- ampd register-public-key ecdsa
    kubectl exec "ampd-axelar-amplifier-worker-$i" -n testnet-amplifiers -c ampd -- ampd register-chain-support amplifier "$CHAIN"
done

echo "Done registering chain support for all workers."