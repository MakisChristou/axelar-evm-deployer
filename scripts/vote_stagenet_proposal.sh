#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <proposal_id>"
    echo "Example: $0 123"
    exit 1
fi
proposal_id="$1"

namespaces=(
    "stagenet724-validator-alpha"
    "stagenet724-validator-beta"
    "stagenet724-validator-delta"
    "stagenet724-validator-epsilon"
    "stagenet724-validator-gamma"
)

for namespace in "${namespaces[@]}"; do
    pod=$(kubectl get pods -n "$namespace" --no-headers | awk '{print $1}')

    if [ -z "$pod" ]; then
        echo "Warning: No pod found in namespace '$namespace', skipping"
        continue
    fi

    echo "Submitting vote for proposal $proposal_id on pod $pod (namespace: $namespace)"
    kubectl exec -n "$namespace" -it "$pod" -- /bin/sh -c "echo \"\$KEYRING_PASSWORD\" | axelard tx gov vote $proposal_id yes --from validator --gas 80000 --gas-adjustment 1.4"
    echo ""
done
