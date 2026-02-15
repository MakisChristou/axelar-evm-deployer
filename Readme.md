## How it works

The deployer tracks progress in a state file (`~/.local/share/axelar-evm-deployer/<axelar-id>.json`). Each `cargo run -- deploy` invocation runs the **next pending step** and marks it completed. Artifact paths are built-in — every step just needs `--axelar-id` (and `--salt` for Create3Deployer). Use `status` to see where you are.

EVM private keys are stored during `cosmos-init` and auto-selected per step — no need to pass `--private-key` on each deploy.

```bash
export CHAIN=arc-11
export SALT=v1.0.13
export MNEMONIC="..."                          # axelar deployer (testnet: axelar1wxej3l9aczsns3harrtdzk7rct29jl47tvu8mp)
export MULTISIG_PROVER_MNEMONIC="..."          # prover admin (testnet: axelar1w7y7v26rtnrj4vrx6q3qq4hfsmc68hhsxnadlf)
export DEPLOYER_PRIVATE_KEY=0x...              # ConstAddressDeployer + Create3Deployer (testnet: 0x156372Cb2F8939d9705fdaa6C70e25825Ea9CAaF)
export GATEWAY_DEPLOYER_PRIVATE_KEY=0x...      # Gateway + Operators + ownership transfers (testnet: 0x92ae7f0b761aC8CFAbe4B94D53d1CD343dF8E3C0)
export GAS_SERVICE_DEPLOYER_PRIVATE_KEY=0x...  # AxelarGasService (testnet: 0x3b7E3351689b0fba2cE9f1F8d14Ae38e270d9eD4)
```

## Setup

```bash
cargo run -- init \
  --chain-name "Arc Testnet" \
  --axelar-id $CHAIN \
  --chain-id 5042002 \
  --rpc-url https://rpc.testnet.arc.network \
  --token-symbol USDC \
  --decimals 18 \
  --explorer-name "Arc Testnet Explorer" \
  --explorer-url "https://testnet.arcscan.app/" \
  --target-json ../axelar-contract-deployments/axelar-chains-config/info/testnet.json
```

```bash
cargo run -- cosmos-init --axelar-id $CHAIN \
  --mnemonic "$MNEMONIC" \
  --admin-mnemonic "$MULTISIG_PROVER_MNEMONIC" \
  --env testnet \
  --salt $SALT \
  --deployer-private-key $DEPLOYER_PRIVATE_KEY \
  --gateway-deployer-private-key $GATEWAY_DEPLOYER_PRIVATE_KEY \
  --gas-service-deployer-private-key $GAS_SERVICE_DEPLOYER_PRIVATE_KEY
```

```bash
cargo run -- status --axelar-id $CHAIN
```

## Steps

Every step below is just `cargo run -- deploy --axelar-id $CHAIN` unless noted otherwise.

### 1. ConstAddressDeployer

### 2. Create3Deployer

### 3. PredictGatewayAddress

Predicts EVM gateway proxy address using CREATE formula based on gateway deployer nonce.

### 4. AddCosmWasmConfig

Adds VotingVerifier and MultisigProver per-chain config entries to testnet.json.

### 5. InstantiateChainContracts

Submits governance proposal to instantiate Gateway, VotingVerifier, and MultisigProver via the Coordinator.

> **ACTION REQUIRED:** Vote on the governance proposal after this step.

### 6. WaitInstantiateProposal

Polls the governance proposal until it passes.

### 7. SaveDeployedContracts

Queries the Coordinator for deployed contract addresses and saves them to testnet.json.

### 8. RegisterDeployment

Submits governance proposal to register the deployment on the Coordinator.

> **ACTION REQUIRED:** Vote on the governance proposal after this step.

### 9. WaitRegisterProposal

Polls the governance proposal until it passes.

### 10. CreateRewardPools

Submits governance proposal to create reward pools for VotingVerifier and Multisig.

> **ACTION REQUIRED:** Vote on the governance proposal after this step.

### 11. WaitRewardPoolsProposal

Polls the governance proposal until it passes.

### 12. AddRewards

Funds both reward pools (VotingVerifier + Multisig) with 1000000uaxl each.

### 13. WaitForVerifierSet

Prints infrastructure PR instructions, polls ServiceRegistry for registered verifiers, then calls `update_verifier_set` on MultisigProver using the admin mnemonic from `cosmos-init`.

> **ACTION REQUIRED:** Merge the infrastructure PR and wait for verifiers to register chain support before this step can complete.

### 14. AxelarGateway

Deploys implementation + proxy. Fetches the initial verifier set from the Axelar chain LCD endpoint automatically. Reuses a previously deployed implementation on retry.

### 15. Operators

Deploys the Operators contract via CREATE2 (through ConstAddressDeployer). Constructor arg `owner` is set to the gateway deployer address.

### 16. RegisterOperators

Registers operator addresses on the Operators contract.

### 17. AxelarGasService

Deploys the AxelarGasService implementation + proxy using the legacy init-based proxy pattern. The gas collector is set to the Operators contract address. Three transactions: deploy implementation, deploy proxy, call `proxy.init()`.

### 18. TransferOperatorsOwnership

Transfers Operators contract ownership to the governance address.

### 19. TransferGatewayOwnership

Transfers AxelarGateway contract ownership to the governance address.

### 20. TransferGasServiceOwnership

Transfers AxelarGasService contract ownership to the governance address.
