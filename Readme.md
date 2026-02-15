## How it works

The deployer tracks progress in a state file (`~/.local/share/axelar-evm-deployer/<axelar-id>.json`). Each `cargo run -- deploy` invocation runs the **next pending step** and marks it completed. Steps that need extra arguments (artifact paths, salt) require them on the command line; steps that don't just need `--axelar-id`. Use `status` to see where you are.

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

## 1. Deploy ConstAddressDeployer

```bash
cargo run -- deploy --axelar-id $CHAIN \
  --artifact-path ../axelar-contract-deployments/evm/legacy/ConstAddressDeployer.json
```

## 2. Deploy Create3Deployer

```bash
cargo run -- deploy --axelar-id $CHAIN \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/deploy/Create3Deployer.sol/Create3Deployer.json \
  --salt $SALT
```

## 3. PredictGatewayAddress

Predicts EVM gateway proxy address using CREATE formula based on gateway deployer nonce.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 4. AddCosmWasmConfig

Adds VotingVerifier and MultisigProver per-chain config entries to testnet.json.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 5. InstantiateChainContracts

Submits governance proposal to instantiate Gateway, VotingVerifier, and MultisigProver via the Coordinator.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

> **ACTION REQUIRED:** Vote on the governance proposal after this step.

## 6. WaitInstantiateProposal

Polls the governance proposal until it passes.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 7. SaveDeployedContracts

Queries the Coordinator for deployed contract addresses and saves them to testnet.json.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 8. RegisterDeployment

Submits governance proposal to register the deployment on the Coordinator.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

> **ACTION REQUIRED:** Vote on the governance proposal after this step.

## 9. WaitRegisterProposal

Polls the governance proposal until it passes.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 10. CreateRewardPools

Submits governance proposal to create reward pools for VotingVerifier and Multisig.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

> **ACTION REQUIRED:** Vote on the governance proposal after this step.

## 11. WaitRewardPoolsProposal

Polls the governance proposal until it passes.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 12. AddRewards

Funds both reward pools (VotingVerifier + Multisig) with 1000000uaxl each.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 13. WaitForVerifierSet

Prints infrastructure PR instructions, polls ServiceRegistry for registered verifiers (testnet requires 22), then calls `update_verifier_set` on MultisigProver using the admin mnemonic from `cosmos-init`.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

> **ACTION REQUIRED:** Merge the infrastructure PR and wait for verifiers to register chain support before this step can complete.

## 14. Deploy AxelarGateway

Deploys implementation + proxy. Fetches the initial verifier set from the Axelar chain LCD endpoint automatically. Reuses a previously deployed implementation on retry.

```bash
cargo run -- deploy --axelar-id $CHAIN \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/gateway/AxelarAmplifierGateway.sol/AxelarAmplifierGateway.json \
  --proxy-artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/gateway/AxelarAmplifierGatewayProxy.sol/AxelarAmplifierGatewayProxy.json
```

## 15. Deploy Operators

Deploys the Operators contract via CREATE2 (through ConstAddressDeployer). Constructor arg `owner` is set to the gateway deployer address. Salt defaults to `"Operators"`.

```bash
cargo run -- deploy --axelar-id $CHAIN \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/utils/Operators.sol/Operators.json
```

## 16. RegisterOperators

Registers operator addresses on the Operators contract.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 17. AxelarGasService

Deploys the AxelarGasService implementation + proxy using the legacy init-based proxy pattern. The gas collector is set to the Operators contract address. Three transactions: deploy implementation, deploy proxy, call `proxy.init()`.

```bash
cargo run -- deploy --axelar-id $CHAIN \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-cgp-solidity/artifacts/contracts/gas-service/AxelarGasService.sol/AxelarGasService.json \
  --proxy-artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-cgp-solidity/artifacts/contracts/gas-service/AxelarGasServiceProxy.sol/AxelarGasServiceProxy.json
```

## 18. TransferOperatorsOwnership

Transfers Operators contract ownership to the governance address.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 19. TransferGatewayOwnership

Transfers AxelarGateway contract ownership to the governance address.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

## 20. TransferGasServiceOwnership

Transfers AxelarGasService contract ownership to the governance address.

```bash
cargo run -- deploy --axelar-id $CHAIN
```
