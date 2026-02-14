## How it works

The deployer tracks progress in a state file (`~/.local/share/axelar-evm-deployer/<axelar-id>.json`). Each `cargo run -- deploy` invocation runs the **next pending step** and marks it completed. Steps that need extra arguments (private key, artifact paths) require them on the command line; steps that don't (CosmWasm steps, ownership transfers) just need `--axelar-id`. Use `status` to see where you are.

```bash
export CHAIN=arc-10
export SALT=v1.0.11
export GATEWAY_DEPLOYER=0x92ae7f0b761aC8CFAbe4B94D53d1CD343dF8E3C0
```

## Setup

```bash
cargo run -- status --axelar-id $CHAIN
```

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
  --env testnet \
  --gateway-deployer $GATEWAY_DEPLOYER
```

## 1. Deploy ConstAddressDeployer

```bash
cargo run -- deploy --axelar-id $CHAIN --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/evm/legacy/ConstAddressDeployer.json
```

## 2. Deploy Create3Deployer

```bash
cargo run -- deploy --axelar-id $CHAIN --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/deploy/Create3Deployer.sol/Create3Deployer.json \
  --salt $SALT$
```

## Steps 3–11: CosmWasm setup

Each `cargo run -- deploy` invocation runs the **next pending step** from the state file and advances automatically. Just repeat the same command to progress through the pipeline.

```bash
cargo run -- deploy --axelar-id $CHAIN
```

| Step | Name | Description |
|------|------|-------------|
| 3 | PredictGatewayAddress | Predicts EVM gateway proxy address using CREATE formula based on gateway deployer nonce |
| 4 | AddCosmWasmConfig | Adds VotingVerifier and MultisigProver per-chain config entries to testnet.json |
| 5 | InstantiateChainContracts | Submits governance proposal to instantiate Gateway, VotingVerifier, and MultisigProver via the Coordinator |
| 6 | WaitInstantiateProposal | Polls the governance proposal until it passes |
| 7 | SaveDeployedContracts | Queries the Coordinator for deployed contract addresses and saves them to testnet.json |
| 8 | RegisterDeployment | Submits governance proposal to register the deployment on the Coordinator |
| 9 | WaitRegisterProposal | Polls the governance proposal until it passes |
| 10 | CreateRewardPools | Submits governance proposal to create reward pools for VotingVerifier and Multisig |
| 11 | WaitRewardPoolsProposal | Polls the governance proposal until it passes |

## 12. Deploy AxelarGateway

Deploys implementation + proxy. Fetches the initial verifier set from the Axelar chain LCD endpoint automatically.

```bash
cargo run -- deploy --axelar-id $CHAIN --private-key $GATEWAY_DEPLOYER_PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/gateway/AxelarAmplifierGateway.sol/AxelarAmplifierGateway.json \
  --proxy-artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/gateway/AxelarAmplifierGatewayProxy.sol/AxelarAmplifierGatewayProxy.json
```

## 13. Deploy Operators

```bash
cargo run -- deploy --axelar-id $CHAIN --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-cgp-solidity/artifacts/contracts/auth/Operators.sol/Operators.json
```

## Steps 14–18: Registration and ownership transfers

```bash
cargo run -- deploy --axelar-id $CHAIN --private-key $PRIVATE_KEY
```

| Step | Name | Description |
|------|------|-------------|
| 14 | RegisterOperators | Registers operator addresses on the Operators contract |
| 15 | AxelarGasService | Deploys the gas service (not yet implemented) |
| 16 | TransferOperatorsOwnership | Transfers Operators contract ownership |
| 17 | TransferGatewayOwnership | Transfers Gateway contract ownership |
| 18 | TransferGasServiceOwnership | Transfers GasService contract ownership |
