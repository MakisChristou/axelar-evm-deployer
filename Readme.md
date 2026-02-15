## How it works

The deployer tracks progress in a state file (`~/.local/share/axelar-evm-deployer/<chain>.json`). A single `cargo run -- deploy` runs **all** steps sequentially, blocking on polls (governance proposals, verifier registration) until they complete. Artifact paths and private keys are resolved automatically. Use `status` to see progress and deployed addresses.

## Configuration

Create a `.env` file (or export these variables). All config is read from the environment.

```bash
# Keys
CHAIN=arc-11
SALT=v1.0.13
MNEMONIC="..."                          # axelar deployer (testnet: axelar1wxej3l9aczsns3harrtdzk7rct29jl47tvu8mp)
MULTISIG_PROVER_MNEMONIC="..."          # prover admin (testnet: axelar1w7y7v26rtnrj4vrx6q3qq4hfsmc68hhsxnadlf)
DEPLOYER_PRIVATE_KEY=0x...              # ConstAddressDeployer + Create3Deployer (testnet: 0x156372Cb2F8939d9705fdaa6C70e25825Ea9CAaF)
GATEWAY_DEPLOYER_PRIVATE_KEY=0x...      # Gateway + Operators + ownership transfers (testnet: 0x92ae7f0b761aC8CFAbe4B94D53d1CD343dF8E3C0)
GAS_SERVICE_DEPLOYER_PRIVATE_KEY=0x...  # AxelarGasService (testnet: 0x3b7E3351689b0fba2cE9f1F8d14Ae38e270d9eD4)

# ITS 
ITS_DEPLOYER_PRIVATE_KEY=0x...          # ITS deployer (testnet: 0x49845e5d9985d8dc941462293ed38EEfF18B0eAE). Required for ITS steps.
ITS_SALT=v2.2.0
ITS_PROXY_SALT=v1.0.0

# Environment: devnet-amplifier, testnet, mainnet
ENV=testnet

# Chain config
CHAIN_NAME="Arc Testnet"
CHAIN_ID=5042002
RPC_URL=https://rpc.testnet.arc.network
TOKEN_SYMBOL=USDC
DECIMALS=18
EXPLORER_NAME="Arc Testnet Explorer"
EXPLORER_URL="https://testnet.arcscan.app/"
TARGET_JSON=../axelar-contract-deployments/axelar-chains-config/info/testnet.json
```

## Usage

```bash
cargo run -- init      # reads .env, creates state file + chain entry in target json
cargo run -- status    # shows progress with deployed addresses
cargo run -- deploy    # runs all pending steps, blocks on polls
```

## Steps

All 23 steps run automatically via `cargo run -- deploy`. Steps that submit governance proposals are followed by polling steps that block until the proposal passes. Manual actions (voting, infrastructure PRs) are prompted inline.

### GMP (steps 1-20)

| # | Step | Description |
|---|------|-------------|
| 1 | ConstAddressDeployer | Deploys via CREATE |
| 2 | Create3Deployer | Deploys via CREATE2 |
| 3 | PredictGatewayAddress | Predicts gateway proxy address from deployer nonce |
| 4 | AddCosmWasmConfig | Writes VotingVerifier + MultisigProver config to target json |
| 5 | InstantiateChainContracts | Governance proposal to instantiate via Coordinator |
| 6 | WaitInstantiateProposal | Polls until proposal passes |
| 7 | SaveDeployedContracts | Queries Coordinator for deployed addresses |
| 8 | RegisterDeployment | Governance proposal to register deployment |
| 9 | WaitRegisterProposal | Polls until proposal passes |
| 10 | CreateRewardPools | Governance proposal to create reward pools |
| 11 | WaitRewardPoolsProposal | Polls until proposal passes |
| 12 | AddRewards | Funds both reward pools with 1000000uaxl each |
| 13 | WaitForVerifierSet | Prints infra PR instructions, polls for verifiers, calls `update_verifier_set` |
| 14 | AxelarGateway | Deploys implementation + proxy with initial verifier set |
| 15 | Operators | Deploys via CREATE2 |
| 16 | RegisterOperators | Registers operator addresses |
| 17 | AxelarGasService | Deploys implementation + proxy (legacy init pattern) |
| 18 | TransferOperatorsOwnership | Transfers to governance address |
| 19 | TransferGatewayOwnership | Transfers to governance address |
| 20 | TransferGasServiceOwnership | Transfers to governance address |

### ITS (steps 21-23)

| # | Step | Description |
|---|------|-------------|
| 21 | DeployInterchainTokenService | Deploys 9 ITS contracts (5 helpers + impl/proxy + factory impl/proxy) via CREATE2/CREATE3 |
| 22 | RegisterItsOnHub | Governance proposal to register chain on the ITS Hub |
| 23 | WaitItsHubRegistration | Polls until proposal passes |

ITS requires `ITS_SALT`, `ITS_PROXY_SALT`, and optionally `ITS_DEPLOYER_PRIVATE_KEY` (falls back to `DEPLOYER_PRIVATE_KEY`). These can be set at init time or as env vars at deploy time.

### Manual actions during deploy

- **Steps 5, 8, 10, 22:** Vote on governance proposals after they're submitted
- **Step 13:** Merge infrastructure PR and register chain support for verifiers

## Testing GMP

After deployment, run a full end-to-end GMP loopback test:

```bash
cargo run -- test gmp --axelar-id arc-13
```

This sends a GMP message from the chain back to itself and relays it through the entire Amplifier pipeline:

1. Deploy a `SenderReceiver` contract (or reuse existing)
2. Send a `callContract` GMP message on the EVM chain
3. `verify_messages` on the cosmwasm Gateway (starts a verification poll)
4. Wait for verifier votes on the VotingVerifier, then `end_poll`
5. `route_messages` on the cosmwasm Gateway
6. `construct_proof` on the MultisigProver, wait for multisig signing
7. Submit the signed proof (`execute_data`) to the EVM Gateway
8. Verify `isContractCallApproved`, then call `execute` on SenderReceiver
9. Confirm the message was stored on-chain
