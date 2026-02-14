## Example

```bash
cargo run -- status --axelar-id arc-9
```

```bash
cargo run -- init \
  --chain-name "Arc Testnet" \
  --axelar-id arc-9 \
  --chain-id 5042002 \
  --rpc-url https://rpc.testnet.arc.network \
  --token-symbol USDC \
  --decimals 18 \
  --explorer-name "Arc Testnet Explorer" \
  --explorer-url "https://testnet.arcscan.app/" \
  --target-json ../axelar-contract-deployments/axelar-chains-config/info/testnet.json
```

## 1. Deploy ConstAddressDeployer

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/evm/legacy/ConstAddressDeployer.json
```

## 2. Deploy Create3Deployer

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-gmp-sdk-solidity/artifacts/contracts/deploy/Create3Deployer.sol/Create3Deployer.json \
  --salt "v1.0.10"
```

## 3. Deploy AxelarGateway

Not yet implemented.

## 4. Deploy Operators

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/node_modules/@axelar-network/axelar-cgp-solidity/artifacts/contracts/auth/Operators.sol/Operators.json
```

## 5. RegisterOperators

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY
```

## 6. Deploy AxelarGasService

Not yet implemented.

## 7. TransferOperatorsOwnership

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY
```

## 8. TransferGatewayOwnership

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY
```

## 9. TransferGasServiceOwnership

```bash
cargo run -- deploy --axelar-id arc-9 --private-key $PRIVATE_KEY
```
