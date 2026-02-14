## Example

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


```bash
cargo run -- deploy \
  --axelar-id arc-9 \
  --private-key $PRIVATE_KEY \
  --artifact-path ../axelar-contract-deployments/evm/legacy/ConstAddressDeployer.json \
  --contract-name ConstAddressDeployer
```