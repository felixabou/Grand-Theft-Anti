# GuardWallet (Phase 1: EVM chains)

Smart-contract wallet where every transaction needs TWO signatures:
the main key + a second authenticator device. A stolen key alone can't move funds.

## Run the tests
    curl -L https://foundry.paradigm.xyz | bash && foundryup
    forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
    forge test

## Status
- 29 tests passing (4 fuzz tests x 10,000 random runs each)
- Slither: no real issues (remaining flags are expected for a wallet)
- NOT audited. Testnet + small amounts only until audited.

## Next phases
1. Deterministic factory deploy (same address on every EVM chain)
2. Authenticator app that decodes and shows the transaction itself
3. Watcher that alerts on RecoveryInitiated events
4. ERC-1271 support (dApp signatures), then Solana program
