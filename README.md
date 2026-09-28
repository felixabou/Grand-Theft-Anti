# GuardWallet

Smart-contract wallet built to stop wallet drains. No single stolen key can empty it.

## Keys

| Key | Where it lives | Job |
|---|---|---|
| Master (called "owner" in the code) | Hardware wallet, offline in a drawer | Key changes and adding daily keys |
| Authenticator | Second device | Co-signs anything important |
| Recovery | Offline backup | Replaces lost keys after a 48h delay |
| Daily keys | Your phone or trading bot | Everyday trades within limits |

## What each combination can do

| Signed by | Can do |
|---|---|
| Daily key alone | Spend up to its daily caps, only through approved apps, until it expires (max 90 days) |
| Daily key + authenticator | Any transaction (bigger moves) |
| Master + authenticator | Everything: add daily keys, rotate keys, cancel recovery |

**Emergency brakes (one key is enough):**
- The master, the authenticator, or the daily key itself can revoke a daily key instantly.
- The master or the authenticator can revoke all daily keys at once.
- Rotating keys or starting a recovery automatically revokes all daily keys.

Daily caps are enforced by measuring the wallet's real balances before and after each transaction, so it doesn't matter *how* money leaves (transfer, swap, leftover approval, fee-on-transfer token).

## The app

`web/index.html` is the whole app: one file, no build step, no server. Host it on GitHub Pages and anyone can use it. It never sees a private key — your devices sign, the page just builds transactions and carries them between devices by QR code.

Run it locally with any static server, or just open the file in a browser.

The app can create a wallet from scratch: you supply your three key addresses and a factory address, it shows you the address your wallet will land on, and creates it. It can also add daily keys. It never generates or handles a private key, and it ships no compiled bytecode, so there is nothing in the page you have to take on trust. The factory is deployed once per network with `forge script script/Deploy.s.sol` and then shared by everyone on that network.

Two checks keep the page and the contracts from drifting apart. Run them against a local chain whenever either side changes:

    anvil &
    npm install ethers@6.13.4
    node web/verify-signing.mjs      # every signature format matches the contract
    node web/verify-onboarding.mjs   # create a wallet and a daily key, the way the page does

## Run the tests
    curl -L https://foundry.paradigm.xyz | bash && foundryup
    forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
    forge test

## Status
- 70 tests passing: 29 Phase 1 + 41 Phase 2 (fuzz tests run 10,000 random cases each)
- Invariant test: 500 runs x 100 random thief actions (50,000 attack calls) with random time jumps. No UTC day ever lost more than the cap.
- Slither: no real issues (remaining flags are expected for a wallet)
- **NOT audited. Testnet and small amounts only until audited.**

## Known limits (read before using real money)
1. **Unlisted tokens with leftover approvals.** If a token is *not* on a daily key's list, but an approved app (like a DEX router) still has an allowance to spend it from an earlier big trade, the daily key could move that token through the app without it counting against a cap. Approve exact amounts for big trades, or revoke leftover approvals.
2. **Only put apps in "approved apps".** A daily key can call any function on an approved app. The contract blocks listed tokens from being approved apps, but it can't tell whether some other address is a token or NFT contract.
3. **Caps reset at 00:00 UTC.** Worst case, a thief could take up to two days' caps around midnight before you react.
4. **Caps are per daily key.** Three active daily keys means three times the exposure.
5. **Daily key + authenticator is uncapped.** If both your phone and your authenticator are compromised, funds are at risk. Keep the authenticator on a separate device.

See TESTING.md for how to try all of this yourself.

## Still to build
1. Token support beyond the native coin
2. A watcher that alerts you when someone starts a recovery (you only have 48 hours to cancel)
3. Native mobile apps for the authenticator
4. ERC-1271 support (signing into dApps), then a Solana version
