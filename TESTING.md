# Testing GuardWallet

Three levels, easiest first. Do them in order.

---

## Level 1: Run the test suite (2 minutes)

Proves the logic is correct. No blockchain, no money, no accounts.

    git clone https://github.com/felixabou/Grand-Theft-Anti.git
    cd Grand-Theft-Anti
    curl -L https://foundry.paradigm.xyz | bash && foundryup
    forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts@v5.1.0 --no-git
    forge test

Expect: `71 tests passed, 0 failed`.

Useful variations:

    forge test -vv                                  # show detail
    forge test --match-test StolenPhone -vvv        # one scenario, full trace
    forge test --gas-report                         # what each action costs

---

## Level 2: Run it on a local blockchain (5 minutes)

A real chain running on your own computer, with real transactions and real blocks. Nothing touches the internet and no real money is involved.

Open a terminal:

    anvil

Leave it running. In a second terminal:

    forge script script/Walkthrough.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --skip-simulation

This deploys a wallet and walks through the seven real scenarios:

| # | Step | Expected |
|---|---|---|
| 1 | Master + authenticator send 1 ETH | succeeds |
| 2 | Add a daily key, cap 0.5 ETH/day | active |
| 3 | Daily key sends 0.3 ETH alone | succeeds |
| 4 | Daily key tries 0.3 more (over cap) | **blocked** |
| 5 | Thief signs with their own key | **rejected** |
| 6 | Authenticator revokes the daily key | key dead |
| 7 | Rotate the authenticator key | new key set |

`--skip-simulation` is needed because steps 4 and 5 are *supposed* to fail.

Inspect anything afterwards with `cast`:

    cast balance <WALLET_ADDR> --rpc-url http://127.0.0.1:8545
    cast call <WALLET_ADDR> "owner()(address)" --rpc-url http://127.0.0.1:8545
    cast call <WALLET_ADDR> "isSessionActive(address)(bool)" <DAILY_KEY> --rpc-url http://127.0.0.1:8545

---

## Level 3: Deploy to a public testnet (30 minutes)

A real public blockchain with a block explorer, using free test coins. This is the closest thing to the real world without risking money.

### 1. Make four throwaway keys

    cast wallet new    # run this 4 times: deployer, master, authenticator, recovery

**These are practice keys. Never send real money to them, and never reuse them for a real wallet.**

### 2. Put them in a `.env` file

`.gitignore` already excludes `.env`, so it will never be committed.

    DEPLOYER_KEY=0x...
    OWNER_ADDR=0x...
    AUTH_ADDR=0x...
    RECOVERY_ADDR=0x...
    SALT=0x0000000000000000000000000000000000000000000000000000000000000001
    RPC_URL=https://sepolia.drpc.org

### 3. Get free test ETH

Search for a "Sepolia faucet" and send test ETH to your **deployer** address. Faucets need a login or a captcha, so this step has to be done by hand.

### 4. Deploy

    source .env
    forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast

It prints the wallet address. Look it up on sepolia.etherscan.io.

### 5. Fund the wallet and try it

Send some test ETH to the wallet address, then run the walkthrough against the testnet. Every step appears on the block explorer, so you can watch a blocked transaction fail for real.

### 6. Same address on other chains

Deploy with the **same deployer key, same keys, and same salt** on Base Sepolia or Arbitrum Sepolia, and the wallet lands on the identical address.

---

## What each level does and doesn't prove

| | Logic correct | Real gas costs | Works with real DEXs | Safe for real money |
|---|---|---|---|---|
| Level 1 | yes | estimates | no | no |
| Level 2 | yes | yes | no | no |
| Level 3 | yes | yes | yes | **no** |

**None of these replace an audit.** Tests only check the attacks you thought of. An auditor looks for the ones you didn't.

---

## Roughly what it costs to use (measured)

| Action | Gas |
|---|---|
| Daily key trade, alone | ~50,000-116,000 |
| Daily key + authenticator | ~52,000-109,000 |
| Master + authenticator send | ~99,000 |
| Add a daily key | ~61,000-261,000 |
| Revoke a daily key | ~57,000-62,000 |
| Rotate keys | ~103,000 |

A plain wallet transfer is 21,000 gas, so a daily-key trade costs roughly 2.5 to 5 times a normal send. On a cheap L2 like Base that's usually a fraction of a cent. On Ethereum mainnet it matters, which is one reason to run this on an L2.
