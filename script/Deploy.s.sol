// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {GuardWallet} from "../src/GuardWallet.sol";
import {GuardWalletFactory} from "../src/GuardWalletFactory.sol";

/// Deploys the factory, then a wallet from it.
///
/// Set these in a .env file (NEVER commit it - .gitignore already excludes .env):
///   DEPLOYER_KEY    private key that pays gas (a throwaway test key)
///   OWNER_ADDR      master key address (offline hardware wallet)
///   AUTH_ADDR       authenticator device address
///   RECOVERY_ADDR   backup key address
///   SALT            any 32-byte value; the same salt + same keys = same wallet address on every chain
///
/// Run:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address owner = vm.envAddress("OWNER_ADDR");
        address auth = vm.envAddress("AUTH_ADDR");
        address recovery = vm.envAddress("RECOVERY_ADDR");
        bytes32 salt = vm.envOr("SALT", bytes32(0));

        vm.startBroadcast(deployerKey);
        GuardWalletFactory factory = new GuardWalletFactory{salt: salt}();
        address predicted = factory.predictAddress(owner, auth, recovery, salt);
        GuardWallet wallet = factory.createWallet(owner, auth, recovery, salt);
        vm.stopBroadcast();

        require(address(wallet) == predicted, "address mismatch");

        console.log("chain id       ", block.chainid);
        console.log("factory        ", address(factory));
        console.log("wallet         ", address(wallet));
        console.log("  owner (master)", wallet.owner());
        console.log("  authenticator ", wallet.authenticator());
        console.log("  recovery      ", wallet.recovery());
        console.log("");
        console.log("Send test funds to the wallet address above.");
    }
}
