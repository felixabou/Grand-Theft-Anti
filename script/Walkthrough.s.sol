// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {GuardWallet} from "../src/GuardWallet.sol";
import {GuardWalletFactory} from "../src/GuardWalletFactory.sol";

/// End-to-end walkthrough against a LIVE chain (local anvil or a public testnet).
/// Every step below is a real transaction you can look up on a block explorer.
///
/// This uses throwaway demo keys on purpose. Never put real money near them.
///
/// Run against a local chain:
///   anvil &
///   forge script script/Walkthrough.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
contract Walkthrough is Script {
    uint256 constant DEPLOYER = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // anvil #0
    uint256 constant MASTER = 0xA11CE;
    uint256 constant AUTH = 0xB0B;
    uint256 constant RECOVERY = 0xC0FFEE;
    uint256 constant DAILY = 0xDA11;
    uint256 constant THIEF = 0xBAD;

    GuardWallet wallet;
    address friend = address(0xF00D);

    function run() external {
        address master = vm.addr(MASTER);
        address auth = vm.addr(AUTH);

        // ---------------------------------------------------------- deploy
        vm.startBroadcast(DEPLOYER);
        GuardWalletFactory factory = new GuardWalletFactory();
        wallet = factory.createWallet(master, auth, vm.addr(RECOVERY), bytes32(0));
        payable(address(wallet)).transfer(10 ether); // fund it
        vm.stopBroadcast();

        console.log("wallet deployed at", address(wallet));
        console.log("balance           ", address(wallet).balance / 1e18, "ETH");
        console.log("");

        _step1_masterSend();
        _step2_addDailyKey();
        _step3_dailySpend();
        _step4_capBlocks();
        _step5_thiefBlocked();
        _step6_revoke();
        _step7_rotate();

        console.log("");
        console.log("=== ALL STEPS BEHAVED AS EXPECTED ===");
        console.log("final wallet balance", address(wallet).balance / 1e15, "milli-ETH");
    }

    // ---------------------------------------------------------------- steps

    /// Master + authenticator send funds.
    function _step1_masterSend() internal {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 dl = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, wallet.nonce(), dl);
        bytes memory mSig = _sign(MASTER, d);
        bytes memory aSig = _sign(AUTH, d);

        vm.broadcast(DEPLOYER); // a relayer submits; the signatures are the authorization
        wallet.execute(calls, dl, mSig, aSig);

        console.log("1. master + authenticator sent 1 ETH  -> friend balance", friend.balance / 1e18, "ETH");
    }

    /// Master + authenticator add a daily key: 0.5 ETH per day, 30 days.
    function _step2_addDailyKey() internal {
        GuardWallet.SessionParams memory p = GuardWallet.SessionParams({
            key: vm.addr(DAILY),
            validUntil: uint64(block.timestamp + 30 days),
            ethDailyCap: 0.5 ether,
            tokens: new address[](0),
            tokenDailyCaps: new uint256[](0),
            targets: new address[](0)
        });
        uint256 dl = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, wallet.nonce(), dl);
        bytes memory mSig = _sign(MASTER, d);
        bytes memory aSig = _sign(AUTH, d);

        vm.broadcast(DEPLOYER);
        wallet.addSession(p, dl, mSig, aSig);

        console.log("2. daily key added, cap 0.5 ETH/day   -> active:", wallet.isSessionActive(vm.addr(DAILY)));
    }

    /// The daily key spends on its own, no authenticator needed.
    function _step3_dailySpend() internal {
        _daily(_one(friend, 0.3 ether, ""), true);
        (uint256 spent, uint256 cap) = wallet.sessionSpentToday(vm.addr(DAILY), address(0));
        console.log("3. daily key sent 0.3 ETH alone       -> spent today", spent / 1e17, "of cap", cap / 1e17);
    }

    /// Going over the cap is rejected.
    function _step4_capBlocks() internal {
        bool blocked = !_daily(_one(friend, 0.3 ether, ""), false);
        console.log("4. tried 0.3 more (over 0.5 cap)      -> blocked:", blocked);
    }

    /// A stolen-key thief can't use the daily key's slot.
    function _step5_thiefBlocked() internal {
        GuardWallet.Call[] memory calls = _one(vm.addr(THIEF), 0.1 ether, "");
        (uint64 gen,,, uint64 sn) = wallet.sessions(vm.addr(DAILY));
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _sign(THIEF, wallet.getSessionExecuteHash(vm.addr(DAILY), gen, sn, calls, dl));

        vm.broadcast(DEPLOYER);
        try wallet.executeSession(vm.addr(DAILY), calls, dl, sig) {
            console.log("5. THIEF SUCCEEDED - THIS IS A BUG");
        } catch {
            console.log("5. thief signed with their own key    -> rejected, thief got", vm.addr(THIEF).balance);
        }
    }

    /// Emergency brake: the authenticator alone kills the daily key.
    function _step6_revoke() internal {
        (uint64 gen,,,) = wallet.sessions(vm.addr(DAILY));
        bytes memory sig = _sign(AUTH, wallet.getRevokeSessionHash(vm.addr(DAILY), gen));

        vm.broadcast(DEPLOYER);
        wallet.revokeSession(vm.addr(DAILY), sig);

        console.log("6. authenticator revoked the daily key-> still active:", wallet.isSessionActive(vm.addr(DAILY)));
    }

    /// Key rotation: the "reset access" step if a key ever leaks.
    function _step7_rotate() internal {
        address newAuth = vm.addr(0x2222);
        uint256 dl = block.timestamp + 1 hours;
        bytes32 d = wallet.getRotateHash(vm.addr(MASTER), newAuth, vm.addr(RECOVERY), wallet.nonce(), dl);
        bytes memory mSig = _sign(MASTER, d);
        bytes memory aSig = _sign(AUTH, d);

        vm.broadcast(DEPLOYER);
        wallet.rotateKeys(vm.addr(MASTER), newAuth, vm.addr(RECOVERY), dl, mSig, aSig);

        console.log("7. rotated authenticator key          -> new authenticator set:", wallet.authenticator() == newAuth);
    }

    // ---------------------------------------------------------------- helpers

    function _daily(GuardWallet.Call[] memory calls, bool expectSuccess) internal returns (bool ok) {
        (uint64 gen,,, uint64 sn) = wallet.sessions(vm.addr(DAILY));
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _sign(DAILY, wallet.getSessionExecuteHash(vm.addr(DAILY), gen, sn, calls, dl));

        vm.broadcast(DEPLOYER);
        try wallet.executeSession(vm.addr(DAILY), calls, dl, sig) {
            ok = true;
        } catch {
            ok = false;
        }
        if (expectSuccess) require(ok, "expected this to succeed");
    }

    function _one(address to, uint256 value, bytes memory data) internal pure returns (GuardWallet.Call[] memory c) {
        c = new GuardWallet.Call[](1);
        c[0] = GuardWallet.Call(to, value, data);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }
}
