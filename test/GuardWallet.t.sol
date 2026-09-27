// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {GuardWallet} from "../src/GuardWallet.sol";
import {GuardWalletFactory} from "../src/GuardWalletFactory.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract MockToken is ERC20("Mock", "MCK") {
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

contract MockNFT is ERC721("MockNFT", "MNFT") {
    function mint(address to, uint256 id) external { _safeMint(to, id); }
}

/// Pretend DEX: pulls approved tokens from the caller.
contract MockDex {
    function pull(ERC20 token, uint256 amt) external { token.transferFrom(msg.sender, address(this), amt); }
}

contract GuardWalletTest is Test {
    GuardWalletFactory factory;
    GuardWallet wallet;

    uint256 ownerPk = 0xA11CE;
    uint256 authPk = 0xB0B;
    uint256 recoveryPk = 0xC0FFEE;
    uint256 thiefPk = 0xBAD;

    address ownerAddr;
    address authAddr;
    address recoveryAddr;
    address thief;
    address friend = address(0xF00D);

    function setUp() public {
        ownerAddr = vm.addr(ownerPk);
        authAddr = vm.addr(authPk);
        recoveryAddr = vm.addr(recoveryPk);
        thief = vm.addr(thiefPk);

        factory = new GuardWalletFactory();
        wallet = factory.createWallet(ownerAddr, authAddr, recoveryAddr, bytes32(0));
        vm.deal(address(wallet), 10 ether);
    }

    // ------------------------------------------------------------------ helpers

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _one(address to, uint256 value, bytes memory data) internal pure returns (GuardWallet.Call[] memory c) {
        c = new GuardWallet.Call[](1);
        c[0] = GuardWallet.Call(to, value, data);
    }

    function _exec(GuardWallet.Call[] memory calls, uint256 oPk, uint256 aPk) internal {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, wallet.nonce(), deadline);
        wallet.execute(calls, deadline, _sign(oPk, d), _sign(aPk, d));
    }

    // ------------------------------------------------------------------ happy path

    function test_BothKeysCanSendEth() public {
        _exec(_one(friend, 1 ether, ""), ownerPk, authPk);
        assertEq(friend.balance, 1 ether);
        assertEq(wallet.nonce(), 1);
    }

    function test_AnyoneCanSubmitSignedTx() public {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.prank(address(0x1234)); // random relayer pays gas
        wallet.execute(calls, deadline, o, a);
        assertEq(friend.balance, 1 ether);
    }

    function test_BatchApproveAndSwap() public {
        MockToken token = new MockToken();
        MockDex dex = new MockDex();
        token.mint(address(wallet), 100e18);

        GuardWallet.Call[] memory calls = new GuardWallet.Call[](2);
        calls[0] = GuardWallet.Call(address(token), 0, abi.encodeCall(ERC20.approve, (address(dex), 40e18)));
        calls[1] = GuardWallet.Call(address(dex), 0, abi.encodeCall(MockDex.pull, (ERC20(address(token)), 40e18)));
        _exec(calls, ownerPk, authPk);

        assertEq(token.balanceOf(address(dex)), 40e18);
        assertEq(token.balanceOf(address(wallet)), 60e18);
    }

    function test_ReceivesEthAndNfts() public {
        (bool ok,) = address(wallet).call{value: 1 ether}("");
        assertTrue(ok);
        MockNFT nft = new MockNFT();
        nft.mint(address(wallet), 7);
        assertEq(nft.ownerOf(7), address(wallet));
    }

    // ------------------------------------------------------------------ THE SWEEPER-BOT SCENARIO

    /// Thief has stolen the main key. Without the authenticator they get nothing.
    function test_StolenMainKeyAlone_CannotDrain() public {
        GuardWallet.Call[] memory calls = _one(thief, 10 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.execute(calls, deadline, _sign(ownerPk, d), _sign(thiefPk, d));
        assertEq(address(wallet).balance, 10 ether);
    }

    /// Thief has stolen the authenticator instead.
    function test_StolenAuthenticatorAlone_CannotDrain() public {
        GuardWallet.Call[] memory calls = _one(thief, 10 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        vm.expectRevert(GuardWallet.BadOwnerSignature.selector);
        wallet.execute(calls, deadline, _sign(thiefPk, d), _sign(authPk, d));
    }

    /// Same key signing twice must not count as two approvals.
    function test_OneKeyCannotSignForBoth() public {
        GuardWallet.Call[] memory calls = _one(thief, 1 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        bytes memory s = _sign(ownerPk, d);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.execute(calls, deadline, s, s);
    }

    /// New deposits after a key leak stay safe - the core problem from the start of this chat.
    function test_DepositsStaySafeAfterMainKeyLeak() public {
        vm.deal(address(this), 5 ether);
        (bool ok,) = address(wallet).call{value: 5 ether}(""); // user tops up after the leak
        assertTrue(ok);

        uint256 before = address(wallet).balance;
        GuardWallet.Call[] memory calls = _one(thief, before, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, wallet.nonce(), deadline);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.execute(calls, deadline, _sign(ownerPk, d), _sign(thiefPk, d));
        assertEq(address(wallet).balance, before);
    }

    // ------------------------------------------------------------------ replay & tampering

    function test_SignatureCannotBeReplayed() public {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        wallet.execute(calls, deadline, o, a);
        vm.expectRevert(); // nonce moved on, so the old signatures no longer match
        wallet.execute(calls, deadline, o, a);
        assertEq(friend.balance, 1 ether);
    }

    function test_TamperedRecipientRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(_one(friend, 1 ether, ""), 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.expectRevert(); // attacker swaps in their own address
        wallet.execute(_one(thief, 1 ether, ""), deadline, o, a);
    }

    function test_ExpiredSignatureRejected() public {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.warp(deadline + 1);
        vm.expectRevert(GuardWallet.Expired.selector);
        wallet.execute(calls, deadline, o, a);
    }

    function test_SignatureFromOtherChainRejected() public {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline); // signed for this chain
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.chainId(8453); // replayed on a different chain
        vm.expectRevert();
        wallet.execute(calls, deadline, o, a);
    }

    function test_SignatureForOtherWalletRejected() public {
        GuardWallet other = factory.createWallet(ownerAddr, authAddr, recoveryAddr, bytes32(uint256(1)));
        vm.deal(address(other), 5 ether);
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = other.getExecuteHash(calls, 0, deadline);
        vm.expectRevert();
        wallet.execute(calls, deadline, _sign(ownerPk, d), _sign(authPk, d));
    }

    function test_FailedInnerCallRevertsEverything() public {
        GuardWallet.Call[] memory calls = new GuardWallet.Call[](2);
        calls[0] = GuardWallet.Call(friend, 1 ether, "");
        calls[1] = GuardWallet.Call(friend, 999 ether, ""); // more than the wallet has
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.expectRevert();
        wallet.execute(calls, deadline, o, a);
        assertEq(friend.balance, 0);
        assertEq(wallet.nonce(), 0);
    }

    /// Cross-check: hash computed independently from the EIP-712 spec matches the contract's.
    function test_ExecuteHashMatchesSpec() public view {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, hex"abcd");
        bytes32 callHash = keccak256(
            abi.encode(keccak256("Call(address to,uint256 value,bytes data)"), friend, 1 ether, keccak256(hex"abcd"))
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Execute(Call[] calls,uint256 nonce,uint256 deadline)Call(address to,uint256 value,bytes data)"),
                keccak256(abi.encodePacked(callHash)),
                uint256(0),
                uint256(123)
            )
        );
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("GuardWallet"),
                keccak256("1"),
                block.chainid,
                address(wallet)
            )
        );
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        assertEq(wallet.getExecuteHash(calls, 0, 123), expected);
    }

    // ------------------------------------------------------------------ key rotation ("reset access")

    function test_RotateKeys_OldKeysStopWorking() public {
        uint256 newOwnerPk = 0x1111;
        uint256 newAuthPk = 0x2222;
        uint256 newRecPk = 0x3333;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getRotateHash(vm.addr(newOwnerPk), vm.addr(newAuthPk), vm.addr(newRecPk), 0, deadline);
        wallet.rotateKeys(
            vm.addr(newOwnerPk), vm.addr(newAuthPk), vm.addr(newRecPk), deadline, _sign(ownerPk, d), _sign(authPk, d)
        );
        assertEq(wallet.owner(), vm.addr(newOwnerPk));

        // old keys are dead
        GuardWallet.Call[] memory calls = _one(thief, 1 ether, "");
        uint256 dl = block.timestamp + 1 hours;
        bytes32 d2 = wallet.getExecuteHash(calls, wallet.nonce(), dl);
        vm.expectRevert(GuardWallet.BadOwnerSignature.selector);
        wallet.execute(calls, dl, _sign(ownerPk, d2), _sign(authPk, d2));

        // new keys work
        _exec(_one(friend, 1 ether, ""), newOwnerPk, newAuthPk);
        assertEq(friend.balance, 1 ether);
    }

    function test_ThiefWithMainKeyCannotRotate() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getRotateHash(thief, address(0xAAA), address(0xBBB), 0, deadline);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.rotateKeys(thief, address(0xAAA), address(0xBBB), deadline, _sign(ownerPk, d), _sign(thiefPk, d));
    }

    function test_CannotSetDuplicateOrZeroKeys() public {
        vm.expectRevert(GuardWallet.InvalidKeys.selector);
        new GuardWallet(ownerAddr, ownerAddr, recoveryAddr);
        vm.expectRevert(GuardWallet.InvalidKeys.selector);
        new GuardWallet(ownerAddr, address(0), recoveryAddr);
        vm.expectRevert(GuardWallet.InvalidKeys.selector);
        new GuardWallet(ownerAddr, authAddr, authAddr);
    }

    // ------------------------------------------------------------------ recovery

    function test_RecoveryAfterDelay() public {
        address newAuth = address(0xAAAA);
        vm.prank(recoveryAddr);
        wallet.initiateRecovery(ownerAddr, newAuth);

        vm.expectRevert(GuardWallet.RecoveryNotReady.selector);
        wallet.finalizeRecovery();

        vm.warp(block.timestamp + 48 hours);
        wallet.finalizeRecovery();
        assertEq(wallet.authenticator(), newAuth);
        assertEq(wallet.nonce(), 1);
    }

    function test_RecoveryInvalidatesOldSignatures() public {
        GuardWallet.Call[] memory calls = _one(friend, 1 ether, "");
        uint256 deadline = block.timestamp + 72 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);

        vm.prank(recoveryAddr);
        wallet.initiateRecovery(ownerAddr, address(0xAAAA));
        vm.warp(block.timestamp + 48 hours);
        wallet.finalizeRecovery();

        vm.expectRevert();
        wallet.execute(calls, deadline, o, a);
    }

    function test_OnlyRecoveryKeyCanInitiate() public {
        vm.prank(thief);
        vm.expectRevert(GuardWallet.NotRecoveryKey.selector);
        wallet.initiateRecovery(thief, address(0xAAAA));
    }

    function test_CancelThiefRecovery() public {
        // thief stole the backup key and tries to take over
        vm.prank(recoveryAddr);
        wallet.initiateRecovery(thief, address(0xAAAA));

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getCancelHash(0, deadline);
        wallet.cancelRecovery(deadline, _sign(ownerPk, d), _sign(authPk, d));

        vm.warp(block.timestamp + 48 hours);
        vm.expectRevert(GuardWallet.NoPendingRecovery.selector);
        wallet.finalizeRecovery();
        assertEq(wallet.owner(), ownerAddr);
    }

    function test_RotationCancelsPendingRecovery() public {
        vm.prank(recoveryAddr);
        wallet.initiateRecovery(thief, address(0xAAAA));
        uint256 deadline = block.timestamp + 1 hours;
        address newRec = address(0xCCCC);
        bytes32 d = wallet.getRotateHash(ownerAddr, authAddr, newRec, 0, deadline);
        wallet.rotateKeys(ownerAddr, authAddr, newRec, deadline, _sign(ownerPk, d), _sign(authPk, d));
        (,, uint64 readyAt) = wallet.pendingRecovery();
        assertEq(readyAt, 0);
        assertEq(wallet.recovery(), newRec);
    }

    // ------------------------------------------------------------------ factory

    function test_FactoryAddressIsPredictable() public {
        bytes32 salt = bytes32(uint256(42));
        address predicted = factory.predictAddress(ownerAddr, authAddr, recoveryAddr, salt);
        GuardWallet w = factory.createWallet(ownerAddr, authAddr, recoveryAddr, salt);
        assertEq(address(w), predicted);
    }

    function test_DifferentKeysGiveDifferentAddress() public view {
        address mine = factory.predictAddress(ownerAddr, authAddr, recoveryAddr, bytes32(0));
        address theirs = factory.predictAddress(thief, authAddr, recoveryAddr, bytes32(0));
        assertTrue(mine != theirs);
    }

    // ------------------------------------------------------------------ fuzz tests

    /// Random attacker keys (thousands of them) can never pass as the authenticator.
    function testFuzz_RandomKeyCannotAuthorize(uint256 attackerPk, uint96 amount) public {
        attackerPk = bound(attackerPk, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494336);
        vm.assume(attackerPk != authPk && attackerPk != ownerPk);
        GuardWallet.Call[] memory calls = _one(thief, amount, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(calls, 0, deadline);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.execute(calls, deadline, _sign(ownerPk, d), _sign(attackerPk, d));
    }

    /// Random garbage signatures never get through.
    function testFuzz_GarbageSignaturesRejected(bytes memory sigA, bytes memory sigB) public {
        GuardWallet.Call[] memory calls = _one(thief, 1 ether, "");
        vm.expectRevert();
        wallet.execute(calls, block.timestamp + 1, sigA, sigB);
        assertEq(address(wallet).balance, 10 ether);
    }

    /// Any legit amount goes to exactly the signed recipient.
    function testFuzz_SendAmount(uint256 amount) public {
        amount = bound(amount, 0, 10 ether);
        _exec(_one(friend, amount, ""), ownerPk, authPk);
        assertEq(friend.balance, amount);
        assertEq(address(wallet).balance, 10 ether - amount);
    }

    /// A signed tx can't be redirected to any other recipient.
    function testFuzz_CannotRedirect(address other) public {
        vm.assume(other != friend);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(_one(friend, 1 ether, ""), 0, deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.expectRevert();
        wallet.execute(_one(other, 1 ether, ""), deadline, o, a);
    }
}
