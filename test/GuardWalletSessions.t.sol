// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {GuardWallet} from "../src/GuardWallet.sol";
import {GuardWalletFactory} from "../src/GuardWalletFactory.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SessMockToken is ERC20("Token", "TKN") {
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

/// Pretend DEX router: pulls tokens from the CALLER and pays ETH to any recipient.
/// A thief would set recipient = themselves, so this is exactly the attack the caps must catch.
contract SessMockRouter {
    receive() external payable {}

    function swapTokenForEth(ERC20 token, uint256 amountIn, address recipient) external {
        token.transferFrom(msg.sender, address(this), amountIn);
        payable(recipient).transfer(amountIn / 1000);
    }

    function swapEthForToken(SessMockToken token, address recipient) external payable {
        token.mint(recipient, msg.value * 1000);
    }
}

/// Some random contract that is NOT on the approved-apps list.
contract SessRandomContract {
    function doSomething() external payable {}
}

/// Malicious recipient that tries to re-enter the wallet when it receives ETH.
contract SessReenterer {
    GuardWallet public wallet;
    address public key;
    GuardWallet.Call[] internal calls;
    uint256 public deadline;
    bytes public sig;

    function arm(GuardWallet w, address k, GuardWallet.Call[] memory c, uint256 d, bytes memory s) external {
        wallet = w;
        key = k;
        delete calls;
        for (uint256 i = 0; i < c.length; i++) calls.push(c[i]);
        deadline = d;
        sig = s;
    }

    receive() external payable {
        wallet.executeSession(key, calls, deadline, sig);
    }
}

/// Thief contract that sneaks the user's own signed "update daily key" in mid-transaction,
/// trying to reset the spending counter. Must be blocked.
contract SessSneakyUpdater {
    GuardWallet public wallet;
    GuardWallet.SessionParams internal params;
    uint256 public deadline;
    bytes public ownerSig;
    bytes public authSig;

    function arm(GuardWallet w, GuardWallet.SessionParams memory p, uint256 d, bytes memory o, bytes memory a) external {
        wallet = w;
        params = p;
        deadline = d;
        ownerSig = o;
        authSig = a;
    }

    receive() external payable {
        wallet.addSession(params, deadline, ownerSig, authSig);
    }
}

contract GuardWalletSessionsTest is Test {
    GuardWallet wallet;
    SessMockToken token;
    SessMockToken otherToken;
    SessMockRouter router;
    SessRandomContract randomContract;

    uint256 ownerPk = 0xA11CE; // master (offline)
    uint256 authPk = 0xB0B; // authenticator
    uint256 recoveryPk = 0xC0FFEE; // backup
    uint256 dailyPk = 0xDA11; // daily key on the phone
    uint256 thiefPk = 0xBAD;

    address daily;
    address thief;
    address friend = address(0xF00D);

    uint256 constant ETH_CAP = 1 ether;
    uint256 constant TOKEN_CAP = 500e18;

    function setUp() public {
        vm.warp(1_800_000_000); // a realistic date, mid-day UTC
        daily = vm.addr(dailyPk);
        thief = vm.addr(thiefPk);

        GuardWalletFactory factory = new GuardWalletFactory();
        wallet = factory.createWallet(vm.addr(ownerPk), vm.addr(authPk), vm.addr(recoveryPk), bytes32(0));
        vm.deal(address(wallet), 100 ether);

        token = new SessMockToken();
        otherToken = new SessMockToken();
        token.mint(address(wallet), 10_000e18);
        otherToken.mint(address(wallet), 10_000e18);
        router = new SessMockRouter();
        vm.deal(address(router), 1000 ether);
        randomContract = new SessRandomContract();

        _addSession(_defaultParams(daily));
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

    function _defaultParams(address key) internal view returns (GuardWallet.SessionParams memory p) {
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory caps = new uint256[](1);
        caps[0] = TOKEN_CAP;
        address[] memory targets = new address[](1);
        targets[0] = address(router);
        p = GuardWallet.SessionParams(key, uint64(block.timestamp + 30 days), ETH_CAP, tokens, caps, targets);
    }

    function _addSession(GuardWallet.SessionParams memory p) internal {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, wallet.nonce(), deadline);
        wallet.addSession(p, deadline, _sign(ownerPk, d), _sign(authPk, d));
    }

    function _sessionSigned(uint256 pk, address key, GuardWallet.Call[] memory calls)
        internal
        view
        returns (uint256 deadline, bytes memory sig)
    {
        (uint64 gen,,, uint64 sn) = wallet.sessions(key);
        deadline = block.timestamp + 1 hours;
        sig = _sign(pk, wallet.getSessionExecuteHash(key, gen, sn, calls, deadline));
    }

    function _daily(GuardWallet.Call[] memory calls) internal {
        (uint256 deadline, bytes memory sig) = _sessionSigned(dailyPk, daily, calls);
        wallet.executeSession(daily, calls, deadline, sig);
    }

    function _expectDailyRevert(GuardWallet.Call[] memory calls, bytes memory err) internal {
        (uint256 deadline, bytes memory sig) = _sessionSigned(dailyPk, daily, calls);
        if (err.length == 0) vm.expectRevert();
        else vm.expectRevert(err);
        wallet.executeSession(daily, calls, deadline, sig);
    }

    function _bigMove(GuardWallet.Call[] memory calls, uint256 sPk, uint256 aPk) internal {
        (uint64 gen,,,) = wallet.sessions(daily);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getSessionAuthExecuteHash(daily, gen, calls, wallet.nonce(), deadline);
        wallet.executeWithSessionAndAuth(daily, calls, deadline, _sign(sPk, d), _sign(aPk, d));
    }

    function _approve(address spender, uint256 amt) internal view returns (bytes memory) {
        return abi.encodeCall(ERC20.approve, (spender, amt));
    }

    // ================================================================== adding daily keys

    function test_AddSession_IsActiveWithRules() public view {
        assertTrue(wallet.isSessionActive(daily));
        (uint256 spent, uint256 cap) = wallet.sessionSpentToday(daily, address(0));
        assertEq(spent, 0);
        assertEq(cap, ETH_CAP);
        (, cap) = wallet.sessionSpentToday(daily, address(token));
        assertEq(cap, TOKEN_CAP);
        assertTrue(wallet.isSessionTarget(daily, address(router)));
        assertFalse(wallet.isSessionTarget(daily, address(randomContract)));
    }

    function test_DailyKeyCannotAddItselfMorePower() public {
        GuardWallet.SessionParams memory p = _defaultParams(thief);
        p.ethDailyCap = 100 ether;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, wallet.nonce(), deadline);
        vm.expectRevert(GuardWallet.BadOwnerSignature.selector);
        wallet.addSession(p, deadline, _sign(dailyPk, d), _sign(authPk, d));
    }

    function test_MasterAloneCannotAddSession() public {
        GuardWallet.SessionParams memory p = _defaultParams(thief);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, wallet.nonce(), deadline);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.addSession(p, deadline, _sign(ownerPk, d), _sign(thiefPk, d));
    }

    function test_RejectBadSessionParams() public {
        GuardWallet.SessionParams memory p;

        p = _defaultParams(vm.addr(ownerPk)); // daily key can't be the master
        _expectAddRevert(p);
        p = _defaultParams(vm.addr(authPk)); // ...or the authenticator
        _expectAddRevert(p);
        p = _defaultParams(address(0));
        _expectAddRevert(p);

        p = _defaultParams(thief);
        p.validUntil = uint64(block.timestamp + 91 days); // longer than 90 days
        _expectAddRevert(p);

        p = _defaultParams(thief);
        p.validUntil = uint64(block.timestamp); // already expired
        _expectAddRevert(p);

        p = _defaultParams(thief);
        p.ethDailyCap = type(uint256).max; // "unlimited" is not allowed
        _expectAddRevert(p);

        p = _defaultParams(thief);
        p.targets[0] = address(token); // a listed token can't also be a free-for-all target
        _expectAddRevert(p);

        p = _defaultParams(thief);
        p.targets[0] = address(wallet); // can't target the wallet itself
        _expectAddRevert(p);

        p = _defaultParams(thief);
        address[] memory dupTokens = new address[](2);
        dupTokens[0] = address(token);
        dupTokens[1] = address(token);
        uint256[] memory caps = new uint256[](2);
        p.tokens = dupTokens;
        p.tokenDailyCaps = caps;
        _expectAddRevert(p);
    }

    function _expectAddRevert(GuardWallet.SessionParams memory p) internal {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, wallet.nonce(), deadline);
        bytes memory o = _sign(ownerPk, d);
        bytes memory a = _sign(authPk, d);
        vm.expectRevert(GuardWallet.InvalidSession.selector);
        wallet.addSession(p, deadline, o, a);
    }

    // ================================================================== daily caps

    function test_DailyKeySendsEthWithinCap() public {
        _daily(_one(friend, 0.4 ether, ""));
        _daily(_one(friend, 0.6 ether, ""));
        assertEq(friend.balance, 1 ether);
        (uint256 spent,) = wallet.sessionSpentToday(daily, address(0));
        assertEq(spent, 1 ether);
    }

    function test_DailyKeyCannotExceedEthCap() public {
        _daily(_one(friend, 0.7 ether, ""));
        _expectDailyRevert(
            _one(thief, 0.4 ether, ""),
            abi.encodeWithSelector(GuardWallet.SpendLimitExceeded.selector, address(0), 1.1 ether, ETH_CAP)
        );
        assertEq(thief.balance, 0);
    }

    function test_CapResetsNextDay() public {
        _daily(_one(friend, 1 ether, ""));
        _expectDailyRevert(_one(friend, 1, ""), "");
        vm.warp(block.timestamp + 1 days);
        _daily(_one(friend, 1 ether, ""));
        assertEq(friend.balance, 2 ether);
    }

    function test_TokenTransferCapped() public {
        _daily(_one(address(token), 0, abi.encodeCall(ERC20.transfer, (friend, 500e18))));
        assertEq(token.balanceOf(friend), 500e18);
        _expectDailyRevert(_one(address(token), 0, abi.encodeCall(ERC20.transfer, (thief, 1))), "");
    }

    /// The thief swaps through an APPROVED router but sends the output to themselves.
    /// Balance measuring still counts it, so they only get the daily cap.
    function test_SwapThroughApprovedRouterStillCapped() public {
        GuardWallet.Call[] memory calls = new GuardWallet.Call[](2);
        calls[0] = GuardWallet.Call(address(token), 0, _approve(address(router), 5000e18));
        calls[1] = GuardWallet.Call(
            address(router), 0, abi.encodeCall(SessMockRouter.swapTokenForEth, (token, 5000e18, thief))
        );
        _expectDailyRevert(calls, "");
        assertEq(token.balanceOf(address(wallet)), 10_000e18);
    }

    /// A normal small trade works: 400 tokens -> ETH back into the wallet.
    function test_SmallTradeWorks() public {
        GuardWallet.Call[] memory calls = new GuardWallet.Call[](2);
        calls[0] = GuardWallet.Call(address(token), 0, _approve(address(router), 400e18));
        calls[1] = GuardWallet.Call(
            address(router), 0, abi.encodeCall(SessMockRouter.swapTokenForEth, (token, 400e18, address(wallet)))
        );
        uint256 ethBefore = address(wallet).balance;
        _daily(calls);
        assertEq(token.balanceOf(address(wallet)), 10_000e18 - 400e18);
        assertEq(address(wallet).balance, ethBefore + 0.4 ether);
    }

    /// A big allowance left over from an earlier master-tier trade can't be abused past the cap.
    function test_LeftoverApprovalStillCapped() public {
        GuardWallet.Call[] memory c = _one(address(token), 0, _approve(address(router), 10_000e18));
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getExecuteHash(c, wallet.nonce(), deadline);
        wallet.execute(c, deadline, _sign(ownerPk, d), _sign(authPk, d));

        _expectDailyRevert(
            _one(address(router), 0, abi.encodeCall(SessMockRouter.swapTokenForEth, (token, 10_000e18, thief))), ""
        );
        assertEq(token.balanceOf(address(wallet)), 10_000e18);
    }

    function test_EthSentIntoRouterCounts() public {
        _expectDailyRevert(
            _one(address(router), 5 ether, abi.encodeCall(SessMockRouter.swapEthForToken, (token, thief))), ""
        );
    }

    // ================================================================== what the daily key may call

    function test_CannotCallUnapprovedContract() public {
        _expectDailyRevert(
            _one(address(randomContract), 0, abi.encodeCall(SessRandomContract.doSomething, ())),
            abi.encodeWithSelector(GuardWallet.SessionCallNotAllowed.selector, 0)
        );
    }

    function test_CannotApproveUnapprovedSpender() public {
        _expectDailyRevert(
            _one(address(token), 0, _approve(thief, 1)),
            abi.encodeWithSelector(GuardWallet.SessionCallNotAllowed.selector, 0)
        );
    }

    function test_CannotCallOtherTokenFunctions() public {
        _expectDailyRevert(
            _one(address(token), 0, abi.encodeCall(ERC20.transferFrom, (address(wallet), thief, 1))),
            abi.encodeWithSelector(GuardWallet.SessionCallNotAllowed.selector, 0)
        );
    }

    function test_CannotTouchUnlistedToken() public {
        _expectDailyRevert(
            _one(address(otherToken), 0, abi.encodeCall(ERC20.transfer, (thief, 1))),
            abi.encodeWithSelector(GuardWallet.SessionCallNotAllowed.selector, 0)
        );
    }

    function test_CannotCallWalletItself() public {
        _expectDailyRevert(
            _one(address(wallet), 0, abi.encodeCall(GuardWallet.finalizeRecovery, ())),
            abi.encodeWithSelector(GuardWallet.SessionCallNotAllowed.selector, 0)
        );
    }

    function test_ReentrancyBlocked() public {
        SessReenterer attacker = new SessReenterer();
        GuardWallet.Call[] memory inner = _one(thief, 0.1 ether, "");
        (uint64 gen,,, uint64 sn) = wallet.sessions(daily);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory innerSig = _sign(dailyPk, wallet.getSessionExecuteHash(daily, gen, sn + 1, inner, dl));
        attacker.arm(wallet, daily, inner, dl, innerSig);

        _expectDailyRevert(_one(address(attacker), 0.1 ether, ""), "");
        assertEq(thief.balance, 0);
    }

    function test_SneakedInKeyUpdateBlocked() public {
        // user signs a legit update for the same daily key (it sits in the public mempool)
        GuardWallet.SessionParams memory p = _defaultParams(daily);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, wallet.nonce(), deadline);
        SessSneakyUpdater sneaky = new SessSneakyUpdater();
        sneaky.arm(wallet, p, deadline, _sign(ownerPk, d), _sign(authPk, d));

        // thief with the daily key spends the full cap, routing it through the sneaky contract
        _expectDailyRevert(_one(address(sneaky), 1 ether, ""), "");
        assertEq(address(sneaky).balance, 0);
    }

    // ================================================================== signatures

    function test_ThiefKeyCannotUseSession() public {
        GuardWallet.Call[] memory calls = _one(thief, 0.1 ether, "");
        (uint256 deadline, bytes memory sig) = _sessionSigned(thiefPk, daily, calls);
        vm.expectRevert(GuardWallet.BadSessionSignature.selector);
        wallet.executeSession(daily, calls, deadline, sig);
    }

    function test_SessionSignatureCannotBeReplayed() public {
        GuardWallet.Call[] memory calls = _one(friend, 0.1 ether, "");
        (uint256 deadline, bytes memory sig) = _sessionSigned(dailyPk, daily, calls);
        wallet.executeSession(daily, calls, deadline, sig);
        vm.expectRevert(GuardWallet.BadSessionSignature.selector);
        wallet.executeSession(daily, calls, deadline, sig);
    }

    function test_ExpiredSessionRejected() public {
        vm.warp(block.timestamp + 31 days);
        _expectDailyRevert(_one(friend, 0.1 ether, ""), abi.encodeWithSelector(GuardWallet.SessionInactive.selector));
    }

    function test_ReaddedKeyKillsOldSignatures() public {
        GuardWallet.Call[] memory calls = _one(thief, 0.5 ether, "");
        (uint256 deadline, bytes memory oldSig) = _sessionSigned(dailyPk, daily, calls);

        _addSession(_defaultParams(daily)); // same key re-added -> new generation
        vm.expectRevert(GuardWallet.BadSessionSignature.selector);
        wallet.executeSession(daily, calls, deadline, oldSig);
    }

    // ================================================================== tier 2: daily key + authenticator

    function test_BigMoveNeedsAuthenticator() public {
        _bigMove(_one(friend, 50 ether, ""), dailyPk, authPk);
        assertEq(friend.balance, 50 ether);
    }

    function test_BigMoveRejectedWithoutAuthenticator() public {
        GuardWallet.Call[] memory calls = _one(thief, 50 ether, "");
        (uint64 gen,,,) = wallet.sessions(daily);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getSessionAuthExecuteHash(daily, gen, calls, wallet.nonce(), deadline);
        bytes memory s = _sign(dailyPk, d);
        bytes memory bad = _sign(thiefPk, d);
        vm.expectRevert(GuardWallet.BadAuthenticatorSignature.selector);
        wallet.executeWithSessionAndAuth(daily, calls, deadline, s, bad);
    }

    function test_BigMoveCannotCallWalletItself() public {
        GuardWallet.Call[] memory calls = _one(address(wallet), 0, abi.encodeCall(GuardWallet.finalizeRecovery, ()));
        (uint64 gen,,,) = wallet.sessions(daily);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getSessionAuthExecuteHash(daily, gen, calls, wallet.nonce(), deadline);
        bytes memory s = _sign(dailyPk, d);
        bytes memory a = _sign(authPk, d);
        vm.expectRevert(abi.encodeWithSelector(GuardWallet.SessionCallNotAllowed.selector, 0));
        wallet.executeWithSessionAndAuth(daily, calls, deadline, s, a);
    }

    function test_RevokedKeyCannotDoBigMove() public {
        (uint64 gen,,,) = wallet.sessions(daily);
        wallet.revokeSession(daily, _sign(authPk, wallet.getRevokeSessionHash(daily, gen)));

        GuardWallet.Call[] memory calls = _one(thief, 50 ether, "");
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getSessionAuthExecuteHash(daily, gen, calls, wallet.nonce(), deadline);
        bytes memory s = _sign(dailyPk, d);
        bytes memory a = _sign(authPk, d);
        vm.expectRevert(GuardWallet.SessionInactive.selector);
        wallet.executeWithSessionAndAuth(daily, calls, deadline, s, a);
    }

    // ================================================================== emergency brakes

    function test_MasterAloneCanRevoke() public { _revokeWith(ownerPk); }

    function test_AuthenticatorAloneCanRevoke() public { _revokeWith(authPk); }

    function test_DailyKeyCanRevokeItself() public { _revokeWith(dailyPk); }

    function _revokeWith(uint256 pk) internal {
        (uint64 gen,,,) = wallet.sessions(daily);
        wallet.revokeSession(daily, _sign(pk, wallet.getRevokeSessionHash(daily, gen)));
        assertFalse(wallet.isSessionActive(daily));
        _expectDailyRevert(_one(thief, 0.1 ether, ""), abi.encodeWithSelector(GuardWallet.SessionInactive.selector));
    }

    function test_ThiefCannotRevoke() public {
        (uint64 gen,,,) = wallet.sessions(daily);
        bytes memory sig = _sign(thiefPk, wallet.getRevokeSessionHash(daily, gen));
        vm.expectRevert(GuardWallet.NotAuthorizedToRevoke.selector);
        wallet.revokeSession(daily, sig);
    }

    function test_OldRevokeCannotKillReaddedKey() public {
        (uint64 gen,,,) = wallet.sessions(daily);
        bytes memory sig = _sign(authPk, wallet.getRevokeSessionHash(daily, gen));
        wallet.revokeSession(daily, sig);
        _addSession(_defaultParams(daily));
        vm.expectRevert(GuardWallet.NotAuthorizedToRevoke.selector); // signature was for the old generation
        wallet.revokeSession(daily, sig);
        assertTrue(wallet.isSessionActive(daily));
    }

    function test_RevokeAllByAuthenticator() public {
        address daily2 = vm.addr(0xDA12);
        _addSession(_defaultParams(daily2));
        wallet.revokeAllSessions(_sign(authPk, wallet.getRevokeAllHash(wallet.sessionEpoch())));
        assertFalse(wallet.isSessionActive(daily));
        assertFalse(wallet.isSessionActive(daily2));
    }

    function test_OldRevokeAllCannotBeReplayed() public {
        bytes memory sig = _sign(authPk, wallet.getRevokeAllHash(wallet.sessionEpoch()));
        wallet.revokeAllSessions(sig);
        _addSession(_defaultParams(daily));
        vm.expectRevert(GuardWallet.NotAuthorizedToRevoke.selector);
        wallet.revokeAllSessions(sig);
        assertTrue(wallet.isSessionActive(daily));
    }

    function test_DailyKeyCannotRevokeAll() public {
        bytes memory sig = _sign(dailyPk, wallet.getRevokeAllHash(wallet.sessionEpoch()));
        vm.expectRevert(GuardWallet.NotAuthorizedToRevoke.selector);
        wallet.revokeAllSessions(sig);
    }

    function test_RotateKeysKillsSessions() public {
        uint256 deadline = block.timestamp + 1 hours;
        address newAuth = vm.addr(0x2222);
        bytes32 d = wallet.getRotateHash(vm.addr(ownerPk), newAuth, vm.addr(recoveryPk), wallet.nonce(), deadline);
        wallet.rotateKeys(vm.addr(ownerPk), newAuth, vm.addr(recoveryPk), deadline, _sign(ownerPk, d), _sign(authPk, d));
        assertFalse(wallet.isSessionActive(daily));
    }

    function test_RecoveryStartKillsSessions() public {
        vm.prank(vm.addr(recoveryPk));
        wallet.initiateRecovery(vm.addr(ownerPk), vm.addr(0x2222));
        assertFalse(wallet.isSessionActive(daily));
    }

    // ================================================================== the scenario from the start of this chat

    /// Phone with the daily key is compromised and a sweeper bot takes over.
    /// It gets at most one day's cap, then the authenticator hits the brake.
    function test_StolenPhone_LossLimitedToOneDayThenStopped() public {
        _daily(_one(thief, 1 ether, "")); // bot sweeps the full daily cap
        _expectDailyRevert(_one(thief, 1 ether, ""), ""); // ...but no more today

        (uint64 gen,,,) = wallet.sessions(daily);
        wallet.revokeSession(daily, _sign(authPk, wallet.getRevokeSessionHash(daily, gen)));

        vm.warp(block.timestamp + 1 days);
        _expectDailyRevert(_one(thief, 1 ether, ""), abi.encodeWithSelector(GuardWallet.SessionInactive.selector));
        assertEq(thief.balance, 1 ether);
        assertEq(address(wallet).balance, 99 ether);
    }

    // ================================================================== fuzz

    function testFuzz_SingleSpendRespectsCap(uint256 amount) public {
        amount = bound(amount, 0, 50 ether);
        GuardWallet.Call[] memory calls = _one(friend, amount, "");
        if (amount <= ETH_CAP) {
            _daily(calls);
            assertEq(friend.balance, amount);
        } else {
            _expectDailyRevert(calls, "");
            assertEq(friend.balance, 0);
        }
    }

    function testFuzz_TwoSpendsSameDayNeverExceedCap(uint256 a, uint256 b) public {
        a = bound(a, 0, 2 ether);
        b = bound(b, 0, 2 ether);
        if (a <= ETH_CAP) _daily(_one(friend, a, ""));
        else _expectDailyRevert(_one(friend, a, ""), "");
        uint256 spentSoFar = friend.balance;
        if (spentSoFar + b <= ETH_CAP) _daily(_one(friend, b, ""));
        else _expectDailyRevert(_one(friend, b, ""), "");
        assertLe(friend.balance, ETH_CAP);
    }

    function testFuzz_RandomContractNeverCallable(address target, bytes4 selector) public {
        vm.assume(target != address(router) && target != address(token));
        vm.assume(target != address(wallet));
        GuardWallet.Call[] memory calls = _one(target, 0, abi.encodePacked(selector, uint256(1)));
        _expectDailyRevert(calls, "");
    }
}
