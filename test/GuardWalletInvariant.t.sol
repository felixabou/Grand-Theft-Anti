// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {GuardWallet} from "../src/GuardWallet.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract InvToken is ERC20("Token", "TKN") {
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

contract InvRouter {
    receive() external payable {}

    function swapTokenForEth(ERC20 token, uint256 amountIn, address recipient) external {
        token.transferFrom(msg.sender, address(this), amountIn);
        payable(recipient).transfer(amountIn / 1000);
    }

    function swapEthForToken(InvToken token, address recipient) external payable {
        token.mint(recipient, msg.value * 1000);
    }
}

/// Plays the thief holding a stolen daily key: tries random drains in random order across random days.
/// Records how much ACTUALLY left the wallet each UTC day.
contract ThiefHandler is Test {
    GuardWallet public wallet;
    InvToken public token;
    InvRouter public router;
    uint256 internal dailyPk;
    address internal daily;
    address public thief = address(0xBAD);

    mapping(uint256 => uint256) public ethOutByDay;
    mapping(uint256 => uint256) public tokenOutByDay;
    uint256 public maxEthDay;
    uint256 public maxTokenDay;
    uint256 public successes;

    constructor(GuardWallet w, InvToken t, InvRouter r, uint256 pk) {
        wallet = w;
        token = t;
        router = r;
        dailyPk = pk;
        daily = vm.addr(pk);
    }

    function _signed(GuardWallet.Call[] memory calls) internal view returns (uint256 deadline, bytes memory sig) {
        (uint64 gen,,, uint64 sn) = wallet.sessions(daily);
        deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(dailyPk, wallet.getSessionExecuteHash(daily, gen, sn, calls, deadline));
        sig = abi.encodePacked(r, s, v);
    }

    function _run(GuardWallet.Call[] memory calls) internal {
        (uint256 deadline, bytes memory sig) = _signed(calls);
        uint256 ethBefore = address(wallet).balance;
        uint256 tokBefore = token.balanceOf(address(wallet));
        try wallet.executeSession(daily, calls, deadline, sig) {
            successes++;
        } catch {}
        _record(ethBefore, tokBefore);
    }

    function _record(uint256 ethBefore, uint256 tokBefore) internal {
        uint256 day = block.timestamp / 1 days;
        uint256 ethAfter = address(wallet).balance;
        uint256 tokAfter = token.balanceOf(address(wallet));
        if (ethAfter < ethBefore) ethOutByDay[day] += ethBefore - ethAfter;
        if (tokAfter < tokBefore) tokenOutByDay[day] += tokBefore - tokAfter;
        if (ethOutByDay[day] > maxEthDay) maxEthDay = ethOutByDay[day];
        if (tokenOutByDay[day] > maxTokenDay) maxTokenDay = tokenOutByDay[day];
    }

    function _one(address to, uint256 value, bytes memory data) internal pure returns (GuardWallet.Call[] memory c) {
        c = new GuardWallet.Call[](1);
        c[0] = GuardWallet.Call(to, value, data);
    }

    function stealEth(uint256 amount) external {
        _run(_one(thief, bound(amount, 0, 3 ether), ""));
    }

    function stealToken(uint256 amount) external {
        _run(_one(address(token), 0, abi.encodeCall(ERC20.transfer, (thief, bound(amount, 0, 2000e18)))));
    }

    function swapToThief(uint256 amount) external {
        amount = bound(amount, 0, 2000e18);
        GuardWallet.Call[] memory c = new GuardWallet.Call[](2);
        c[0] = GuardWallet.Call(address(token), 0, abi.encodeCall(ERC20.approve, (address(router), amount)));
        c[1] = GuardWallet.Call(address(router), 0, abi.encodeCall(InvRouter.swapTokenForEth, (token, amount, thief)));
        _run(c);
    }

    function buyTokensForThief(uint256 amount) external {
        amount = bound(amount, 0, 3 ether);
        _run(_one(address(router), amount, abi.encodeCall(InvRouter.swapEthForToken, (token, thief))));
    }

    function mixedBatch(uint256 a, uint256 b) external {
        GuardWallet.Call[] memory c = new GuardWallet.Call[](3);
        c[0] = GuardWallet.Call(thief, bound(a, 0, 1 ether), "");
        c[1] = GuardWallet.Call(address(token), 0, abi.encodeCall(ERC20.transfer, (thief, bound(b, 0, 600e18))));
        c[2] = GuardWallet.Call(address(token), 0, abi.encodeCall(ERC20.approve, (address(router), 0)));
        _run(c);
    }

    function waitHours(uint256 h) external {
        vm.warp(block.timestamp + bound(h, 1, 30) * 1 hours);
    }
}

contract GuardWalletInvariantTest is Test {
    GuardWallet wallet;
    InvToken token;
    ThiefHandler handler;

    uint256 constant ETH_CAP = 1 ether;
    uint256 constant TOKEN_CAP = 500e18;

    function setUp() public {
        vm.warp(1_800_000_000);
        uint256 ownerPk = 0xA11CE;
        uint256 authPk = 0xB0B;
        uint256 dailyPk = 0xDA11;

        wallet = new GuardWallet(vm.addr(ownerPk), vm.addr(authPk), vm.addr(0xC0FFEE));
        vm.deal(address(wallet), 1000 ether);
        token = new InvToken();
        token.mint(address(wallet), 1_000_000e18);
        InvRouter router = new InvRouter();
        vm.deal(address(router), 1_000_000 ether);

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory caps = new uint256[](1);
        caps[0] = TOKEN_CAP;
        address[] memory targets = new address[](1);
        targets[0] = address(router);
        GuardWallet.SessionParams memory p =
            GuardWallet.SessionParams(vm.addr(dailyPk), uint64(block.timestamp + 90 days), ETH_CAP, tokens, caps, targets);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = wallet.getAddSessionHash(p, 0, deadline);
        wallet.addSession(p, deadline, _sig(ownerPk, d), _sig(authPk, d));

        handler = new ThiefHandler(wallet, token, router, dailyPk);
        targetContract(address(handler));
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// No matter what sequence of attacks the thief tries, no UTC day ever loses more than the cap.
    function invariant_NeverMoreThanDailyCapPerDay() public view {
        assertLe(handler.maxEthDay(), ETH_CAP);
        assertLe(handler.maxTokenDay(), TOKEN_CAP);
    }

    /// The master-level keys are never touched by anything the daily key does.
    function invariant_MainKeysUnchanged() public view {
        assertEq(wallet.owner(), vm.addr(0xA11CE));
        assertEq(wallet.authenticator(), vm.addr(0xB0B));
        assertEq(wallet.recovery(), vm.addr(0xC0FFEE));
    }
}

