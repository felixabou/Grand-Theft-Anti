// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title GuardWallet (Phase 2: daily keys)
/// @notice A smart-contract wallet with three tiers of permission, so no single stolen key can drain it.
///
///         Keys:
///           owner (master) - kept OFFLINE (hardware wallet in a drawer). Only comes out for key changes.
///           authenticator  - second device (hardware wallet or spare phone)
///           recovery       - offline backup; can replace lost keys only after a 48h delay
///           daily keys     - "session keys" on your phone or bot, added by master + authenticator
///
///         Tiers:
///           1. Daily key alone          -> spend up to its daily caps, only to approved apps, until it expires
///           2. Daily key + authenticator -> any transaction (bigger moves)
///           3. Master + authenticator    -> everything, including adding daily keys and rotating keys
///
///         Emergency brakes (any ONE of these keys is enough, because stopping can't steal anything):
///           - master, authenticator, or the daily key itself can revoke a daily key instantly
///           - master or authenticator can revoke ALL daily keys instantly
///           - rotating keys or starting a recovery also revokes all daily keys
///
///         Design choices for safety:
///           - Only plain CALLs are allowed (no delegatecall), so no outside code can rewrite storage.
///           - Every signature is bound to this wallet, this chain, a one-time nonce and a deadline.
///           - Daily caps are enforced by measuring the wallet's actual balances before and after,
///             so it doesn't matter HOW the money leaves (transfer, swap, fee-on-transfer token...).
///           - Every state-changing function is locked against re-entry (no function can be
///             called again from inside another one mid-transaction).
///           - Built on OpenZeppelin's audited ECDSA + EIP-712 code (rejects malleable signatures).
contract GuardWallet is EIP712 {
    // ------------------------------------------------------------------ types

    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    struct PendingRecovery {
        address newOwner;
        address newAuthenticator;
        uint64 readyAt; // 0 = nothing pending
    }

    /// @notice What a daily key is allowed to do.
    struct SessionParams {
        address key; // the daily key's address
        uint64 validUntil; // unix time it stops working (max 90 days out)
        uint256 ethDailyCap; // max native coin (ETH/BNB/...) that may leave per UTC day, in wei
        address[] tokens; // ERC-20 tokens it may spend
        uint256[] tokenDailyCaps; // matching daily caps, in each token's smallest unit
        address[] targets; // approved apps (e.g. DEX routers) it may call and approve
    }

    struct Session {
        uint64 generation; // bumps every time this key is (re)added, so old signatures die
        uint64 validUntil; // 0 = revoked
        uint64 epoch; // must equal sessionEpoch, so "revoke all" kills it
        uint64 nonce; // this daily key's own one-time counter
    }

    struct Spend {
        uint64 day; // UTC day number
        uint192 amount; // spent so far that day
    }

    // ------------------------------------------------------------------ constants

    uint256 public constant RECOVERY_DELAY = 48 hours;
    uint256 public constant MAX_SESSION_DURATION = 90 days;
    uint256 public constant MAX_SESSION_TOKENS = 10;
    uint256 public constant MAX_SESSION_TARGETS = 20;
    address public constant NATIVE = address(0); // "asset" id used for ETH/native coin

    bytes32 public constant CALL_TYPEHASH = keccak256("Call(address to,uint256 value,bytes data)");
    bytes32 public constant EXECUTE_TYPEHASH =
        keccak256("Execute(Call[] calls,uint256 nonce,uint256 deadline)Call(address to,uint256 value,bytes data)");
    bytes32 public constant ROTATE_TYPEHASH = keccak256(
        "RotateKeys(address newOwner,address newAuthenticator,address newRecovery,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant CANCEL_TYPEHASH = keccak256("CancelRecovery(uint256 nonce,uint256 deadline)");
    bytes32 public constant ADD_SESSION_TYPEHASH = keccak256(
        "AddSession(address sessionKey,uint64 validUntil,uint256 ethDailyCap,address[] tokens,uint256[] tokenDailyCaps,address[] targets,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant SESSION_EXECUTE_TYPEHASH = keccak256(
        "SessionExecute(address sessionKey,uint64 generation,uint64 sessionNonce,Call[] calls,uint256 deadline)Call(address to,uint256 value,bytes data)"
    );
    bytes32 public constant SESSION_AUTH_EXECUTE_TYPEHASH = keccak256(
        "SessionAuthExecute(address sessionKey,uint64 generation,Call[] calls,uint256 nonce,uint256 deadline)Call(address to,uint256 value,bytes data)"
    );
    bytes32 public constant REVOKE_SESSION_TYPEHASH = keccak256("RevokeSession(address sessionKey,uint64 generation)");
    bytes32 public constant REVOKE_ALL_TYPEHASH = keccak256("RevokeAllSessions(uint64 epoch)");

    // ------------------------------------------------------------------ state

    address public owner;
    address public authenticator;
    address public recovery;
    uint256 public nonce;
    PendingRecovery public pendingRecovery;

    uint64 public sessionEpoch;
    mapping(address => Session) public sessions;

    // per-session rules, keyed by sessionId = keccak256(key, generation) so re-adding a key starts clean
    mapping(bytes32 => mapping(address => uint256)) private _caps;
    mapping(bytes32 => mapping(address => bool)) private _isToken;
    mapping(bytes32 => mapping(address => bool)) private _isTarget;
    mapping(bytes32 => address[]) private _tokens;
    mapping(bytes32 => mapping(address => Spend)) private _spent;

    bool private _locked;

    // ------------------------------------------------------------------ events

    event Executed(uint256 indexed nonce, uint256 callCount);
    event KeysRotated(address indexed owner, address indexed authenticator, address indexed recovery);
    event RecoveryInitiated(address indexed newOwner, address indexed newAuthenticator, uint64 readyAt);
    event RecoveryCancelled();
    event RecoveryFinalized(address indexed owner, address indexed authenticator);
    event SessionAdded(address indexed key, uint64 generation, uint64 validUntil);
    event SessionExecuted(address indexed key, uint64 generation, uint64 sessionNonce, uint256 callCount);
    event SessionAuthExecuted(address indexed key, uint256 indexed nonce, uint256 callCount);
    event SessionRevoked(address indexed key, uint64 generation, address indexed revokedBy);
    event AllSessionsRevoked(uint64 newEpoch);

    // ------------------------------------------------------------------ errors

    error InvalidKeys();
    error Expired();
    error BadOwnerSignature();
    error BadAuthenticatorSignature();
    error NotRecoveryKey();
    error NoPendingRecovery();
    error RecoveryNotReady();
    error CallFailed(uint256 index, bytes reason);
    error InvalidSession();
    error SessionInactive();
    error BadSessionSignature();
    error SessionCallNotAllowed(uint256 index);
    error SpendLimitExceeded(address asset, uint256 attempted, uint256 cap);
    error NotAuthorizedToRevoke();
    error Reentrancy();

    // ------------------------------------------------------------------ setup

    constructor(address owner_, address authenticator_, address recovery_) EIP712("GuardWallet", "1") {
        _setKeys(owner_, authenticator_, recovery_);
    }

    receive() external payable {}

    modifier nonReentrant() {
        if (_locked) revert Reentrancy();
        _locked = true;
        _;
        _locked = false;
    }

    // ================================================================== TIER 3: master + authenticator

    /// @notice Run one or more calls if BOTH the master key and the authenticator signed them.
    ///         Anyone may submit the transaction and pay gas; the signatures are the authorization.
    function execute(Call[] calldata calls, uint256 deadline, bytes calldata ownerSig, bytes calldata authenticatorSig)
        external
        nonReentrant
    {
        uint256 currentNonce = nonce;
        bytes32 digest = getExecuteHash(calls, currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);

        nonce = currentNonce + 1; // consume nonce BEFORE any outside call
        emit Executed(currentNonce, calls.length);
        _runCalls(calls);
    }

    /// @notice Add (or replace) a daily key. Needs master + authenticator.
    function addSession(
        SessionParams calldata p,
        uint256 deadline,
        bytes calldata ownerSig,
        bytes calldata authenticatorSig
    ) external nonReentrant {
        uint256 currentNonce = nonce;
        bytes32 digest = getAddSessionHash(p, currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);
        nonce = currentNonce + 1;

        _validateSessionParams(p);

        uint64 generation = sessions[p.key].generation + 1;
        sessions[p.key] = Session(generation, p.validUntil, sessionEpoch, 0);
        bytes32 sid = _sessionId(p.key, generation);

        _caps[sid][NATIVE] = p.ethDailyCap;
        for (uint256 i = 0; i < p.tokens.length; i++) {
            _isToken[sid][p.tokens[i]] = true;
            _caps[sid][p.tokens[i]] = p.tokenDailyCaps[i];
        }
        _tokens[sid] = p.tokens;
        for (uint256 i = 0; i < p.targets.length; i++) {
            _isTarget[sid][p.targets[i]] = true;
        }
        emit SessionAdded(p.key, generation, p.validUntil);
    }

    /// @notice Replace any keys using master + authenticator. Also cancels recovery and kills all daily keys.
    function rotateKeys(
        address newOwner,
        address newAuthenticator,
        address newRecovery,
        uint256 deadline,
        bytes calldata ownerSig,
        bytes calldata authenticatorSig
    ) external nonReentrant {
        uint256 currentNonce = nonce;
        bytes32 digest = getRotateHash(newOwner, newAuthenticator, newRecovery, currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);

        nonce = currentNonce + 1;
        delete pendingRecovery;
        _revokeAllSessions();
        _setKeys(newOwner, newAuthenticator, newRecovery);
    }

    /// @notice Cancel a recovery you didn't start. Needs master + authenticator.
    function cancelRecovery(uint256 deadline, bytes calldata ownerSig, bytes calldata authenticatorSig)
        external
        nonReentrant
    {
        if (pendingRecovery.readyAt == 0) revert NoPendingRecovery();
        uint256 currentNonce = nonce;
        bytes32 digest = getCancelHash(currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);

        nonce = currentNonce + 1;
        delete pendingRecovery;
        emit RecoveryCancelled();
    }

    // ================================================================== TIER 1: daily key alone

    /// @notice Daily key acting alone: only approved apps, only up to today's caps.
    function executeSession(address key, Call[] calldata calls, uint256 deadline, bytes calldata sessionSig)
        external
        nonReentrant
    {
        Session memory s = sessions[key];
        _requireActive(s);
        if (block.timestamp > deadline) revert Expired();
        bytes32 digest = getSessionExecuteHash(key, s.generation, s.nonce, calls, deadline);
        if (ECDSA.recover(digest, sessionSig) != key) revert BadSessionSignature();

        sessions[key].nonce = s.nonce + 1; // consume BEFORE any outside call
        emit SessionExecuted(key, s.generation, s.nonce, calls.length);

        bytes32 sid = _sessionId(key, s.generation);
        for (uint256 i = 0; i < calls.length; i++) {
            if (!_sessionCallAllowed(sid, calls[i])) revert SessionCallNotAllowed(i);
        }

        // measure real balances before and after: catches every way money can leave
        address[] memory tokens = _tokens[sid];
        uint256[] memory before = new uint256[](tokens.length + 1);
        before[0] = address(this).balance;
        for (uint256 i = 0; i < tokens.length; i++) {
            before[i + 1] = IERC20(tokens[i]).balanceOf(address(this));
        }

        _runCalls(calls);

        uint256 afterBal = address(this).balance;
        if (afterBal < before[0]) _recordSpend(sid, NATIVE, before[0] - afterBal);
        for (uint256 i = 0; i < tokens.length; i++) {
            afterBal = IERC20(tokens[i]).balanceOf(address(this));
            if (afterBal < before[i + 1]) _recordSpend(sid, tokens[i], before[i + 1] - afterBal);
        }
    }

    // ================================================================== TIER 2: daily key + authenticator

    /// @notice Bigger moves: daily key + authenticator together, no caps.
    function executeWithSessionAndAuth(
        address key,
        Call[] calldata calls,
        uint256 deadline,
        bytes calldata sessionSig,
        bytes calldata authenticatorSig
    ) external nonReentrant {
        Session memory s = sessions[key];
        _requireActive(s);
        if (block.timestamp > deadline) revert Expired();
        uint256 currentNonce = nonce;
        bytes32 digest = getSessionAuthExecuteHash(key, s.generation, calls, currentNonce, deadline);
        if (ECDSA.recover(digest, sessionSig) != key) revert BadSessionSignature();
        if (ECDSA.recover(digest, authenticatorSig) != authenticator) revert BadAuthenticatorSignature();

        nonce = currentNonce + 1;
        emit SessionAuthExecuted(key, currentNonce, calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            if (calls[i].to == address(this)) revert SessionCallNotAllowed(i);
        }
        _runCalls(calls);
    }

    // ================================================================== EMERGENCY BRAKES (one key is enough)

    /// @notice Revoke one daily key. Signed by the master, the authenticator, OR the daily key itself.
    function revokeSession(address key, bytes calldata sig) external nonReentrant {
        Session memory s = sessions[key];
        if (s.generation == 0) revert InvalidSession();
        address signer = ECDSA.recover(getRevokeSessionHash(key, s.generation), sig);
        if (signer != owner && signer != authenticator && signer != key) revert NotAuthorizedToRevoke();
        sessions[key].validUntil = 0;
        emit SessionRevoked(key, s.generation, signer);
    }

    /// @notice Revoke every daily key at once. Signed by the master OR the authenticator.
    function revokeAllSessions(bytes calldata sig) external nonReentrant {
        address signer = ECDSA.recover(getRevokeAllHash(sessionEpoch), sig);
        if (signer != owner && signer != authenticator) revert NotAuthorizedToRevoke();
        _revokeAllSessions();
    }

    // ================================================================== RECOVERY (backup key, 48h delay)

    /// @notice Backup key starts replacing the master and/or authenticator (e.g. lost device).
    ///         Kills all daily keys immediately; the key change only happens after RECOVERY_DELAY.
    function initiateRecovery(address newOwner, address newAuthenticator) external nonReentrant {
        if (msg.sender != recovery) revert NotRecoveryKey();
        _validateKeys(newOwner, newAuthenticator, recovery);

        uint64 readyAt = uint64(block.timestamp + RECOVERY_DELAY);
        pendingRecovery = PendingRecovery(newOwner, newAuthenticator, readyAt);
        _revokeAllSessions();
        emit RecoveryInitiated(newOwner, newAuthenticator, readyAt);
    }

    /// @notice After the delay, anyone can finish the recovery.
    function finalizeRecovery() external nonReentrant {
        PendingRecovery memory p = pendingRecovery;
        if (p.readyAt == 0) revert NoPendingRecovery();
        if (block.timestamp < p.readyAt) revert RecoveryNotReady();

        delete pendingRecovery;
        nonce += 1; // kill any signatures made with the old keys
        _revokeAllSessions();
        _setKeys(p.newOwner, p.newAuthenticator, recovery);
        emit RecoveryFinalized(p.newOwner, p.newAuthenticator);
    }

    // ================================================================== views

    function isSessionActive(address key) public view returns (bool) {
        Session memory s = sessions[key];
        return s.generation != 0 && s.validUntil > block.timestamp && s.epoch == sessionEpoch;
    }

    /// @notice How much a daily key has spent today and its cap, for an asset (NATIVE = address(0)).
    function sessionSpentToday(address key, address asset) external view returns (uint256 spent, uint256 cap) {
        bytes32 sid = _sessionId(key, sessions[key].generation);
        Spend memory sp = _spent[sid][asset];
        spent = sp.day == block.timestamp / 1 days ? sp.amount : 0;
        cap = (asset == NATIVE || _isToken[sid][asset]) ? _caps[sid][asset] : 0;
    }

    function sessionTokens(address key) external view returns (address[] memory) {
        return _tokens[_sessionId(key, sessions[key].generation)];
    }

    function isSessionTarget(address key, address target) external view returns (bool) {
        return _isTarget[_sessionId(key, sessions[key].generation)][target];
    }

    // ------------------------------------------------------------------ hashes (what the devices sign)

    function getExecuteHash(Call[] calldata calls, uint256 nonce_, uint256 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(EXECUTE_TYPEHASH, _hashCalls(calls), nonce_, deadline)));
    }

    function getRotateHash(
        address newOwner,
        address newAuthenticator,
        address newRecovery,
        uint256 nonce_,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(ROTATE_TYPEHASH, newOwner, newAuthenticator, newRecovery, nonce_, deadline))
        );
    }

    function getCancelHash(uint256 nonce_, uint256 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CANCEL_TYPEHASH, nonce_, deadline)));
    }

    function getAddSessionHash(SessionParams calldata p, uint256 nonce_, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ADD_SESSION_TYPEHASH,
                    p.key,
                    p.validUntil,
                    p.ethDailyCap,
                    keccak256(abi.encodePacked(p.tokens)),
                    keccak256(abi.encodePacked(p.tokenDailyCaps)),
                    keccak256(abi.encodePacked(p.targets)),
                    nonce_,
                    deadline
                )
            )
        );
    }

    function getSessionExecuteHash(
        address key,
        uint64 generation,
        uint64 sessionNonce,
        Call[] calldata calls,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(SESSION_EXECUTE_TYPEHASH, key, generation, sessionNonce, _hashCalls(calls), deadline)
            )
        );
    }

    function getSessionAuthExecuteHash(
        address key,
        uint64 generation,
        Call[] calldata calls,
        uint256 nonce_,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(SESSION_AUTH_EXECUTE_TYPEHASH, key, generation, _hashCalls(calls), nonce_, deadline))
        );
    }

    function getRevokeSessionHash(address key, uint64 generation) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REVOKE_SESSION_TYPEHASH, key, generation)));
    }

    function getRevokeAllHash(uint64 epoch) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(REVOKE_ALL_TYPEHASH, epoch)));
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ------------------------------------------------------------------ receiving NFTs

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    // ------------------------------------------------------------------ internals

    function _runCalls(Call[] calldata calls) private {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret); // all-or-nothing
        }
    }

    function _hashCalls(Call[] calldata calls) private pure returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] = keccak256(abi.encode(CALL_TYPEHASH, calls[i].to, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(callHashes));
    }

    /// @dev What a daily key may call on its own:
    ///      - plain coin transfers (no data) to anyone, counted against the daily cap
    ///      - on its listed tokens: only transfer() and approve() - and approve only to approved apps
    ///      - any function on approved apps
    function _sessionCallAllowed(bytes32 sid, Call calldata c) private view returns (bool) {
        if (c.to == address(this)) return false;
        if (c.data.length == 0) return true;
        if (_isToken[sid][c.to]) {
            if (c.data.length < 4) return false;
            bytes4 selector = bytes4(c.data[:4]);
            if (selector == IERC20.transfer.selector) return true;
            if (selector == IERC20.approve.selector) {
                if (c.data.length < 36) return false;
                address spender = address(uint160(uint256(bytes32(c.data[4:36]))));
                return _isTarget[sid][spender];
            }
            return false;
        }
        return _isTarget[sid][c.to];
    }

    function _recordSpend(bytes32 sid, address asset, uint256 amount) private {
        uint64 today = uint64(block.timestamp / 1 days);
        Spend memory sp = _spent[sid][asset];
        uint256 total = (sp.day == today ? sp.amount : 0) + amount;
        uint256 cap = _caps[sid][asset];
        if (total > cap) revert SpendLimitExceeded(asset, total, cap);
        _spent[sid][asset] = Spend(today, uint192(total)); // safe: total <= cap <= uint192 max
    }

    function _requireActive(Session memory s) private view {
        if (s.generation == 0 || s.validUntil <= block.timestamp || s.epoch != sessionEpoch) revert SessionInactive();
    }

    function _revokeAllSessions() private {
        uint64 newEpoch = sessionEpoch + 1;
        sessionEpoch = newEpoch;
        emit AllSessionsRevoked(newEpoch);
    }

    function _sessionId(address key, uint64 generation) private pure returns (bytes32) {
        return keccak256(abi.encode(key, generation));
    }

    function _validateSessionParams(SessionParams calldata p) private view {
        if (p.key == address(0) || p.key == owner || p.key == authenticator || p.key == recovery) {
            revert InvalidSession();
        }
        if (p.key == address(this)) revert InvalidSession();
        if (p.validUntil <= block.timestamp || p.validUntil > block.timestamp + MAX_SESSION_DURATION) {
            revert InvalidSession();
        }
        if (p.ethDailyCap > type(uint192).max) revert InvalidSession();
        if (p.tokens.length != p.tokenDailyCaps.length || p.tokens.length > MAX_SESSION_TOKENS) revert InvalidSession();
        if (p.targets.length > MAX_SESSION_TARGETS) revert InvalidSession();

        for (uint256 i = 0; i < p.tokens.length; i++) {
            if (p.tokens[i] == address(0) || p.tokens[i] == address(this)) revert InvalidSession();
            if (p.tokenDailyCaps[i] > type(uint192).max) revert InvalidSession();
            for (uint256 j = i + 1; j < p.tokens.length; j++) {
                if (p.tokens[i] == p.tokens[j]) revert InvalidSession();
            }
        }
        for (uint256 i = 0; i < p.targets.length; i++) {
            address t = p.targets[i];
            if (t == address(0) || t == address(this)) revert InvalidSession();
            // a listed token can't also be a free-for-all target, or the transfer/approve rules could be skipped
            for (uint256 j = 0; j < p.tokens.length; j++) {
                if (t == p.tokens[j]) revert InvalidSession();
            }
        }
    }

    function _checkBothSigned(bytes32 digest, uint256 deadline, bytes calldata ownerSig, bytes calldata authSig)
        private
        view
    {
        if (block.timestamp > deadline) revert Expired();
        if (ECDSA.recover(digest, ownerSig) != owner) revert BadOwnerSignature();
        if (ECDSA.recover(digest, authSig) != authenticator) revert BadAuthenticatorSignature();
    }

    function _setKeys(address owner_, address authenticator_, address recovery_) private {
        _validateKeys(owner_, authenticator_, recovery_);
        owner = owner_;
        authenticator = authenticator_;
        recovery = recovery_;
        emit KeysRotated(owner_, authenticator_, recovery_);
    }

    /// @dev All three main keys must be real and all different, so one stolen key can never count twice.
    function _validateKeys(address owner_, address authenticator_, address recovery_) private pure {
        if (owner_ == address(0) || authenticator_ == address(0) || recovery_ == address(0)) revert InvalidKeys();
        if (owner_ == authenticator_ || owner_ == recovery_ || authenticator_ == recovery_) revert InvalidKeys();
    }
}
