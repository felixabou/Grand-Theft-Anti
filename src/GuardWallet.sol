// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title GuardWallet
/// @notice A smart-contract wallet where every transaction needs TWO signatures:
///         one from the main key and one from a second "authenticator" device.
///         Stealing one key is not enough to move funds, so sweeper bots can't drain it.
///
///         Three keys:
///           owner         - main key (e.g. phone wallet)
///           authenticator - second device (hardware wallet or spare phone)
///           recovery      - offline backup; can replace lost keys only after a 48h delay
///
///         Design choices for safety:
///           - Only plain CALLs are allowed (no delegatecall), so no outside code can rewrite storage.
///           - Every signature is bound to this wallet, this chain, a one-time nonce and a deadline.
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

    // ------------------------------------------------------------------ constants

    uint256 public constant RECOVERY_DELAY = 48 hours;

    bytes32 public constant CALL_TYPEHASH = keccak256("Call(address to,uint256 value,bytes data)");
    bytes32 public constant EXECUTE_TYPEHASH =
        keccak256("Execute(Call[] calls,uint256 nonce,uint256 deadline)Call(address to,uint256 value,bytes data)");
    bytes32 public constant ROTATE_TYPEHASH = keccak256(
        "RotateKeys(address newOwner,address newAuthenticator,address newRecovery,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant CANCEL_TYPEHASH = keccak256("CancelRecovery(uint256 nonce,uint256 deadline)");

    // ------------------------------------------------------------------ state

    address public owner;
    address public authenticator;
    address public recovery;
    uint256 public nonce;
    PendingRecovery public pendingRecovery;

    // ------------------------------------------------------------------ events

    event Executed(uint256 indexed nonce, uint256 callCount);
    event KeysRotated(address indexed owner, address indexed authenticator, address indexed recovery);
    event RecoveryInitiated(address indexed newOwner, address indexed newAuthenticator, uint64 readyAt);
    event RecoveryCancelled();
    event RecoveryFinalized(address indexed owner, address indexed authenticator);

    // ------------------------------------------------------------------ errors

    error InvalidKeys();
    error Expired();
    error BadOwnerSignature();
    error BadAuthenticatorSignature();
    error NotRecoveryKey();
    error NoPendingRecovery();
    error RecoveryNotReady();
    error CallFailed(uint256 index, bytes reason);

    // ------------------------------------------------------------------ setup

    constructor(address owner_, address authenticator_, address recovery_) EIP712("GuardWallet", "1") {
        _setKeys(owner_, authenticator_, recovery_);
    }

    receive() external payable {}

    // ------------------------------------------------------------------ main action

    /// @notice Run one or more calls (e.g. approve + swap) if BOTH keys signed them.
    ///         Anyone may submit the transaction and pay gas; the signatures are the authorization.
    function execute(
        Call[] calldata calls,
        uint256 deadline,
        bytes calldata ownerSig,
        bytes calldata authenticatorSig
    ) external {
        uint256 currentNonce = nonce;
        bytes32 digest = getExecuteHash(calls, currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);

        nonce = currentNonce + 1; // consume nonce BEFORE any outside call
        emit Executed(currentNonce, calls.length);

        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret); // all-or-nothing
        }
    }

    // ------------------------------------------------------------------ key management

    /// @notice Replace any keys using BOTH current keys. Use this the moment you suspect a key leaked.
    ///         Also cancels any pending recovery.
    function rotateKeys(
        address newOwner,
        address newAuthenticator,
        address newRecovery,
        uint256 deadline,
        bytes calldata ownerSig,
        bytes calldata authenticatorSig
    ) external {
        uint256 currentNonce = nonce;
        bytes32 digest = getRotateHash(newOwner, newAuthenticator, newRecovery, currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);

        nonce = currentNonce + 1;
        delete pendingRecovery;
        _setKeys(newOwner, newAuthenticator, newRecovery);
    }

    /// @notice Backup key starts replacing the owner and/or authenticator (e.g. lost phone).
    ///         Takes effect only after RECOVERY_DELAY, giving you time to cancel if it's a thief.
    function initiateRecovery(address newOwner, address newAuthenticator) external {
        if (msg.sender != recovery) revert NotRecoveryKey();
        _validateKeys(newOwner, newAuthenticator, recovery);

        uint64 readyAt = uint64(block.timestamp + RECOVERY_DELAY);
        pendingRecovery = PendingRecovery(newOwner, newAuthenticator, readyAt);
        emit RecoveryInitiated(newOwner, newAuthenticator, readyAt);
    }

    /// @notice Cancel a recovery you didn't start. Needs BOTH current keys.
    function cancelRecovery(uint256 deadline, bytes calldata ownerSig, bytes calldata authenticatorSig) external {
        if (pendingRecovery.readyAt == 0) revert NoPendingRecovery();
        uint256 currentNonce = nonce;
        bytes32 digest = getCancelHash(currentNonce, deadline);
        _checkBothSigned(digest, deadline, ownerSig, authenticatorSig);

        nonce = currentNonce + 1;
        delete pendingRecovery;
        emit RecoveryCancelled();
    }

    /// @notice After the delay, anyone can finish the recovery.
    function finalizeRecovery() external {
        PendingRecovery memory p = pendingRecovery;
        if (p.readyAt == 0) revert NoPendingRecovery();
        if (block.timestamp < p.readyAt) revert RecoveryNotReady();

        delete pendingRecovery;
        nonce += 1; // kill any signatures made with the old keys
        _setKeys(p.newOwner, p.newAuthenticator, recovery);
        emit RecoveryFinalized(p.newOwner, p.newAuthenticator);
    }

    // ------------------------------------------------------------------ hashes (what the devices sign)

    function getExecuteHash(Call[] calldata calls, uint256 nonce_, uint256 deadline) public view returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] =
                keccak256(abi.encode(CALL_TYPEHASH, calls[i].to, calls[i].value, keccak256(calls[i].data)));
        }
        bytes32 structHash =
            keccak256(abi.encode(EXECUTE_TYPEHASH, keccak256(abi.encodePacked(callHashes)), nonce_, deadline));
        return _hashTypedDataV4(structHash);
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

    /// @dev All three keys must be real and all different, so one stolen key can never count twice.
    function _validateKeys(address owner_, address authenticator_, address recovery_) private pure {
        if (owner_ == address(0) || authenticator_ == address(0) || recovery_ == address(0)) revert InvalidKeys();
        if (owner_ == authenticator_ || owner_ == recovery_ || authenticator_ == recovery_) revert InvalidKeys();
    }
}
