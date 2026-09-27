// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {GuardWallet} from "./GuardWallet.sol";

/// @title GuardWalletFactory
/// @notice Deploys GuardWallets with CREATE2 so the address is known in advance and identical on every
///         EVM chain (as long as this factory sits at the same address on each chain and the code is
///         compiled with identical settings).
///
///         The address is derived from your three starting keys, so nobody else can deploy a wallet
///         that lands on "your" address with different keys. That makes it safe to receive funds on a
///         chain before the wallet is deployed there.
contract GuardWalletFactory {
    event WalletCreated(address indexed wallet, address indexed owner, address indexed authenticator, address recovery);

    function createWallet(address owner, address authenticator, address recovery, bytes32 salt)
        external
        returns (GuardWallet wallet)
    {
        wallet = new GuardWallet{salt: salt}(owner, authenticator, recovery);
        emit WalletCreated(address(wallet), owner, authenticator, recovery);
    }

    function predictAddress(address owner, address authenticator, address recovery, bytes32 salt)
        external
        view
        returns (address)
    {
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(GuardWallet).creationCode, abi.encode(owner, authenticator, recovery)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)))));
    }
}
