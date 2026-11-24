// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P256} from "solady/utils/P256.sol";
import {IValidator} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
import {P256Point} from "./P256Point.sol";

/// @title P256Validator
/// @notice ERC-7579 validator for an account owned by a raw P-256 (secp256r1)
/// key held in hardware — a TPM 2.0, a Secure Enclave — that never leaves it.
///
/// The signature is the bare ECDSA pair `abi.encodePacked(r, s)` (64 bytes)
/// over the hash the account hands us: `userOpHash` for ERC-4337, the wrapped
/// hash for ERC-1271. There is no WebAuthn envelope because the chip signs a
/// digest and nothing more. Verification goes through the RIP-7212 precompile
/// via Solady's `P256`, which rejects high-s, so every accepted signature is
/// canonical.
contract P256Validator is IValidator {
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    error InvalidPublicKey();

    event P256KeyRegistered(address indexed account, bytes32 x, bytes32 y);

    mapping(address account => PublicKey) public publicKeys;

    /// @param data `abi.encode(bytes32 x, bytes32 y)`: the enrolled hardware key.
    function onInstall(bytes calldata data) external payable override {
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        if (data.length < 64) revert InvalidPublicKey();
        (bytes32 x, bytes32 y) = abi.decode(data[:64], (bytes32, bytes32));
        if (!P256Point.isOnCurve(x, y)) revert InvalidPublicKey();
        publicKeys[msg.sender] = PublicKey(x, y);
        emit P256KeyRegistered(msg.sender, x, y);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete publicKeys[msg.sender];
    }

    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _isInitialized(account);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return _verify(msg.sender, userOpHash, userOp.signature)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        virtual
        override
        returns (bytes4)
    {
        return _verify(msg.sender, hash, signature) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function _isInitialized(address account) internal view returns (bool) {
        return publicKeys[account].x != 0;
    }

    function _verify(address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 64) return false;
        PublicKey memory key = publicKeys[account];
        if (key.x == 0) return false;
        (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
        return P256.verifySignature(hash, r, s, key.x, key.y);
    }
}
