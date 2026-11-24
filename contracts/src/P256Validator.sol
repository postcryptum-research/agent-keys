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

/// @title P256Validator - ERC-7579 validator for a P-256 key held in hardware
/// @notice ERC-7579 validator for an account owned by a raw P-256 (secp256r1)
/// key held in hardware — a TPM 2.0, a Secure Enclave — that never leaves it.
/// @dev The signature is the bare ECDSA pair `abi.encodePacked(r, s)` (64 bytes)
/// over the hash the account hands us: `userOpHash` for ERC-4337, the wrapped
/// hash for ERC-1271. There is no WebAuthn envelope because the chip signs a
/// digest and nothing more. Verification goes through the RIP-7212 precompile
/// via Solady's `P256`, which rejects high-s, so every accepted signature is
/// canonical.
///
/// Kernel calls this module from the account, so `msg.sender` is the account
/// whose key is installed, checked or removed. The
/// contract has no owner and no admin function: one deployment serves every
/// account, and an account can only reach its own key. The key is kept per
/// account and nothing else, which is also the storage ERC-7562 lets the
/// validation of that account read.
contract P256Validator is IValidator {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    /// `P256RecoveryValidator` inherits it (a constant cannot be redeclared), so
    /// a change to either contract raises it.
    string public constant VERSION = "0.1.0";

    // A P-256 public key in affine coordinates, each below the field prime p
    struct PublicKey {
        // The x coordinate, big-endian
        bytes32 x;
        // The y coordinate, big-endian
        bytes32 y;
    }

    /// @dev The install data is shorter than two words, or its point is not on P-256.
    error InvalidPublicKey();

    /// @dev Emitted when an account enrolls its key.
    /// @param account The account that installed this validator.
    /// @param x The key's x coordinate.
    /// @param y The key's y coordinate.
    event P256KeyRegistered(address indexed account, bytes32 x, bytes32 y);

    // Map of account => its enrolled key; `x == 0` marks an account without one.
    // The account is the mapping's key, so the key's two words sit at
    // keccak256(account ‖ slot) and the word after it: storage that ERC-7562
    // associates with the account, which its validation may read.
    mapping(address account => PublicKey) public publicKeys;

    /// @dev Enrolls the account's hardware key. Kernel calls it when the account
    /// installs this validator, as root or as a further validator.
    /// An account that already has a key here cannot enroll another over it: it
    /// uninstalls first, or uses another instance of the contract
    /// (`P256RecoveryValidator` is one).
    /// @param data `abi.encode(bytes32 x, bytes32 y)`: the enrolled hardware key.
    function onInstall(bytes calldata data) external payable override {
        // The account must not have a key here yet
        if (_isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        // The data must hold both coordinates
        if (data.length < 64) revert InvalidPublicKey();
        // Decode the first two words; anything after them is not read
        (bytes32 x, bytes32 y) = abi.decode(data[:64], (bytes32, bytes32));
        // An off-curve key would fail every signature and lock the account out
        if (!P256Point.isOnCurve(x, y)) revert InvalidPublicKey();
        // Store the key under the account and record it
        publicKeys[msg.sender] = PublicKey(x, y);
        emit P256KeyRegistered(msg.sender, x, y);
    }

    /// @dev Removes the account's key. Kernel calls it when the account
    /// uninstalls this validator, and goes on with the uninstall even if this
    /// call reverts (Kernel's `ModuleLib.uninstallModule`). Kernel refuses to
    /// uninstall the root validator. The data Kernel passes (the only
    /// parameter) is not read.
    function onUninstall(bytes calldata) external payable override {
        // The account must have a key here
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        // Clear both words of the key
        delete publicKeys[msg.sender];
    }

    /// @dev Tells Kernel which ERC-7579 module type this is.
    /// @param typeId An ERC-7579 module type id.
    /// @return True only for the validator type (`MODULE_TYPE_VALIDATOR`).
    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR;
    }

    /// @dev Whether an account has a key enrolled here.
    /// @param account The account address.
    /// @return True if the account has a key, false otherwise.
    function isInitialized(address account) external view override returns (bool) {
        return _isInitialized(account);
    }

    /// @dev Checks a user operation's signature against the account's key. The
    /// account calls it in the ERC-4337 validation phase, for an operation whose
    /// nonce selects this validator, or selects root while this validator is root.
    /// A bad signature returns a failure and does not revert, as ERC-4337 asks:
    /// the EntryPoint then refuses the operation (AA24). The result carries no
    /// time range.
    /// @param userOp The user operation; only its `signature` is read.
    /// @param userOpHash The EntryPoint's hash of the operation: the digest the chip signed.
    /// @return `SIG_VALIDATION_SUCCESS_UINT` (0) if the signature verifies,
    /// `SIG_VALIDATION_FAILED_UINT` (1) otherwise.
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

    /// @dev Checks an ERC-1271 signature against the account's key. Kernel calls
    /// it from the account's `isValidSignature`, with the hash wrapped for this
    /// account, and, while this validator is root, to check the signature that
    /// enables a new validator (Kernel's enable mode). The first
    /// parameter, the address that asked the account, is not read: the key
    /// answers the same to every caller. `virtual` so that
    /// `P256RecoveryValidator` can refuse every request.
    /// @param hash The hash to check, as the account hands it over.
    /// @param signature `abi.encodePacked(r, s)`, 64 bytes.
    /// @return `ERC1271_MAGICVALUE` if the account's key signed `hash`,
    /// `ERC1271_INVALID` otherwise.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        virtual
        override
        returns (bytes4)
    {
        return _verify(msg.sender, hash, signature) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    /// @dev Whether an account has a key enrolled here; `x == 0` marks an empty
    /// slot. The curve does have two points with x = 0, (0, ±√b): such a key
    /// would install, then read as no key and verify nothing. A key made in a
    /// chip is one of them with a chance of about 2^-255.
    /// @param account The account address.
    /// @return True if the account has a key, false otherwise.
    function _isInitialized(address account) internal view returns (bool) {
        return publicKeys[account].x != 0;
    }

    /// @dev Checks a P-256 signature over `hash` against the account's key.
    /// @param account The account whose key is used.
    /// @param hash The digest the key should have signed.
    /// @param signature `abi.encodePacked(r, s)`, 64 bytes.
    /// @return True if the signature verifies under the account's key; false
    /// otherwise, and always for an account without a key.
    function _verify(address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        // Only the bare 64-byte (r, s) pair is accepted
        if (signature.length != 64) return false;
        // Load the account's key; an account without one verifies nothing
        PublicKey memory key = publicKeys[account];
        if (key.x == 0) return false;
        // Split the signature into r and s
        (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
        // RIP-7212 through Solady: false for a high s or a wrong signature; where
        // neither the precompile nor Solady's fallback verifier exists, false too
        return P256.verifySignature(hash, r, s, key.x, key.y);
    }
}
