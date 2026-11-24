// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {P256} from "solady/utils/P256.sol";
import {ISigner} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_SIGNER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
import {P256Point} from "./P256Point.sol";

/// @title P256Signer - Kernel permission signer for a P-256 key held in hardware
/// @notice Kernel permission signer for a raw P-256 key held in hardware.
/// @dev Where `P256Validator` makes the chip the account's root, this module makes
/// it one *permission*: the key only authorizes what the policies installed
/// next to it allow. That is the agent setup — the TPM key signs the agent's
/// operations, the account's root stays with its owner, and `AgentPolicy`
/// bounds the damage a compromised agent host can do.
///
/// Keys are scoped per `(permission id, account)`. The signature is the bare
/// low-s `abi.encodePacked(r, s)`; Kernel strips the permission framing
/// before handing it over.
///
/// Kernel calls this module from the account, so `msg.sender` is the account.
/// The contract has no owner and no admin function: one deployment serves
/// every account, and an account can only reach its own keys. Every slot it
/// keeps has the account as the innermost mapping key, which is the storage
/// ERC-7562 lets the validation of that account read and write.
contract P256Signer is ISigner {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.1";

    // A P-256 public key in affine coordinates, each below the field prime p
    struct PublicKey {
        // The x coordinate, big-endian
        bytes32 x;
        // The y coordinate, big-endian
        bytes32 y;
    }

    /// @dev The install data is not exactly the id and two words, or its point is not on P-256.
    error InvalidPublicKey();

    /// @dev Emitted when an account installs a permission with this signer.
    /// @param account The account that installed the permission.
    /// @param id The permission id, as Kernel passes it (the 4-byte id, left-aligned).
    /// @param x The key's x coordinate.
    /// @param y The key's y coordinate.
    event P256SignerRegistered(address indexed account, bytes32 indexed id, bytes32 x, bytes32 y);

    // Map of permission id => account => the permission's key; `x == 0` marks no key.
    // The account is the inner key, so the key's words sit at
    // keccak256(account ‖ keccak256(id ‖ slot)) and the word after it: storage
    // that ERC-7562 associates with the account. Were the id the inner key, the
    // slot would not be the account's, and a bundler that enforces the rules
    // would refuse the operation.
    mapping(bytes32 id => mapping(address account => PublicKey)) public publicKeys;
    // Map of account => the number of its permissions that use this signer; `isInitialized` reads it
    mapping(address account => uint256) public usedIds;

    /// @dev Enrolls the key of one permission of the account. Kernel calls it when
    /// the account installs a permission whose signer is this contract.
    /// A permission id that already has a key here for the account cannot get
    /// another over it: to change the key, the permission is uninstalled first.
    /// @param data `bytes32 id ++ abi.encode(bytes32 x, bytes32 y)`, as Kernel packs it: exactly 96 bytes.
    function onInstall(bytes calldata data) external payable override {
        // The permission id comes first, as Kernel packs it
        bytes32 id = bytes32(data[0:32]);
        // This permission must not have a key yet
        if (publicKeys[id][msg.sender].x != 0) revert AlreadyInitialized(msg.sender);
        // The data must be the id and both coordinates, and nothing more
        if (data.length != 96) revert InvalidPublicKey();
        // Decode the two words after the id
        (bytes32 x, bytes32 y) = abi.decode(data[32:96], (bytes32, bytes32));
        // An off-curve key would fail every signature and leave the permission dead
        if (!P256Point.isOnCurve(x, y)) revert InvalidPublicKey();
        // Store the key, count the permission, and record it
        publicKeys[id][msg.sender] = PublicKey(x, y);
        usedIds[msg.sender]++;
        emit P256SignerRegistered(msg.sender, id, x, y);
    }

    /// @dev Removes the key of one permission of the account. Kernel calls it when
    /// the account uninstalls the permission, and goes on with the uninstall
    /// even if this call reverts (Kernel's `ModuleLib.uninstallModule`).
    /// @param data `bytes32 id ++ ...`, as Kernel packs it; only the id is read.
    function onUninstall(bytes calldata data) external payable override {
        // The permission id comes first, as Kernel packs it
        bytes32 id = bytes32(data[0:32]);
        // This permission must have a key here
        if (publicKeys[id][msg.sender].x == 0) revert NotInitialized(msg.sender);
        // Clear the key and uncount the permission; the count cannot underflow,
        // since every stored key was counted once when it was installed
        delete publicKeys[id][msg.sender];
        usedIds[msg.sender]--;
    }

    /// @dev Tells Kernel which ERC-7579 module type this is.
    /// @param typeId An ERC-7579 module type id.
    /// @return True only for the signer type (`MODULE_TYPE_SIGNER`).
    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_SIGNER;
    }

    /// @dev Whether any permission of the account uses this signer. Keys are kept
    /// per permission, so the count of them answers for the account as a whole.
    /// @param account The account address.
    /// @return True if at least one of the account's permissions has a key here, false otherwise.
    function isInitialized(address account) external view override returns (bool) {
        return usedIds[account] > 0;
    }

    /// @dev Checks a user operation's signature against the permission's key. The
    /// account calls it in the ERC-4337 validation phase, after the
    /// permission's policies, for an operation whose nonce selects this
    /// permission. A bad signature returns a failure and does not revert, as
    /// ERC-4337 asks: the EntryPoint then refuses the operation (AA24). The
    /// result carries no time range; the policies' results carry theirs.
    /// @param id The permission id the operation's nonce selects.
    /// @param userOp The user operation, its `signature` already stripped of
    /// the permission framing by Kernel; only `signature` is read.
    /// @param userOpHash The EntryPoint's hash of the operation: the digest the chip signed.
    /// @return `SIG_VALIDATION_SUCCESS_UINT` (0) if the signature verifies,
    /// `SIG_VALIDATION_FAILED_UINT` (1) otherwise.
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        return _verify(id, msg.sender, userOpHash, userOp.signature)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    /// @dev Checks an ERC-1271 signature against the permission's key. Kernel
    /// calls it from the account's `isValidSignature`, with the hash wrapped
    /// for this account, only after the permission's policies have accepted
    /// the request: what the agent may sign is the policies' decision
    /// (`AgentPolicy` refuses all but registered x402 authorizations). The
    /// second parameter, the address that asked the account, is not read.
    /// @param id The permission id the signature names.
    /// @param hash The hash to check, as the account hands it over.
    /// @param signature `abi.encodePacked(r, s)`, 64 bytes.
    /// @return `ERC1271_MAGICVALUE` if the permission's key signed `hash`,
    /// `ERC1271_INVALID` otherwise.
    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        return _verify(id, msg.sender, hash, signature) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    /// @dev Checks a P-256 signature over `hash` against the key of one permission of the account.
    /// @param id The permission id.
    /// @param account The account whose permission it is.
    /// @param hash The digest the key should have signed.
    /// @param signature `abi.encodePacked(r, s)`, 64 bytes.
    /// @return True if the signature verifies under the permission's key; false
    /// otherwise, and always for a permission without a key.
    function _verify(bytes32 id, address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        // Only the bare 64-byte (r, s) pair is accepted
        if (signature.length != 64) return false;
        // Load the permission's key; a permission without one verifies nothing
        PublicKey memory key = publicKeys[id][account];
        if (key.x == 0) return false;
        // Split the signature into r and s
        (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
        // RIP-7212 through Solady: false for a high s or a wrong signature; where
        // neither the precompile nor Solady's fallback verifier exists, false too
        return P256.verifySignature(hash, r, s, key.x, key.y);
    }
}
