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

/// @title P256Signer
/// @notice Kernel permission signer for a raw P-256 key held in hardware.
///
/// Where `P256Validator` makes the chip the account's root, this module makes
/// it one *permission*: the key only authorizes what the policies installed
/// next to it allow. That is the agent setup — the TPM key signs the agent's
/// operations, the account's root stays with its owner, and `AgentPolicy`
/// bounds the damage a compromised agent host can do.
///
/// Keys are scoped per `(permission id, account)`. The signature is the bare
/// low-s `abi.encodePacked(r, s)`; Kernel strips the permission framing
/// before handing it over.
contract P256Signer is ISigner {
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    error InvalidPublicKey();

    event P256SignerRegistered(address indexed account, bytes32 indexed id, bytes32 x, bytes32 y);

    mapping(bytes32 id => mapping(address account => PublicKey)) public publicKeys;
    mapping(address account => uint256) public usedIds;

    /// @param data `bytes32 id ++ abi.encode(bytes32 x, bytes32 y)`, as Kernel packs it.
    function onInstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        if (publicKeys[id][msg.sender].x != 0) revert AlreadyInitialized(msg.sender);
        if (data.length < 96) revert InvalidPublicKey();
        (bytes32 x, bytes32 y) = abi.decode(data[32:96], (bytes32, bytes32));
        if (!P256Point.isOnCurve(x, y)) revert InvalidPublicKey();
        publicKeys[id][msg.sender] = PublicKey(x, y);
        usedIds[msg.sender]++;
        emit P256SignerRegistered(msg.sender, id, x, y);
    }

    function onUninstall(bytes calldata data) external payable override {
        bytes32 id = bytes32(data[0:32]);
        if (publicKeys[id][msg.sender].x == 0) revert NotInitialized(msg.sender);
        delete publicKeys[id][msg.sender];
        usedIds[msg.sender]--;
    }

    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_SIGNER;
    }

    function isInitialized(address account) external view override returns (bool) {
        return usedIds[account] > 0;
    }

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

    function checkSignature(bytes32 id, address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        return _verify(id, msg.sender, hash, signature) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function _verify(bytes32 id, address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signature.length != 64) return false;
        PublicKey memory key = publicKeys[id][account];
        if (key.x == 0) return false;
        (bytes32 r, bytes32 s) = abi.decode(signature, (bytes32, bytes32));
        return P256.verifySignature(hash, r, s, key.x, key.y);
    }
}
