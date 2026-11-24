// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {P256} from "solady/utils/P256.sol";

/// @notice The reference paper's telemetry logger, with its three
/// EOA-submitted authorization methods side by side. Used only by the gas
/// benchmark; the agent path logs through `DemoCounter` / the smart account.
///
///  - addressOnly: the sending EOA must be on an allow-list
///  - k1:          an independent secp256k1 signature over the payload
///  - r1:          an independent P-256 signature over the payload (RIP-7212)
contract Logger {
    /// @dev The version of this contract's code (semantic versioning), raised with
    /// any change to its bytecode. A release tag names the versions it carries.
    string public constant VERSION = "0.1.0";

    event Logged(address indexed by, bytes payload);

    error NotAllowed();
    error BadSignature();

    mapping(address => bool) public allowed;
    address public k1Signer;
    bytes32 public r1X;
    bytes32 public r1Y;

    constructor(address sender, address k1, bytes32 x, bytes32 y) {
        allowed[sender] = true;
        k1Signer = k1;
        r1X = x;
        r1Y = y;
    }

    function logAddressOnly(bytes calldata payload) external {
        if (!allowed[msg.sender]) revert NotAllowed();
        emit Logged(msg.sender, payload);
    }

    function logK1(bytes calldata payload, bytes calldata signature) external {
        if (ECDSA.recover(keccak256(payload), signature) != k1Signer) revert BadSignature();
        emit Logged(msg.sender, payload);
    }

    function logR1(bytes calldata payload, bytes32 r, bytes32 s) external {
        if (!P256.verifySignature(keccak256(payload), r, s, r1X, r1Y)) revert BadSignature();
        emit Logged(msg.sender, payload);
    }

    /// The agent path: the smart account is the caller, as with DemoCounter.
    function log(bytes calldata payload) external {
        emit Logged(msg.sender, payload);
    }
}
