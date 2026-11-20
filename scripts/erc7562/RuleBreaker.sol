// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// A test policy for a Kernel permission. It approves every operation and,
/// while doing so (that is, during validation), does exactly one thing chosen
/// at deployment. Used to find out which ERC-7562 rules a bundler enforces.
///
///   1  reads TIMESTAMP                                   (a banned opcode)
///   2  writes persistent storage at slot 0               (not the sender's)
///   3  writes transient storage at slot 0                (not the sender's)
///   4  writes transient storage at keccak(sender . 1)    (the sender's: allowed)
///   5  writes persistent storage at keccak(sender . 1)   (the sender's: allowed)
contract RuleBreaker {
    uint256 internal sink; // slot 0
    uint8 public immutable mode;

    constructor(uint8 m) {
        mode = m;
    }

    function onInstall(bytes calldata) external payable {}

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 t) external pure returns (bool) {
        return t == 5;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable returns (uint256) {
        uint8 m = mode;
        if (m == 1) {
            if (block.timestamp == 0) revert();
        } else if (m == 2) {
            sink += 1;
        } else if (m == 3) {
            assembly {
                tstore(0, add(tload(0), 1))
            }
        } else if (m == 4 || m == 5) {
            uint256 slot = uint256(keccak256(abi.encode(msg.sender, uint256(1))));
            if (m == 4) {
                assembly {
                    tstore(slot, add(tload(slot), 1))
                }
            } else {
                assembly {
                    sstore(slot, add(sload(slot), 1))
                }
            }
        }
        return 0;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure returns (uint256) {
        return 0;
    }

    /// Any view the CLI may ask of an AgentPolicy answers with zeros.
    fallback() external payable {
        assembly {
            return(0, 0x200)
        }
    }
}
