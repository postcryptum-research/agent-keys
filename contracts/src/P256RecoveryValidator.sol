// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1271_INVALID} from "kernel/src/types/Constants.sol";

import {P256Validator} from "./P256Validator.sol";

/// @title P256RecoveryValidator
/// @notice `P256Validator` under its own address, for a cold recovery key.
///
/// Kernel keys a validator's state by (validator contract, account), so a
/// second P-256 key on the same account needs a second contract. The owner
/// installs this one with the recovery key and grants it a single selector,
/// `changeRootValidator`: if the owner's device is lost or breaks, the
/// recovery key can make itself root and hand root to a new device — and
/// nothing else (docs/RESILIENCE.md). Its key is as powerful as root and is
/// kept cold accordingly (docs/KEY_POLICY.md, rule 5).
///
/// It never vouches for an ERC-1271 signature: Kernel asks any installed
/// validator to verify one without checking the selectors granted to it, so
/// a recovery key that could sign messages would sign permits for the
/// account without ever becoming root.
contract P256RecoveryValidator is P256Validator {
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return ERC1271_INVALID;
    }
}
