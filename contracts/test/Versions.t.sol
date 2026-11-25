// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {P256Validator} from "../src/P256Validator.sol";
import {P256RecoveryValidator} from "../src/P256RecoveryValidator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {DemoCounter} from "../src/demo/DemoCounter.sol";
import {Logger} from "../src/demo/Logger.sol";
import {IEntryPoint as IAAEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "kernel/test/base/erc4337Util.sol";

/// @dev Stands in for CoW's settlement: the decoder reads these two in its constructor.
contract SettlementForVersion {
    bytes32 public domainSeparator = keccak256("a domain");
    address public vaultRelayer = address(0xBEEF);
}

/// @dev Every deployable contract answers `VERSION()` with its version, so that
/// an instance on chain says which code it is. All started at 0.1.0; a
/// change to a contract's bytecode raises its version (CLAUDE.md, versions
/// and releases), and that contract's line here then names its own.
contract VersionsTest is Test {
    string internal constant FIRST = "0.1.0";
    // install data of exactly the expected length (#154)
    string internal constant P256_MODULES = "0.1.1";

    function test_everyDeployableContractCarriesItsVersion() public {
        // Contracts without constructor arguments
        assertEq(new P256Validator().VERSION(), P256_MODULES, "P256Validator");
        assertEq(new P256RecoveryValidator().VERSION(), P256_MODULES, "P256RecoveryValidator");
        assertEq(new P256Signer().VERSION(), P256_MODULES, "P256Signer");
        assertEq(new SafeNonceAssert().VERSION(), FIRST, "SafeNonceAssert");
        assertEq(new DemoCounter().VERSION(), FIRST, "DemoCounter");
        assertEq(new Logger(address(this), address(this), bytes32(0), bytes32(0)).VERSION(), FIRST, "Logger");
        // Contracts with constructor arguments, given stand-ins
        // 0.1.1: a venue's spender is refused as a target (issue #149)
        assertEq(new AgentPolicy(address(new SafeNonceAssert())).VERSION(), "0.1.1", "AgentPolicy");
        assertEq(new CowSwapDecoder(address(new SettlementForVersion())).VERSION(), FIRST, "CowSwapDecoder");
        IAAEntryPoint entryPoint = IAAEntryPoint(EntryPointLib.deploy());
        assertEq(new WhitelistPaymaster(entryPoint, address(this)).VERSION(), FIRST, "WhitelistPaymaster");
    }
}
