// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {P256Validator} from "../src/P256Validator.sol";
import {P256RecoveryValidator} from "../src/P256RecoveryValidator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {OneInchLimitOrderDecoder} from "../src/venues/OneInchLimitOrderDecoder.sol";
import {RouterStandIn} from "./OneInchLimitOrderDecoder.t.sol";
import {SwapRouter02Decoder} from "../src/venues/SwapRouter02Decoder.sol";
import {CallRulesDecoder} from "../src/venues/CallRulesDecoder.sol";
import {SeaportBidDecoder} from "../src/venues/SeaportBidDecoder.sol";
import {SeaportStandIn, ConduitStandIn} from "./SeaportTrading.t.sol";
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
/// an instance on chain says which code it is. Every contract stays at 0.1.0
/// until the first audited release; from then on a change to a contract's
/// bytecode raises its version (CLAUDE.md, rule 9), and that contract's line
/// here then names its own.
contract VersionsTest is Test {
    string internal constant FIRST = "0.1.0";

    function test_everyDeployableContractCarriesItsVersion() public {
        // Contracts without constructor arguments
        assertEq(new P256Validator().VERSION(), FIRST, "P256Validator");
        assertEq(new P256RecoveryValidator().VERSION(), FIRST, "P256RecoveryValidator");
        assertEq(new P256Signer().VERSION(), FIRST, "P256Signer");
        assertEq(new SafeNonceAssert().VERSION(), FIRST, "SafeNonceAssert");
        assertEq(new DemoCounter().VERSION(), FIRST, "DemoCounter");
        assertEq(new Logger(address(this), address(this), bytes32(0), bytes32(0)).VERSION(), FIRST, "Logger");
        // Contracts with constructor arguments, given stand-ins
        assertEq(new AgentPolicy(address(new SafeNonceAssert())).VERSION(), FIRST, "AgentPolicy");
        assertEq(new CowSwapDecoder(address(new SettlementForVersion())).VERSION(), FIRST, "CowSwapDecoder");
        assertEq(
            new OneInchLimitOrderDecoder(address(new RouterStandIn())).VERSION(), FIRST, "OneInchLimitOrderDecoder"
        );
        // any contract stands in for the swap router: the decoder asks only for code there
        assertEq(new SwapRouter02Decoder(address(new RouterStandIn())).VERSION(), FIRST, "SwapRouter02Decoder");
        // any contract stands in for the venue and its spender: the decoder asks only for code there
        address standIn = address(new RouterStandIn());
        assertEq(new CallRulesDecoder(standIn, standIn).VERSION(), FIRST, "CallRulesDecoder");
        // a Seaport that hashes an order as the decoder does, through Seaport itself (the key of zero)
        address seaport = address(new SeaportStandIn(bytes32(uint256(1)), new ConduitStandIn()));
        assertEq(new SeaportBidDecoder(seaport, bytes32(0)).VERSION(), FIRST, "SeaportBidDecoder");
        IAAEntryPoint entryPoint = IAAEntryPoint(EntryPointLib.deploy());
        assertEq(new WhitelistPaymaster(entryPoint, address(this)).VERSION(), FIRST, "WhitelistPaymaster");
    }
}
