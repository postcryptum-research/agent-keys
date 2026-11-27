// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// @dev How the deploy script names a superseded instance when a redeploy
/// replaces it (`REDEPLOY=true`, house rule 9): `<name>V<n>`, one above the
/// highest version the file records, so that live accounts can still be
/// found and moved.
import {ConduitStandIn} from "./SeaportTrading.t.sol";

contract DeployScriptTest is Test {
    Deploy internal script = new Deploy();

    function test_aVersionedKeyIsReadAsSuch() public view {
        // Positive: a name, `V`, a number
        (bool v, string memory base, uint256 n) = script.versionOf("agentPolicyV8");
        assertTrue(v);
        assertEq(base, "agentPolicy");
        assertEq(n, 8);
        (v, base, n) = script.versionOf("p256ValidatorV12");
        assertTrue(v);
        assertEq(base, "p256Validator");
        assertEq(n, 12);
        // Negative: no number, a leading zero, no name, no `V`, a current key
        string[7] memory not_ =
            ["agentPolicyV", "agentPolicyV08", "V1", "agentPolicy8", "p256Validator", "solc", "evmVersion"];
        for (uint256 i; i < not_.length; i++) {
            (v,,) = script.versionOf(not_[i]);
            assertFalse(v, not_[i]);
        }
    }

    /// The bid decoder is deployed where Seaport is, with the conduit its orders name.
    function test_seaportIsHereOnlyWithItsConduit() public {
        address seaport = 0x0000000000000068F116a894984e2DB1123eB395;
        bytes32 key = 0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000;
        assertFalse(script.seaportIsHere(), "no code at Seaport's address");
        // a Seaport whose controller knows another key
        deployCodeTo(
            "SeaportTrading.t.sol:SeaportStandIn", abi.encode(bytes32(uint256(key) ^ 1), new ConduitStandIn()), seaport
        );
        assertFalse(script.seaportIsHere(), "no conduit behind the key");
        deployCodeTo("SeaportTrading.t.sol:SeaportStandIn", abi.encode(key, new ConduitStandIn()), seaport);
        assertTrue(script.seaportIsHere());
    }

    /// A decoder of rules has a key of its own, which a rewrite of the file keeps.
    function test_aRulesKeyIsReadAsSuch() public view {
        assertTrue(script.isRulesKey("callRulesAaveV3Pool"));
        assertTrue(script.isRulesKey("callRulesX"));
        string[6] memory not_ = ["callRules", "callRule", "CallRulesAave", "cowSwapDecoder", "swapRouter02Decoder", ""];
        for (uint256 i; i < not_.length; i++) {
            assertFalse(script.isRulesKey(not_[i]), not_[i]);
        }
    }

    function test_theNextVersionIsOneAboveTheHighestRecorded() public view {
        string[] memory keys = new string[](7);
        keys[0] = "agentPolicy";
        keys[1] = "agentPolicyV1";
        keys[2] = "agentPolicyV8";
        keys[3] = "agentPolicyV3";
        keys[4] = "p256Validator";
        keys[5] = "p256ValidatorV1";
        keys[6] = "safeNonceAssert";
        assertEq(script.nextVersionKey(keys, "agentPolicy"), "agentPolicyV9");
        assertEq(script.nextVersionKey(keys, "p256Validator"), "p256ValidatorV2");
        // None recorded yet: V1
        assertEq(script.nextVersionKey(keys, "safeNonceAssert"), "safeNonceAssertV1");
        // A name that is a prefix of another is not confused with it
        assertEq(script.nextVersionKey(keys, "agentPolicyV"), "agentPolicyVV1");
    }

    /// @dev The gas limit of a deployment is the chain's estimate, read from
    /// `eth_estimateGas`, with 30% added.
    function test_theChainsEstimateIsReadAndGivenAMargin() public view {
        assertEq(script.quantity(hex"5208"), 21000);
        assertEq(script.quantity(hex"0235592d"), 37050669);
        assertEq(script.quantity(hex"00000000000000ff"), 255);
        // empty, or wider than any gas figure: no estimate
        assertEq(script.quantity(""), 0);
        assertEq(script.quantity(hex"010000000000000000"), 0);
        assertEq(script.withMargin(37058759), 48176386);
        assertEq(script.withMargin(0), 0);
    }

    /// @dev Without an RPC to ask (a test, or a script run without one),
    /// there is no estimate and forge sizes the transaction as before.
    function test_noRpcMeansNoEstimate() public {
        assertEq(script.chainGas(address(this), hex"00"), 0);
    }

    /// @dev Against the file as it stands for Base Sepolia.
    function test_theRecordedFileGivesTheExpectedNames() public view {
        string[] memory keys = vm.parseJsonKeys(vm.readFile("deployments/84532.json"), "$");
        assertEq(script.nextVersionKey(keys, "agentPolicy"), "agentPolicyV12");
        assertEq(script.nextVersionKey(keys, "p256Signer"), "p256SignerV3");
        assertEq(script.nextVersionKey(keys, "demoCounter"), "demoCounterV2");
        assertEq(script.nextVersionKey(keys, "cowSwapDecoder"), "cowSwapDecoderV1");
    }
}
