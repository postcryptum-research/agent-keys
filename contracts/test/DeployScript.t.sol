// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// @dev How the deploy script names a superseded instance when a redeploy
/// replaces it (`REDEPLOY=true`, house rule 9): `<name>V<n>`, one above the
/// highest version the file records, so that live accounts can still be
/// found and moved.
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
        string[7] memory not_ = ["agentPolicyV", "agentPolicyV08", "V1", "agentPolicy8", "p256Validator", "solc", "evmVersion"];
        for (uint256 i; i < not_.length; i++) {
            (v,,) = script.versionOf(not_[i]);
            assertFalse(v, not_[i]);
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

    /// @dev Against the file as it stands for Base Sepolia.
    function test_theRecordedFileGivesTheExpectedNames() public view {
        string[] memory keys = vm.parseJsonKeys(vm.readFile("deployments/84532.json"), "$");
        assertEq(script.nextVersionKey(keys, "agentPolicy"), "agentPolicyV9");
        assertEq(script.nextVersionKey(keys, "p256Signer"), "p256SignerV2");
        assertEq(script.nextVersionKey(keys, "demoCounter"), "demoCounterV1");
    }
}
