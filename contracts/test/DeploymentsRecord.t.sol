// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";

/// @dev The compiler settings recorded in the deployments files (issue #123)
/// are the ones `foundry.toml` builds with. The deploy script writes them, so
/// the script's constants, `foundry.toml` and every recorded chain's file must
/// agree; a file that lacks them fails here until they are added.
contract DeploymentsRecordTest is Test {
    /// @dev Chains with a deployments file in this repository: Base Sepolia
    /// and Sepolia. A chain listed here whose file does not exist yet is skipped.
    uint256[2] internal chains = [uint256(84532), uint256(11155111)];

    function test_recordedBuildIsFoundryToml() public {
        // The settings foundry.toml builds every contract with
        string memory toml = vm.readFile("foundry.toml");
        string memory solc = vm.parseTomlString(toml, ".profile.default.solc");
        string memory evmVersion = vm.parseTomlString(toml, ".profile.default.evm_version");

        // The deploy script writes its own constants into the file it records
        Deploy script = new Deploy();
        assertEq(script.SOLC(), solc, "Deploy.s.sol SOLC differs from foundry.toml");
        assertEq(script.EVM_VERSION(), evmVersion, "Deploy.s.sol EVM_VERSION differs from foundry.toml");

        // Every chain's recorded file carries the same two values
        uint256 checked;
        for (uint256 i; i < chains.length; ++i) {
            string memory path = string.concat("deployments/", vm.toString(chains[i]), ".json");
            if (!vm.exists(path)) continue;
            string memory recorded = vm.readFile(path);
            assertEq(vm.parseJsonString(recorded, ".solc"), solc, string.concat(path, ": solc"));
            assertEq(vm.parseJsonString(recorded, ".evmVersion"), evmVersion, string.concat(path, ": evmVersion"));
            ++checked;
        }
        // Base Sepolia's file at least: the test is not vacuous
        assertGt(checked, 0, "no deployments file was checked");
    }
}
