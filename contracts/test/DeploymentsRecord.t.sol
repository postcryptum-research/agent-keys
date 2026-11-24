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

    /// @dev Every address a chain's deployments file records is on
    /// docs/DEPLOYMENTS.md, written as the file writes it (checksummed), so
    /// the page cannot fall behind a deployment.
    function test_everyRecordedAddressIsOnTheDeploymentsPage() public {
        string memory page = vm.readFile("../docs/DEPLOYMENTS.md");
        uint256 checked;
        for (uint256 i; i < chains.length; ++i) {
            string memory path = string.concat("deployments/", vm.toString(chains[i]), ".json");
            if (!vm.exists(path)) continue;
            string memory recorded = vm.readFile(path);
            string[] memory keys = vm.parseJsonKeys(recorded, "$");
            for (uint256 k; k < keys.length; ++k) {
                // The keys that are not addresses
                bytes32 h = keccak256(bytes(keys[k]));
                if (h == keccak256("chainId") || h == keccak256("solc") || h == keccak256("evmVersion")) continue;
                address a = vm.parseJsonAddress(recorded, string.concat(".", keys[k]));
                // A page that does not name the address fails, with the key and the file
                assertTrue(
                    vm.indexOf(page, vm.toString(a)) != type(uint256).max,
                    string.concat(path, ": ", keys[k], " ", vm.toString(a), " is not on docs/DEPLOYMENTS.md")
                );
                ++checked;
            }
        }
        assertGt(checked, 0, "no recorded address was checked");
    }
}
