// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {DemoCounter} from "../src/demo/DemoCounter.sol";

/// Deploys the three modules and the demo target deterministically through
/// the canonical CREATE2 deployer (salt 0), so addresses match on every
/// chain. Kernel v3.3 itself is ZeroDev's canonical deployment. Re-running
/// is a no-op for anything already deployed.
///
///   forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast \
///       --private-key "$(cat ../../gas-wallet.key)"
///
/// Writes deployments/<chainid>.json, which the Rust side reads.
contract Deploy is Script {
    // A number constant: inline assembly below cannot reference a bytes32 one.
    uint256 internal constant SALT = 0;

    // ERC-4337 EntryPoint v0.7 and ZeroDev Kernel v3.3 (same on every chain).
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant KERNEL = 0xd6CEDDe84be40893d153Be9d467CD6aD37875b28;
    address internal constant KERNEL_FACTORY = 0x2577507b78c2008Ff367261CB6285d44ba5eF2E9;

    function run() external {
        require(ENTRY_POINT.code.length > 0, "EntryPoint v0.7 missing on this chain");
        require(KERNEL_FACTORY.code.length > 0, "Kernel v3.3 factory missing on this chain");

        vm.startBroadcast();
        address validator = _deploy("P256Validator", type(P256Validator).creationCode);
        address signer = _deploy("P256Signer", type(P256Signer).creationCode);
        address policy = _deploy("AgentPolicy", type(AgentPolicy).creationCode);
        address counter = _deploy("DemoCounter", type(DemoCounter).creationCode);
        vm.stopBroadcast();

        string memory json = "deployment";
        vm.serializeUint(json, "chainId", block.chainid);
        vm.serializeAddress(json, "entryPoint", ENTRY_POINT);
        vm.serializeAddress(json, "kernel", KERNEL);
        vm.serializeAddress(json, "kernelFactory", KERNEL_FACTORY);
        vm.serializeAddress(json, "p256Validator", validator);
        vm.serializeAddress(json, "p256Signer", signer);
        vm.serializeAddress(json, "agentPolicy", policy);
        string memory out = vm.serializeAddress(json, "demoCounter", counter);
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        vm.writeJson(out, path);
        console.log("wrote", path);
    }

    function _deploy(string memory name, bytes memory creationCode) internal returns (address addr) {
        addr = vm.computeCreate2Address(bytes32(SALT), keccak256(creationCode));
        if (addr.code.length > 0) {
            console.log(name, "already at", addr);
            return addr;
        }
        assembly {
            addr := create2(0, add(creationCode, 0x20), mload(creationCode), SALT)
        }
        require(addr != address(0), "create2 failed");
        console.log(name, "deployed at", addr);
    }
}
