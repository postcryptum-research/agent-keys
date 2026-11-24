// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256RecoveryValidator} from "../src/P256RecoveryValidator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";
import {DemoCounter} from "../src/demo/DemoCounter.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

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
    // ZeroDev's FactoryStaker: staked at the EntryPoint, it creates accounts
    // through Kernel's factory, so that an account's first operation names a
    // staked factory (ERC-7562 STO-022, issue #102). Recorded where it has code.
    address internal constant KERNEL_FACTORY_STAKER = 0xd703aaE79538628d27099B8c4f621bE4CCd142d5;

    function run() external {
        require(ENTRY_POINT.code.length > 0, "EntryPoint v0.7 missing on this chain");
        require(KERNEL_FACTORY.code.length > 0, "Kernel v3.3 factory missing on this chain");

        // Addresses already recorded for this chain win over recomputed
        // CREATE2 addresses: any change to compiler settings changes the
        // creation code, and a redeploy would silently fork the deployment
        // that live accounts reference.
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        string memory recorded = vm.exists(path) ? vm.readFile(path) : "";

        vm.startBroadcast();
        address validator = _reuseOrDeploy(recorded, "p256Validator", "P256Validator", type(P256Validator).creationCode);
        address recoveryValidator = _reuseOrDeploy(
            recorded, "p256RecoveryValidator", "P256RecoveryValidator", type(P256RecoveryValidator).creationCode
        );
        address signer = _reuseOrDeploy(recorded, "p256Signer", "P256Signer", type(P256Signer).creationCode);
        address nonceAssert =
            _reuseOrDeploy(recorded, "safeNonceAssert", "SafeNonceAssert", type(SafeNonceAssert).creationCode);
        address policy = _reuseOrDeploy(
            recorded, "agentPolicy", "AgentPolicy", abi.encodePacked(type(AgentPolicy).creationCode, abi.encode(nonceAssert))
        );
        address counter = _reuseOrDeploy(recorded, "demoCounter", "DemoCounter", type(DemoCounter).creationCode);
        // The paymaster is owned by whoever runs this script (the sponsor);
        // its address therefore depends on the sponsor, unlike the modules.
        address sponsor = msg.sender;
        address paymaster = _reuseOrDeploy(
            recorded,
            "whitelistPaymaster",
            "WhitelistPaymaster",
            abi.encodePacked(type(WhitelistPaymaster).creationCode, abi.encode(IEntryPoint(ENTRY_POINT), sponsor))
        );
        vm.stopBroadcast();

        string memory json = "deployment";
        vm.serializeUint(json, "chainId", block.chainid);
        vm.serializeAddress(json, "entryPoint", ENTRY_POINT);
        vm.serializeAddress(json, "kernel", KERNEL);
        vm.serializeAddress(json, "kernelFactory", KERNEL_FACTORY);
        if (KERNEL_FACTORY_STAKER.code.length > 0) {
            vm.serializeAddress(json, "kernelFactoryStaker", KERNEL_FACTORY_STAKER);
        }
        vm.serializeAddress(json, "p256Validator", validator);
        vm.serializeAddress(json, "p256RecoveryValidator", recoveryValidator);
        vm.serializeAddress(json, "p256Signer", signer);
        vm.serializeAddress(json, "agentPolicy", policy);
        vm.serializeAddress(json, "safeNonceAssert", nonceAssert);
        vm.serializeAddress(json, "whitelistPaymaster", paymaster);
        vm.serializeAddress(json, "paymasterOwner", sponsor);
        // Superseded module versions stay recorded: live permissions installed
        // with them keep pointing there until the owner rotates them.
        _keepSuperseded(json, recorded);
        string memory out = vm.serializeAddress(json, "demoCounter", counter);
        vm.writeJson(out, path);
        console.log("wrote", path);
    }

    function _keepSuperseded(string memory json, string memory recorded) internal {
        // Superseded versions stay recorded: live permissions and accounts
        // installed with them keep pointing there until the owner moves them.
        string[12] memory superseded = [
            "agentPolicyV8",
            "agentPolicyV7",
            "agentPolicyV1",
            "agentPolicyV2",
            "agentPolicyV3",
            "agentPolicyV4",
            "agentPolicyV5",
            "agentPolicyV6",
            "p256SignerV1",
            "p256ValidatorV1",
            "whitelistPaymasterV1",
            "p256RecoveryValidatorV1"
        ];
        for (uint256 i; i < superseded.length; i++) {
            string memory k = string.concat(".", superseded[i]);
            if (bytes(recorded).length > 0 && vm.keyExistsJson(recorded, k)) {
                vm.serializeAddress(json, superseded[i], vm.parseJsonAddress(recorded, k));
            }
        }
    }

    function _reuseOrDeploy(string memory recorded, string memory key, string memory name, bytes memory creationCode)
        internal
        returns (address addr)
    {
        string memory jsonKey = string.concat(".", key);
        if (bytes(recorded).length > 0 && vm.keyExistsJson(recorded, jsonKey)) {
            addr = vm.parseJsonAddress(recorded, jsonKey);
            if (addr.code.length > 0) {
                console.log(name, "recorded at", addr);
                return addr;
            }
        }
        return _deploy(name, creationCode);
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
