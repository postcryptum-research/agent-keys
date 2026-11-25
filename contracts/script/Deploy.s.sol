// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256RecoveryValidator} from "../src/P256RecoveryValidator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";
import {DemoCounter} from "../src/demo/DemoCounter.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// Deploys the modules, the demo target and, where CoW Protocol runs, its
/// order decoder deterministically through
/// the canonical CREATE2 deployer (salt 0), so addresses match on every
/// chain. Kernel v3.3 itself is ZeroDev's canonical deployment. Re-running
/// is a no-op for anything already deployed.
///
///   forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast \
///       --private-key "$(cat ../../gas-wallet.key)"
///
/// With `REDEPLOY=true` in the environment, every contract is deployed from
/// this build even where an address is recorded (house rule 9: before the
/// first audited release a fix is carried by a redeploy). A recorded address
/// that is replaced stays in the file under the next versioned name
/// (`agentPolicy` -> `agentPolicyV9`): live accounts keep pointing there until
/// the owner moves them. docs/REDEPLOY.md lists what follows a redeploy.
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

    // CoW Protocol's settlement (GPv2Settlement), the same address on every
    // chain CoW runs on. The decoder is deployed only where it has code.
    address internal constant COW_SETTLEMENT = 0x9008D19f58AAbD9eD0D60971565AA8510560ab41;

    // The compiler settings this script is built with, as foundry.toml sets
    // them, recorded in the deployments file so that the code of an instance
    // can be rebuilt and compared (issue #123). `DeploymentsRecord.t.sol`
    // holds them equal to foundry.toml and to the recorded files.
    string public constant SOLC = "0.8.38";
    string public constant EVM_VERSION = "cancun";

    function run() external {
        require(ENTRY_POINT.code.length > 0, "EntryPoint v0.7 missing on this chain");
        require(KERNEL_FACTORY.code.length > 0, "Kernel v3.3 factory missing on this chain");

        // Addresses already recorded for this chain win over recomputed
        // CREATE2 addresses: any change to compiler settings changes the
        // creation code, and a redeploy would silently fork the deployment
        // that live accounts reference.
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        string memory recorded = vm.exists(path) ? vm.readFile(path) : "";
        redeploy = vm.envOr("REDEPLOY", false);

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
        // The decoder reads the settlement's domain separator and spender when
        // it is created, so on each chain it is that chain's venue and no other.
        address cowDecoder;
        if (COW_SETTLEMENT.code.length > 0) {
            cowDecoder = _reuseOrDeploy(
                recorded,
                "cowSwapDecoder",
                "CowSwapDecoder",
                abi.encodePacked(type(CowSwapDecoder).creationCode, abi.encode(COW_SETTLEMENT))
            );
        }
        vm.stopBroadcast();

        string memory json = "deployment";
        // Every versioned key already recorded, then each address this run replaced
        _keepSuperseded(json, recorded);
        _supersede(json, recorded, "p256Validator", validator);
        _supersede(json, recorded, "p256RecoveryValidator", recoveryValidator);
        _supersede(json, recorded, "p256Signer", signer);
        _supersede(json, recorded, "safeNonceAssert", nonceAssert);
        _supersede(json, recorded, "agentPolicy", policy);
        _supersede(json, recorded, "whitelistPaymaster", paymaster);
        _supersede(json, recorded, "demoCounter", counter);
        if (cowDecoder != address(0)) _supersede(json, recorded, "cowSwapDecoder", cowDecoder);
        vm.serializeUint(json, "chainId", block.chainid);
        vm.serializeString(json, "solc", SOLC);
        vm.serializeString(json, "evmVersion", EVM_VERSION);
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
        if (cowDecoder != address(0)) vm.serializeAddress(json, "cowSwapDecoder", cowDecoder);
        string memory out = vm.serializeAddress(json, "demoCounter", counter);
        vm.writeJson(out, path);
        console.log("wrote", path);
    }

    /// @dev True when this run deploys from the build rather than reusing what is recorded.
    bool internal redeploy;

    /// @dev Keeps every superseded version the file records (`<name>V<n>`):
    /// live permissions and accounts installed with them keep pointing there
    /// until the owner moves them.
    /// @param json The serialization key of the file being written.
    /// @param recorded The file as it was, or "".
    function _keepSuperseded(string memory json, string memory recorded) internal {
        if (bytes(recorded).length == 0) return;
        string[] memory keys = vm.parseJsonKeys(recorded, "$");
        for (uint256 i; i < keys.length; i++) {
            (bool versioned,,) = versionOf(keys[i]);
            if (versioned) vm.serializeAddress(json, keys[i], vm.parseJsonAddress(recorded, string.concat(".", keys[i])));
        }
    }

    /// @dev When this run put `current` where the file recorded another
    /// address for `name`, the recorded one is kept as `<name>V<n>`, n one
    /// above the highest version recorded for that name.
    /// @param json The serialization key of the file being written.
    /// @param recorded The file as it was, or "".
    /// @param name The contract's key, e.g. "agentPolicy".
    /// @param current The address this run records for it.
    function _supersede(string memory json, string memory recorded, string memory name, address current) internal {
        if (bytes(recorded).length == 0 || !vm.keyExistsJson(recorded, string.concat(".", name))) return;
        address was = vm.parseJsonAddress(recorded, string.concat(".", name));
        if (was == current) return;
        string memory key = nextVersionKey(vm.parseJsonKeys(recorded, "$"), name);
        vm.serializeAddress(json, key, was);
        console.log(name, "superseded, kept as", key);
    }

    /// @dev The key a superseded `name` is kept under: `<name>V<n>`, n one
    /// above the highest version among `keys` (V1 when there is none).
    /// @param keys The file's keys.
    /// @param name The contract's key.
    /// @return The versioned key.
    function nextVersionKey(string[] memory keys, string memory name) public pure returns (string memory) {
        uint256 highest;
        for (uint256 i; i < keys.length; i++) {
            (bool versioned, string memory base, uint256 n) = versionOf(keys[i]);
            if (versioned && keccak256(bytes(base)) == keccak256(bytes(name)) && n > highest) highest = n;
        }
        return string.concat(name, "V", vm.toString(highest + 1));
    }

    /// @dev Whether `key` is a superseded version, `<name>V<n>`: a name of at
    /// least one letter, then `V`, then a number without a leading zero.
    /// @param key A key of the deployments file.
    /// @return versioned True for `<name>V<n>`.
    /// @return base The name before `V<n>`.
    /// @return n The version number.
    function versionOf(string memory key) public pure returns (bool versioned, string memory base, uint256 n) {
        bytes memory k = bytes(key);
        uint256 i = k.length;
        // The digits at the end
        while (i > 0 && k[i - 1] >= "0" && k[i - 1] <= "9") i--;
        // At least one digit, no leading zero, a `V` before them and a name before that
        if (i == k.length || k[i] == "0" || i < 2 || k[i - 1] != "V") return (false, "", 0);
        for (uint256 j = i; j < k.length; j++) n = n * 10 + uint8(k[j]) - 48;
        bytes memory b = new bytes(i - 1);
        for (uint256 j; j + 1 < i; j++) b[j] = k[j];
        return (true, string(b), n);
    }

    function _reuseOrDeploy(string memory recorded, string memory key, string memory name, bytes memory creationCode)
        internal
        returns (address addr)
    {
        string memory jsonKey = string.concat(".", key);
        // A redeploy deploys from this build; the recorded address is superseded, not reused
        if (!redeploy && bytes(recorded).length > 0 && vm.keyExistsJson(recorded, jsonKey)) {
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
