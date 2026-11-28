// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {Script, console} from "forge-std/Script.sol";

import {P256Validator} from "../src/P256Validator.sol";
import {P256RecoveryValidator} from "../src/P256RecoveryValidator.sol";
import {P256Signer} from "../src/P256Signer.sol";
import {AgentPolicy} from "../src/AgentPolicy.sol";
import {SafeShapes} from "../src/judges/SafeShapes.sol";
import {SafeNonceAssert} from "../src/SafeNonceAssert.sol";
import {CowSwapDecoder} from "../src/venues/CowSwapDecoder.sol";
import {OneInchLimitOrderDecoder} from "../src/venues/OneInchLimitOrderDecoder.sol";
import {SwapRouter02Decoder} from "../src/venues/SwapRouter02Decoder.sol";
import {SeaportBidDecoder, ISeaport, IConduitController} from "../src/venues/SeaportBidDecoder.sol";
import {WhitelistPaymaster} from "../src/WhitelistPaymaster.sol";
import {DemoCounter} from "../src/demo/DemoCounter.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// Deploys the modules, the demo target and, where a venue runs, its
/// decoder (CoW Protocol, 1inch, Uniswap's SwapRouter02, Seaport)
/// deterministically through
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
    uint256 internal constant SALT = 0;

    // The canonical CREATE2 deployer: its calldata is the salt (32 bytes)
    // followed by the creation code, and it returns the 20-byte address.
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

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

    // 1inch's router (AggregationRouterV6, which carries Limit Order Protocol
    // v4), the same address on every chain it is on. The decoder is deployed
    // only where it has code, and its constructor reverts unless that code
    // hashes an order as the decoder does.
    address internal constant ONE_INCH_ROUTER = 0x111111125421cA6dc452d289314280a0f8842A65;

    // Seaport 1.6, the same address on every chain it is on, and the key of
    // the conduit OpenSea's orders move their tokens through. The decoder is
    // deployed only where Seaport has code and its conduit controller knows
    // that key; its constructor reverts unless Seaport hashes an order as
    // the decoder does.
    address internal constant SEAPORT = 0x0000000000000068F116a894984e2DB1123eB395;
    bytes32 internal constant SEAPORT_CONDUIT_KEY = 0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000;

    /// @dev Whether Seaport and the conduit of `SEAPORT_CONDUIT_KEY` are on this chain.
    /// @return True where a bid decoder can be deployed.
    function seaportIsHere() public view returns (bool) {
        if (SEAPORT.code.length == 0) return false;
        (,, address controller) = ISeaport(SEAPORT).information();
        if (controller.code.length == 0) return false;
        (, bool exists) = IConduitController(controller).getConduit(SEAPORT_CONDUIT_KEY);
        return exists;
    }

    /// @dev Uniswap's SwapRouter02, whose address differs from chain to chain
    /// (Uniswap's deployment pages; code of the same length and a `factory()`
    /// and a `positionManager()` at each, read on 2026-11-26).
    /// @return The router on this chain, or zero where this script names none.
    function swapRouter02() public view returns (address) {
        if (block.chainid == 1 || block.chainid == 42161) return 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45;
        if (block.chainid == 8453) return 0x2626664c2603336E57B271c5C0b26F421741e481;
        if (block.chainid == 56) return 0xB971eF87ede563556b2ED4b1C0b0019111Dd85d2;
        if (block.chainid == 11155111) return 0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E;
        if (block.chainid == 84532) return 0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4;
        return address(0);
    }

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
        safeShapes = _reuseOrDeploy(recorded, "safeShapes", "SafeShapes", type(SafeShapes).creationCode);
        address policy = _reuseOrDeploy(
            recorded,
            "agentPolicy",
            "AgentPolicy",
            abi.encodePacked(type(AgentPolicy).creationCode, abi.encode(nonceAssert))
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
        // The venues' decoders, CoW Swap's, 1inch's, the swap router's and Seaport's: zero where the venue is not on this chain
        address[4] memory decoders;
        if (COW_SETTLEMENT.code.length > 0) {
            decoders[0] = _reuseOrDeploy(
                recorded,
                "cowSwapDecoder",
                "CowSwapDecoder",
                abi.encodePacked(type(CowSwapDecoder).creationCode, abi.encode(COW_SETTLEMENT))
            );
        }
        // The decoder reads the router's EIP-712 domain when it is created, so
        // on each chain it is that chain's router and no other.
        if (ONE_INCH_ROUTER.code.length > 0) {
            decoders[1] = _reuseOrDeploy(
                recorded,
                "oneInchLimitOrderDecoder",
                "OneInchLimitOrderDecoder",
                abi.encodePacked(type(OneInchLimitOrderDecoder).creationCode, abi.encode(ONE_INCH_ROUTER))
            );
        }
        // A swap at Uniswap's SwapRouter02: the router is the decoder's venue, so
        // on each chain it is that chain's router and no other.
        if (swapRouter02().code.length > 0) {
            decoders[2] = _reuseOrDeploy(
                recorded,
                "swapRouter02Decoder",
                "SwapRouter02Decoder",
                abi.encodePacked(type(SwapRouter02Decoder).creationCode, abi.encode(swapRouter02()))
            );
        }
        // A bid at Seaport, through the conduit of `SEAPORT_CONDUIT_KEY`: the
        // decoder reads Seaport's domain separator and the conduit when it is
        // created, so on each chain it is that chain's.
        if (seaportIsHere()) {
            decoders[3] = _reuseOrDeploy(
                recorded,
                "seaportBidDecoder",
                "SeaportBidDecoder",
                abi.encodePacked(type(SeaportBidDecoder).creationCode, abi.encode(SEAPORT, SEAPORT_CONDUIT_KEY))
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
        _supersede(json, recorded, "safeShapes", safeShapes);
        _supersede(json, recorded, "agentPolicy", policy);
        // the policy's install code, which its constructor creates (#251); a
        // recorded policy from before the division has none
        policyInstall = installOf(policy);
        if (policyInstall != address(0)) _supersede(json, recorded, "policyInstall", policyInstall);
        _supersede(json, recorded, "whitelistPaymaster", paymaster);
        _supersede(json, recorded, "demoCounter", counter);
        if (decoders[0] != address(0)) _supersede(json, recorded, "cowSwapDecoder", decoders[0]);
        if (decoders[1] != address(0)) _supersede(json, recorded, "oneInchLimitOrderDecoder", decoders[1]);
        if (decoders[2] != address(0)) _supersede(json, recorded, "swapRouter02Decoder", decoders[2]);
        if (decoders[3] != address(0)) _supersede(json, recorded, "seaportBidDecoder", decoders[3]);
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
        if (policyInstall != address(0)) vm.serializeAddress(json, "policyInstall", policyInstall);
        vm.serializeAddress(json, "safeNonceAssert", nonceAssert);
        vm.serializeAddress(json, "safeShapes", safeShapes);
        vm.serializeAddress(json, "whitelistPaymaster", paymaster);
        vm.serializeAddress(json, "paymasterOwner", sponsor);
        if (decoders[0] != address(0)) vm.serializeAddress(json, "cowSwapDecoder", decoders[0]);
        if (decoders[1] != address(0)) vm.serializeAddress(json, "oneInchLimitOrderDecoder", decoders[1]);
        if (decoders[2] != address(0)) vm.serializeAddress(json, "swapRouter02Decoder", decoders[2]);
        if (decoders[3] != address(0)) vm.serializeAddress(json, "seaportBidDecoder", decoders[3]);
        string memory out = vm.serializeAddress(json, "demoCounter", counter);
        vm.writeJson(out, path);
        console.log("wrote", path);
    }

    /// @dev True when this run deploys from the build rather than reusing what is recorded.
    bool internal redeploy;
    /// The SafeShapes judge of this run, which a mandate pins (#251), and the
    /// policy's install code. Fields and not locals: `run` has no stack slot left.
    address internal safeShapes;
    address internal policyInstall;

    /// @dev The install code a policy created in its constructor (#251), or
    /// zero for a policy from before the division, which has none.
    /// @param policy The AgentPolicy.
    /// @return The policy's `INSTALL`, or zero.
    function installOf(address policy) public view returns (address) {
        // a low-level call: one to an address without code reverts past a `try`
        (bool ok, bytes memory answer) = policy.staticcall(abi.encodeWithSignature("INSTALL()"));
        if (!ok || answer.length != 32) return address(0);
        return abi.decode(answer, (address));
    }

    /// @dev Keeps every superseded version the file records (`<name>V<n>`):
    /// live permissions and accounts installed with them keep pointing there
    /// until the owner moves them. And every decoder of rules (`callRules…`):
    /// there is one a contract, deployed by `DeployCallRules.s.sol` and
    /// recorded under a key of its own, which this script does not deploy.
    /// @param json The serialization key of the file being written.
    /// @param recorded The file as it was, or "".
    function _keepSuperseded(string memory json, string memory recorded) internal {
        if (bytes(recorded).length == 0) return;
        string[] memory keys = vm.parseJsonKeys(recorded, "$");
        for (uint256 i; i < keys.length; i++) {
            (bool versioned,,) = versionOf(keys[i]);
            if (versioned || isRulesKey(keys[i])) {
                vm.serializeAddress(json, keys[i], vm.parseJsonAddress(recorded, string.concat(".", keys[i])));
            }
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

    /// @dev Whether `key` records a decoder of rules: `callRules` and a name
    /// after it (`callRulesAaveV3Pool`).
    /// @param key A key of the deployments file.
    /// @return True for `callRules<Name>`.
    function isRulesKey(string memory key) public pure returns (bool) {
        bytes memory k = bytes(key);
        bytes memory prefix = bytes("callRules");
        if (k.length <= prefix.length) return false;
        for (uint256 i; i < prefix.length; i++) {
            if (k[i] != prefix[i]) return false;
        }
        return true;
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
        for (uint256 j = i; j < k.length; j++) {
            n = n * 10 + uint8(k[j]) - 48;
        }
        bytes memory b = new bytes(i - 1);
        for (uint256 j; j + 1 < i; j++) {
            b[j] = k[j];
        }
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
        bytes memory data = abi.encodePacked(bytes32(SALT), creationCode);
        // The gas limit is the chain's own estimate with a margin. forge sizes
        // a limit by simulating under the compiled `evm_version`, and on a
        // chain that prices state creation higher (EIP-8037, Glamsterdam:
        // Sepolia since 2026-10-06) that limit runs out while the code is
        // stored. With no RPC to ask, forge estimates as before.
        uint256 limit = chainGas(msg.sender, data);
        (bool ok, bytes memory ret) = limit == 0 ? CREATE2_DEPLOYER.call(data) : CREATE2_DEPLOYER.call{gas: limit}(data);
        require(ok && ret.length == 20 && address(bytes20(ret)) == addr, "create2 failed");
        console.log(name, "deployed at", addr);
        if (limit != 0) console.log("  gas limit from the chain's estimate:", limit);
    }

    /// @dev The chain's `eth_estimateGas` for a call, 30% added (forge's own
    /// default margin); 0 when there is no RPC or it gives no estimate.
    function chainGas(address from, bytes memory data) public returns (uint256) {
        string memory params = string.concat(
            '[{"from":"',
            vm.toString(from),
            '","to":"',
            vm.toString(CREATE2_DEPLOYER),
            '","data":"',
            vm.toString(data),
            '"}]'
        );
        try vm.rpc("eth_estimateGas", params) returns (bytes memory r) {
            return withMargin(quantity(r));
        } catch {
            return 0;
        }
    }

    /// @dev A JSON-RPC quantity as `vm.rpc` returns it (big-endian bytes);
    /// 0 when empty or wider than 8 bytes, which no gas figure is.
    function quantity(bytes memory r) public pure returns (uint256 q) {
        if (r.length == 0 || r.length > 8) return 0;
        for (uint256 i; i < r.length; i++) {
            q = (q << 8) | uint8(r[i]);
        }
    }

    /// @dev `estimate` with 30% added, rounded down.
    function withMargin(uint256 estimate) public pure returns (uint256) {
        return estimate * 13 / 10;
    }
}
