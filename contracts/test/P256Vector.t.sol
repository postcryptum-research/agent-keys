// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {P256} from "solady/utils/P256.sol";

/// Phase 0: a digest signed off-chain by `agent-signer` verifies on-chain
/// through the RIP-7212 precompile — the same check a P256 smart account
/// performs in `validateUserOp`. Vectors are produced by
/// `agent-signer vector --backend <software|tpm> --message ...` and committed
/// under `test/vectors/`. The TPM vector was signed inside a real TPM 2.0.
contract P256VectorTest is Test {
    struct Vector {
        bytes32 digest;
        bytes32 r;
        bytes32 s;
        bytes32 x;
        bytes32 y;
    }

    /// P-256 group order; a low-s signature satisfies s <= N / 2.
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    function _load(string memory path) internal view returns (Vector memory v) {
        string memory json = vm.readFile(path);
        v.digest = vm.parseJsonBytes32(json, ".digest");
        v.r = vm.parseJsonBytes32(json, ".r");
        v.s = vm.parseJsonBytes32(json, ".s");
        v.x = vm.parseJsonBytes32(json, ".x");
        v.y = vm.parseJsonBytes32(json, ".y");
    }

    function _assertVector(string memory path) internal view {
        Vector memory v = _load(path);
        assertTrue(
            P256.verifySignature(v.digest, v.r, v.s, v.x, v.y),
            "valid signature must verify"
        );
        assertFalse(
            P256.verifySignature(v.digest ^ bytes32(uint256(1)), v.r, v.s, v.x, v.y),
            "tampered digest must fail"
        );
        // Swapped coordinates are (almost surely) not a point on the curve.
        assertFalse(
            P256.verifySignature(v.digest, v.r, v.s, v.y, v.x),
            "wrong key must fail"
        );
        assertLe(uint256(v.s), N / 2, "signer must normalize to low-s");
    }

    function test_precompileAvailable() public view {
        assertTrue(
            P256.hasPrecompile(),
            "RIP-7212 precompile missing: set `odyssey = true` in foundry.toml"
        );
    }

    function test_softwareVector() public view {
        _assertVector("test/vectors/p256_software.json");
    }

    function test_tpmVector() public view {
        _assertVector("test/vectors/p256_tpm.json");
    }

    /// Every committed vector — so one signed by a new secure element
    /// (Secure Enclave, Windows CNG, TROPIC01, …) is covered the moment it
    /// lands in test/vectors/.
    function test_everyCommittedVector() public view {
        Vm.DirEntry[] memory entries = vm.readDir("test/vectors");
        uint256 checked;
        for (uint256 i; i < entries.length; i++) {
            if (entries[i].isDir || !_endsWith(entries[i].path, ".json")) continue;
            _assertVector(entries[i].path);
            checked++;
        }
        assertGe(checked, 2, "software and TPM vectors are always present");
    }

    function _endsWith(string memory s, string memory suffix) internal pure returns (bool) {
        bytes memory b = bytes(s);
        bytes memory e = bytes(suffix);
        if (e.length > b.length) return false;
        for (uint256 i; i < e.length; i++) {
            if (b[b.length - e.length + i] != e[i]) return false;
        }
        return true;
    }
}
