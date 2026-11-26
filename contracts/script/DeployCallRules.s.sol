// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/Script.sol";
import {Deploy} from "./Deploy.s.sol";
import {CallRulesDecoder} from "../src/venues/CallRulesDecoder.sol";

/// Deploys a `CallRulesDecoder` for one contract, through the canonical
/// CREATE2 deployer (salt 0) like the modules: the same venue and spender
/// give the same address on every chain where they are the same.
///
///   forge script script/DeployCallRules.s.sol --sig 'rules(address,address)' \
///       <venue> <spender> --rpc-url base_sepolia --broadcast \
///       --private-key "$(cat ../../gas-wallet.key)"
///
/// One decoder speaks for one contract: `AgentPolicy` admits a decoder's
/// call at the decoder's own venue only. The spender is the contract the
/// account approves there: the venue itself where it pulls tokens itself.
/// Nothing is written to deployments/: a mandate names such a decoder with
/// its address and its code hash, which this script prints.
contract DeployCallRules is Deploy {
    /// @dev Deploys the decoder for `venue`, or finds it already there.
    /// @param venue The contract the decoder's calls are made at.
    /// @param spender The contract the account approves there.
    /// @return decoder The decoder's address.
    function rules(address venue, address spender) external returns (address decoder) {
        require(venue.code.length > 0 && spender.code.length > 0, "no code at the venue or at the spender");
        vm.startBroadcast();
        decoder = _deploy("CallRulesDecoder", creation(venue, spender));
        vm.stopBroadcast();
        console.log("venue", venue);
        console.log("spender", spender);
        console.log("code hash, once deployed:");
        console.logBytes32(decoder.codehash);
    }

    /// @dev The address a decoder for `venue` and `spender` has, deployed or not.
    /// @param venue The contract the decoder's calls are made at.
    /// @param spender The contract the account approves there.
    /// @return The decoder's CREATE2 address.
    function rulesAddress(address venue, address spender) external pure returns (address) {
        return vm.computeCreate2Address(bytes32(SALT), keccak256(creation(venue, spender)), CREATE2_DEPLOYER);
    }

    /// @dev The decoder's creation code with its two arguments.
    /// @param venue The contract the decoder's calls are made at.
    /// @param spender The contract the account approves there.
    /// @return The bytes handed to the CREATE2 deployer after the salt.
    function creation(address venue, address spender) public pure returns (bytes memory) {
        return abi.encodePacked(type(CallRulesDecoder).creationCode, abi.encode(venue, spender));
    }
}
