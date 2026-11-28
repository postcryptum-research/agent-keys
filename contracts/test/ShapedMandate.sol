// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {AgentPolicy} from "../src/AgentPolicy.sol";

/// The twelve-word form of a mandate (issue #251): a seven- or eight-word
/// mandate with a shape judge pinned, which every mandate with a Safe
/// transaction or a batch on its allow-list needs.
library ShapedMandate {
    /// The head parameters of the shorter forms.
    struct Head {
        address[] targets;
        bytes4[] selectors;
        uint128 maxValuePerOp;
        uint128 budget;
        uint48 validUntil;
        AgentPolicy.TokenCap[] tokens;
        uint48 validAfter;
        AgentPolicy.TokenPayees[] payees;
    }

    /// @dev `params` (after the permission id) in the seven- or eight-word
    /// form, re-encoded in the twelve-word form with `judge` pinned at its
    /// present code.
    function shaped(bytes memory params, address judge) internal view returns (bytes memory) {
        Head memory h = _head(params);
        AgentPolicy.ShapeJudge[] memory shapes = new AgentPolicy.ShapeJudge[](1);
        shapes[0] = AgentPolicy.ShapeJudge(judge, judge.codehash);
        return abi.encode(
            h.targets,
            h.selectors,
            h.maxValuePerOp,
            h.budget,
            h.validUntil,
            h.tokens,
            h.validAfter,
            h.payees,
            uint32(0),
            new AgentPolicy.Venue[](0),
            new AgentPolicy.IdCap[](0),
            shapes
        );
    }

    function _head(bytes memory params) private pure returns (Head memory h) {
        uint256 first;
        assembly ("memory-safe") {
            first := mload(add(params, 0x20))
        }
        require(first == 7 * 32 || first == 8 * 32, "a seven- or eight-word mandate");
        // the seven head words both forms start with
        (h.targets, h.selectors, h.maxValuePerOp, h.budget, h.validUntil, h.tokens, h.validAfter) = abi.decode(
            params, (address[], bytes4[], uint128, uint128, uint48, AgentPolicy.TokenCap[], uint48)
        );
        // the eighth on its own, as the policy's install reads it
        if (first == 8 * 32) {
            (,,,,,,, h.payees) = abi.decode(
                params, (address[], bytes4[], uint128, uint128, uint48, AgentPolicy.TokenCap[], uint48, AgentPolicy.TokenPayees[])
            );
        }
    }
}
