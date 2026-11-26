// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VenueCallProof} from "./VenueCallProof.t.sol";

/// The statements of `VenueCallProof` run on sample values by `forge test`,
/// which does not prove them: the prover does (`.github/workflows/kontrol.yml`).
/// What this holds is the harness itself: that it builds, that each statement
/// holds on values at and around the limits, and that the cases a statement
/// is about are accepted at all (a statement about accepted operations says
/// nothing if every operation is refused).
contract VenueCallProofSamples is VenueCallProof {
    function test_samples() public {
        uint256[6] memory v = [uint256(0), 1, 1 ether, 1 ether + 1, 2 ether, type(uint256).max];
        for (uint256 i; i < v.length; i++) {
            uint256 s = vm.snapshotState();
            check_venueCall_valueCounted(v[i]);
            vm.revertToState(s);
        }
        uint256[6] memory p = [uint256(0), 1, 100, 101, 151, type(uint256).max];
        for (uint256 i; i < p.length; i++) {
            uint256 s = vm.snapshotState();
            check_venueCall_priced(p[i]);
            vm.revertToState(s);
        }
        // each statement starts from the state after setUp, as under the prover
        uint256 fresh = vm.snapshotState();
        check_venueCall_onlyThatCall(5, 5);
        vm.revertToState(fresh);
        fresh = vm.snapshotState();
        check_venueCall_onlyThatCall(5, 6);
        vm.revertToState(fresh);
        fresh = vm.snapshotState();
        check_venueCall_onlyThatCall(0, 1);
        vm.revertToState(fresh);
        fresh = vm.snapshotState();
        check_venueCall_aRegistrationAlone(0, 0);
        vm.revertToState(fresh);
        fresh = vm.snapshotState();
        check_venueCall_aRegistrationAlone(7, 50);
        vm.revertToState(fresh);
    }

    /// With the registered value the pair is accepted; so the third statement is not empty.
    function test_theSameValueIsAccepted() public {
        require(_validate(_pair(5, 0, 5)) != 1, "the registered call");
        require(_validate(_pair(5, 0, 6)) == 1, "another value");
    }

    /// The accepted cases really are accepted (the statements would hold trivially if everything were refused).
    function test_acceptedWhereItShould() public {
        require(_validate(_pair(1 ether, 0, 1 ether)) != 1, "a call within the native cap");
        require(_nativeSpent() == 1 ether, "booked");
        require(_validate(_pair(0, 50, 0)) != 1, "a priced call within the token cap");
        require(_tokenSpent() == 50, "booked");
        require(_validate(_pair(1 ether + 1, 0, 1 ether + 1)) == 1, "over the native cap");
        require(_validate(_pair(0, 101, 0)) == 1, "over the token cap");
    }
}
