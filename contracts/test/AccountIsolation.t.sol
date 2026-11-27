// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

// Tests by the reviewer of #87 for the storage layout of issue #83. With the account as the innermost key, two accounts that
// install the SAME permission id share every outer key (the id, its epoch,
// the target, the token), and only the inner key keeps them apart. These
// tests hold that: each account gets what it installed, and nothing of the
// other's.
import "./AgentPermission.t.sol";

/// Stands in for an account: names its EntryPoint and calls the policy as itself.
contract OtherAccount {
    address internal immutable ENTRY_POINT;

    constructor(address entryPoint_) {
        ENTRY_POINT = entryPoint_;
    }

    function entrypoint() external view returns (address) {
        return ENTRY_POINT;
    }

    function ask(address policy, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = policy.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }
}

contract AccountIsolation is AgentPermissionTest {
    bytes32 internal constant ID = bytes32(uint256(0x69736f31) << 224); // "iso1", for both accounts
    address internal constant LISTED = address(0xBEEF);
    address internal constant OUTSIDER = address(0xDEAD);
    uint128 internal constant B_TOKEN_MAX = 1 ether;
    uint128 internal constant B_TOKEN_BUDGET = 2 ether;

    OtherAccount internal a;
    OtherAccount internal b;
    Counter internal counterB;

    function _params(address target, uint128 max, uint128 tokenBudget, bool list) internal view returns (bytes memory) {
        return _paramsFor(target, max, tokenBudget, list ? LISTED : address(0));
    }

    /// `payee` zero: no list for the token.
    function _paramsFor(address target, uint128 max, uint128 tokenBudget, address payee) internal view returns (bytes memory) {
        address[] memory targets = new address[](2);
        bytes4[] memory selectors = new bytes4[](2);
        (targets[0], selectors[0]) = (target, Counter.increment.selector);
        (targets[1], selectors[1]) = (address(token), MockToken.transfer.selector);
        AgentPolicy.TokenCap[] memory caps = new AgentPolicy.TokenCap[](1);
        caps[0] = AgentPolicy.TokenCap(address(token), max, tokenBudget, bytes32(0));
        if (payee == address(0)) return abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0));
        AgentPolicy.TokenPayees[] memory lists = new AgentPolicy.TokenPayees[](1);
        address[] memory payees = new address[](1);
        payees[0] = payee;
        lists[0] = AgentPolicy.TokenPayees(address(token), payees);
        return abi.encode(targets, selectors, MAX_VALUE, BUDGET, expiry, caps, uint48(0), lists);
    }

    /// A: the counter, the token up to TOKEN_MAX, to LISTED only.
    /// B: its own counter, the token up to 1 ether, to anyone. The same id.
    function _two() internal {
        a = new OtherAccount(address(entryPoint));
        b = new OtherAccount(address(entryPoint));
        counterB = new Counter();
        a.ask(address(policy), abi.encodeCall(AgentPolicy.onInstall, (abi.encodePacked(ID, _params(address(counter), TOKEN_MAX, TOKEN_BUDGET, true)))));
        b.ask(address(policy), abi.encodeCall(AgentPolicy.onInstall, (abi.encodePacked(ID, _params(address(counterB), B_TOKEN_MAX, B_TOKEN_BUDGET, false)))));
    }

    /// Whether the policy admits `who` making this one call.
    function _admits(OtherAccount who, address target, bytes memory data) internal returns (bool) {
        PackedUserOperation memory op = _op(0, _singleCall(target, 0, data));
        bytes memory ret = who.ask(address(policy), abi.encodeCall(AgentPolicy.checkUserOpPolicy, (ID, op)));
        return abi.decode(ret, (uint256)) != SIG_VALIDATION_FAILED_UINT;
    }

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeCall(MockToken.transfer, (to, amount));
    }

    function _spent(OtherAccount who) internal view returns (uint256) {
        return policy.tokenLimit(address(who), ID, address(token)).spent;
    }

    function test_isolation_allowListsDoNotCross() public {
        _two();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        // each its own
        assertTrue(_admits(a, address(counter), inc), "A, its counter");
        assertTrue(_admits(b, address(counterB), inc), "B, its counter");
        // neither the other's
        assertFalse(_admits(a, address(counterB), inc), "A, B's counter");
        assertFalse(_admits(b, address(counter), inc), "B, A's counter");
        // and the view says the same
        assertTrue(policy.isAllowed(address(a), ID, address(counter), Counter.increment.selector));
        assertFalse(policy.isAllowed(address(a), ID, address(counterB), Counter.increment.selector));
        assertTrue(policy.isAllowed(address(b), ID, address(counterB), Counter.increment.selector));
        assertFalse(policy.isAllowed(address(b), ID, address(counter), Counter.increment.selector));
        // an account that installed nothing under this id has nothing
        OtherAccount c = new OtherAccount(address(entryPoint));
        assertFalse(_admits(c, address(counter), inc), "an account without a mandate");
        assertFalse(policy.isAllowed(address(c), ID, address(counter), Counter.increment.selector));
    }

    function test_isolation_tokenLimitsAndSpendingDoNotCross() public {
        _two();
        // A's cap is ten times B's
        assertTrue(_admits(a, address(token), _transfer(LISTED, TOKEN_MAX)), "A at its cap");
        assertFalse(_admits(b, address(token), _transfer(LISTED, TOKEN_MAX)), "B at A's cap");
        assertTrue(_admits(b, address(token), _transfer(LISTED, B_TOKEN_MAX)), "B at its cap");
        assertEq(_spent(a), TOKEN_MAX);
        assertEq(_spent(b), B_TOKEN_MAX);
        // B uses up its budget; A's is untouched by that
        assertTrue(_admits(b, address(token), _transfer(LISTED, B_TOKEN_MAX)));
        assertFalse(_admits(b, address(token), _transfer(LISTED, 1)), "B past its budget");
        assertEq(_spent(b), B_TOKEN_BUDGET);
        assertTrue(_admits(a, address(token), _transfer(LISTED, TOKEN_MAX)), "A, after B ran out");
        assertEq(_spent(a), 2 * TOKEN_MAX);
        // the limits as the views give them
        assertEq(policy.tokenLimit(address(a), ID, address(token)).maxPerOp, TOKEN_MAX);
        assertEq(policy.tokenLimit(address(b), ID, address(token)).maxPerOp, B_TOKEN_MAX);
    }

    function test_isolation_payeeListsDoNotCross() public {
        _two();
        // A is held to its list; B has none and A's does not bind it
        assertFalse(_admits(a, address(token), _transfer(OUTSIDER, 1)), "A to an address off its list");
        assertTrue(_admits(a, address(token), _transfer(LISTED, 1)), "A to its listed payee");
        assertTrue(_admits(b, address(token), _transfer(OUTSIDER, 1)), "B to anyone");
        assertFalse(policy.payeeAllowed(address(a), ID, address(token), OUTSIDER));
        assertTrue(policy.payeeAllowed(address(a), ID, address(token), LISTED));
        assertTrue(policy.payeeAllowed(address(b), ID, address(token), OUTSIDER));
        assertTrue(policy.tokenLimit(address(a), ID, address(token)).payeesOnly);
        assertFalse(policy.tokenLimit(address(b), ID, address(token)).payeesOnly);

        // two accounts that each have a list, of different payees: neither may pay the other's
        OtherAccount c = new OtherAccount(address(entryPoint));
        c.ask(address(policy), abi.encodeCall(AgentPolicy.onInstall, (abi.encodePacked(ID, _paramsFor(address(counter), TOKEN_MAX, TOKEN_BUDGET, OUTSIDER)))));
        assertTrue(_admits(c, address(token), _transfer(OUTSIDER, 1)), "C to its listed payee");
        assertFalse(_admits(c, address(token), _transfer(LISTED, 1)), "C to A's payee");
        assertFalse(_admits(a, address(token), _transfer(OUTSIDER, 1)), "A to C's payee");
        assertTrue(policy.payeeAllowed(address(c), ID, address(token), OUTSIDER));
        assertFalse(policy.payeeAllowed(address(c), ID, address(token), LISTED));
        assertFalse(policy.payeeAllowed(address(a), ID, address(token), OUTSIDER));
    }

    function test_isolation_oneAccountsUninstallAndReinstallLeaveTheOther() public {
        _two();
        bytes memory inc = abi.encodeWithSelector(Counter.increment.selector);
        b.ask(address(policy), abi.encodeCall(AgentPolicy.onUninstall, (abi.encodePacked(ID))));
        assertFalse(_admits(b, address(counterB), inc), "B after its uninstall");
        assertTrue(_admits(a, address(counter), inc), "A after B's uninstall");
        assertTrue(_admits(a, address(token), _transfer(LISTED, 1)));
        // B comes back under the same id with A's counter as its target and a list of its own
        b.ask(address(policy), abi.encodeCall(AgentPolicy.onInstall, (abi.encodePacked(ID, _params(address(counter), B_TOKEN_MAX, B_TOKEN_BUDGET, true)))));
        assertTrue(_admits(b, address(counter), inc), "B, its new target");
        assertFalse(_admits(b, address(counterB), inc), "B, the target of its earlier mandate");
        assertFalse(_admits(b, address(token), _transfer(OUTSIDER, 1)), "B, now with a list");
        assertEq(_spent(b), 0, "B starts clean");
        // A is where it was: its epoch, its limits, its list
        (uint48 untilA, uint32 epochA,,,,) = policy.configs(address(a), ID);
        (uint48 untilB, uint32 epochB,,,,) = policy.configs(address(b), ID);
        assertEq(epochA, 0);
        assertEq(epochB, 1);
        assertEq(untilA, expiry);
        assertEq(untilB, expiry);
        assertFalse(_admits(a, address(counterB), inc), "A, still not B's old target");
        assertFalse(_admits(a, address(token), _transfer(OUTSIDER, 1)), "A, still held to its list");
        assertEq(policy.tokenLimit(address(a), ID, address(token)).maxPerOp, TOKEN_MAX);
    }

    /// The same id may not be installed twice by one account, and one
    /// account's installation does not stand in the other's way.
    function test_isolation_installIsPerAccount() public {
        _two();
        bytes memory again = abi.encodeCall(AgentPolicy.onInstall, (abi.encodePacked(ID, _params(address(counter), TOKEN_MAX, TOKEN_BUDGET, false))));
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized(address)", address(a)));
        a.ask(address(policy), again);
        OtherAccount c = new OtherAccount(address(entryPoint));
        c.ask(address(policy), again);
        assertTrue(policy.isAllowed(address(c), ID, address(counter), Counter.increment.selector));
        assertEq(policy.usedIds(address(a)), 1);
        assertEq(policy.usedIds(address(c)), 1);
    }
}
