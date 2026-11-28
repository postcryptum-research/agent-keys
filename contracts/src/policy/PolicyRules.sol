// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {PolicyStorage, TokenLimit, VenuePin} from "./PolicyStorage.sol";

// What the policy's validation and its install both apply (issue #251):
// selectors, Permit2's address, and the rules below, compiled into both.

// `approve(address,uint256,uint256)` of ERC-6909: an allowance of one
// token id, withdrawn with the same function and amount 0
bytes4 constant ERC6909_APPROVE = 0x426a8493;
// The tag of `idAsset`'s hash
bytes32 constant ID_ASSET = keccak256("agent-keys.AgentPolicy.idAsset");
// `transfer(address,uint256,uint256)` of ERC-6909
bytes4 constant ERC6909_TRANSFER = 0x095bcdb6;
// `transferFrom(address,address,uint256,uint256)` of ERC-6909
bytes4 constant ERC6909_TRANSFER_FROM = 0xfe99049a;
// `authorizeOperator(address)` of ERC-777: an operator grant withdrawn
// by another function (`revokeOperator`). No mandate may list it.
bytes4 constant AUTHORIZE_OPERATOR = 0x959b8c3f;
// The four ERC-20 functions the policy meters (`_chargeToken`), the only
// ones a token with a limit may be called through.
// The recipient in argument 0, the amount in argument 1
bytes4 constant ERC20_TRANSFER = 0xa9059cbb; // transfer(address,uint256)
// The sender in argument 0, the recipient in argument 1, the amount in argument 2
bytes4 constant ERC20_TRANSFER_FROM = 0x23b872dd; // transferFrom(address,address,uint256)
// The spender in argument 0, the amount in argument 1
bytes4 constant ERC20_APPROVE = 0x095ea7b3; // approve(address,uint256)
// The spender in argument 0, the amount added in argument 1
bytes4 constant ERC20_INCREASE_ALLOWANCE = 0x39509351; // increaseAllowance(address,uint256)
// @dev Uniswap's Permit2 where it is deployed by the usual CREATE2
// factory: Ethereum, Base and their testnets among others. Not every
// chain: on zkSync-style chains it sits elsewhere. Check it before this
// policy is deployed to a chain it has not been on.
address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
// `x402Authorize(address,address,address,uint256,uint256,uint256,bytes32)`
// of `AgentPolicy`, one of its three entry points the account may call
bytes4 constant X402_AUTHORIZE = 0x4993d616;
// `x402Reclaim(bytes32,address,address,uint256,uint256,uint256,bytes32)` of `AgentPolicy`
bytes4 constant X402_RECLAIM = 0xf3ea183e;
// `orderRegister(address,bytes,bytes)` of `AgentPolicy`
bytes4 constant ORDER_REGISTER = 0x27ddae76;
// `Safe.execTransaction(...)` and `MultiSendCallOnly.multiSend(bytes)`: never
// a plain call (`AgentPolicy.SAFE_EXEC_TRANSACTION` and `MULTI_SEND`)
bytes4 constant SAFE_EXEC_TRANSACTION = 0x6a761202;
bytes4 constant MULTI_SEND = 0x8d80ff0a;

/// @title PolicyRules - the keys and rules the policy's validation and its install share
/// @notice Internal functions only, compiled into `AgentPolicy` and
/// `PolicyInstall` alike, so that both read a mandate the same way.
/// `msg.sender` is the account in both: Kernel calls the policy from the
/// account, and the install runs by DELEGATECALL. `address(this)` is the
/// policy in both.
library PolicyRules {
    /// @dev One installation of a permission: the id and its epoch, which
    /// moves on at uninstall so that nothing of an earlier installation is
    /// found again. Part of every outer key below.
    /// @param id The permission id.
    /// @param epoch The id's epoch for the account.
    /// @return The mandate key.
    function mandate(bytes32 id, uint32 epoch) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, epoch));
    }

    /// @dev The outer key of an allow-list entry.
    /// @param m The mandate key.
    /// @param target The call's target.
    /// @param selector The call's selector; zero for a plain value transfer.
    /// @return The key into `_allowed`.
    function allowedKey(bytes32 m, address target, bytes4 selector) internal pure returns (bytes32) {
        return keccak256(abi.encode(m, target, selector));
    }

    /// @dev The outer key of a payee-list entry.
    /// @param m The mandate key.
    /// @param token_ The token.
    /// @param payee The address the token may reach.
    /// @return The key into `_payees`.
    function payeeKey(bytes32 m, address token_, address payee) internal pure returns (bytes32) {
        return keccak256(abi.encode(m, token_, payee));
    }

    /// @dev The account's limit for a token under a mandate.
    /// @param account The account.
    /// @param m The mandate key.
    /// @param token_ The token.
    /// @return The `TokenLimit`; `set` is false if the token has none.
    function token(address account, bytes32 m, address token_) internal view returns (TokenLimit storage) {
        return PolicyStorage.store().tokens[keccak256(abi.encode(m, token_))][account];
    }

    /// @dev The account's pin of a venue's decoder under a mandate.
    /// @param account The account.
    /// @param m The mandate key.
    /// @param decoder The decoder.
    /// @return The `VenuePin`; a zero `codeHash` if the decoder is not a venue of the mandate.
    function venue(address account, bytes32 m, address decoder) internal view returns (VenuePin storage) {
        return PolicyStorage.store().venues[keccak256(abi.encode(m, decoder))][account];
    }

    /// @dev Whether the mandate limits ids of the contract.
    /// @param m The mandate key.
    /// @param token_ The contract.
    /// @return True if the mandate has an `IdCap` for it.
    function hasIds(bytes32 m, address token_) internal view returns (bool) {
        return PolicyStorage.store().idContracts[keccak256(abi.encode(m, token_))][msg.sender];
    }

    /// @dev Whether a selector is one of the three ERC-6909 functions
    /// `_chargeId` meters.
    /// @param selector The selector.
    /// @return True for ERC-6909's `transfer`, `transferFrom` and `approve`.
    function isIdMetered(bytes4 selector) internal pure returns (bool) {
        return selector == ERC6909_TRANSFER || selector == ERC6909_TRANSFER_FROM || selector == ERC6909_APPROVE;
    }

    /// @notice The key an id's limit is kept under, in the place of a token's
    /// address: `tokenLimit(account, permissionId, idAsset(token, id))` is
    /// the id's limit and what it has spent.
    /// @dev The low 160 bits of a tagged hash of `(token, id)`. Everything a
    /// token's limit has (the sum per operation, the budget, its period) is
    /// then the id's too. To use a limit meant for another id, or a token's,
    /// takes a second preimage of 160 bits.
    /// @param token_ The ERC-6909 contract.
    /// @param id The token id.
    /// @return The key, as an address.
    function idAsset(address token_, uint256 id) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode(ID_ASSET, token_, id)))));
    }

    /// @dev Targets no agent may ever have, whatever the allow-list says: the
    /// account itself (Kernel's own `grantAccess`, `installValidations`,
    /// `changeRootValidator`, `execute`: the mandate would widen or replace
    /// itself) and this policy, except the three entry points the account
    /// calls on purpose: `x402Authorize`, `x402Reclaim` and `orderRegister`.
    /// `msg.sender` is the account in both callers.
    /// And Permit2: it holds one allowance per token and its own `approve`
    /// names who may pull it, a call this policy does not read, so through
    /// it a token would leave past its cap and its payee list. Refused until
    /// the policy meters Permit2's calls. This closes the one well-known
    /// contract of that shape, not the shape: any allow-listed contract
    /// that holds an allowance from the account can move it.
    /// And every place of the account's venues (`_venuePlaces`).
    /// @param target The target.
    /// @param selector The selector, which matters only for this policy.
    /// @return True if the target may be on an allow-list.
    function targetAllowed(address target, bytes4 selector) internal view returns (bool) {
        if (target == msg.sender || target == PERMIT2) return false;
        if (PolicyStorage.store().venuePlaces[target][msg.sender]) return false;
        if (target == address(this)) return selector == X402_AUTHORIZE || selector == X402_RECLAIM || selector == ORDER_REGISTER;
        return true;
    }
}
