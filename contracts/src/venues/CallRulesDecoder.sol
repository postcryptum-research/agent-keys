// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

import {IVenueDecoder} from "./IVenueDecoder.sol";
import {VenueCalls} from "./VenueCalls.sol";

/// @title CallRulesDecoder - calls at one contract, each argument held to a rule, for `AgentPolicy` (issue #80)
/// @notice Judges a call, not an order: a call the account makes itself at
///         one contract, this decoder's `venue`, in the leg right after its
///         registration. The owner's config lists the functions the agent
///         may call there, and for each function a rule for every argument
///         word:
///         - the word is the account's address (a beneficiary held to the
///           account: `onBehalfOf`, `receiver`, `to`);
///         - the word is a value the owner set (a token, a market, a
///           destination, a zero);
///         - the word is at most a bound the owner set;
///         - the word is an amount, charged in a token the owner named;
///         - the word is the agent's to choose.
///         A function has a rule for each of its words, in order: none is
///         left out, so a word the agent may choose is one the owner wrote
///         down as such. A call is allowed only if its selector is listed
///         once, it is exactly as long as its rules, and every word passes.
///         No native value goes with the call.
/// @dev No storage, no upgrade path, no `delegatecall`, no `selfdestruct`.
/// One decoder is deployed for each contract it speaks for: `AgentPolicy`
/// admits a decoder's call at the decoder's own `venue` and nowhere else.
///
/// What this decoder does not know: what the contract does with the words.
/// It reads calldata as 32-byte words after the selector and nothing more.
/// - It does not know which word is a beneficiary: an owner who leaves one
///   to the agent has given the agent that choice.
/// - A function with a dynamic argument (`bytes`, an array) has offsets and
///   lengths among its words. They are words like any other: held to the
///   values of the one encoding the owner means (an empty `bytes` is an
///   offset and a zero length), the call has that shape and no other.
/// - The amount charged is the word the owner named, as the contract will
///   read it. A contract that takes more than that word says, or takes it
///   from a balance it already holds, is outside what a word can bound.
/// - The charge is made when the call is registered, in validation: a call
///   that reverts when the operation runs was still charged, as a transfer
///   is, and the mandate's period gives it back.
contract CallRulesDecoder is IVenueDecoder {
    /// Semantic version of this contract (house rule 9).
    string public constant VERSION = "0.1.0";

    /// The rule for one argument word. `value` is read by the kinds that
    /// need one and must be zero for the others.
    struct Word {
        /// One of `IS_ACCOUNT`, `IS_VALUE`, `AT_MOST`, `CHARGED`, `ANY`.
        uint8 kind;
        /// `IS_VALUE`: the word. `AT_MOST`: the bound. `CHARGED`: the token
        /// the amount is charged in. Zero otherwise.
        uint256 value;
    }

    /// A function the agent may call at the venue, and the rule for each of its argument words, in order.
    struct Function {
        /// The function's selector.
        bytes4 selector;
        /// A rule for every 32-byte word after the selector: the call has exactly this many.
        Word[] words;
    }

    /// The owner's configuration for the venue, ABI-encoded, hash-pinned in the mandate.
    struct Config {
        /// The functions the agent may call, each once.
        Function[] functions;
    }

    /// The word is the address of the account that makes the call.
    uint8 public constant IS_ACCOUNT = 0;
    /// The word is the rule's `value`.
    uint8 public constant IS_VALUE = 1;
    /// The word, as an unsigned number, is at most the rule's `value`.
    uint8 public constant AT_MOST = 2;
    /// The word is an amount of the token the rule's `value` names; it is
    /// charged against that token's cap per operation and its budget.
    uint8 public constant CHARGED = 3;
    /// The word is the agent's to choose.
    uint8 public constant ANY = 4;

    /// The most functions a config may list: a decoder reads them all, inside a gas bound.
    uint256 public constant MAX_FUNCTIONS = 8;
    /// The most argument words a function may have.
    uint256 public constant MAX_WORDS = 16;

    /// @dev There is no code at the venue's address.
    error NotAContract();
    /// @dev The call is shorter than a selector.
    error NotACall();
    /// @dev The call's function is not listed.
    /// @param selector The call's selector.
    error FunctionNotListed(bytes4 selector);
    /// @dev The config lists the call's function more than once.
    error FunctionListedTwice();
    /// @dev The call is not exactly as long as its function's rules.
    /// @param length The call's length in bytes.
    error NotTheFunctionsLength(uint256 length);
    /// @dev A word does not pass its rule.
    /// @param index The word's position among the arguments, from zero.
    error WordRefused(uint256 index);
    /// @dev The config breaks a rule of `checkConfig`.
    error InvalidConfig();

    /// The one contract this decoder's calls are made at.
    address public immutable override venue;
    /// Who takes tokens from the account at the venue: the venue itself, or
    /// the contract of the same protocol that pulls for it.
    address public immutable override spender;

    /// @dev Decoder constructor.
    /// @param venue_ The contract the calls are made at.
    /// @param spender_ The contract the account approves there; the venue itself where it pulls tokens itself.
    constructor(address venue_, address spender_) {
        if (venue_.code.length == 0 || spender_.code.length == 0) revert NotAContract();
        venue = venue_;
        spender = spender_;
    }

    /// @inheritdoc IVenueDecoder
    /// @dev `order` is the call's calldata: the selector and the argument
    /// words. `notBefore` and `validTo` are zero: that is how a decoder says
    /// it judged a call the account makes now (`VenueCalls`). `digest` is
    /// that call's hash, with no value. `sellToken` and `mostSold` are the
    /// charged word's token and amount, or zero where the function charges
    /// nothing. It does not rest on `checkConfig` having been asked: a
    /// config with too many functions or words, a function listed twice, a
    /// kind it does not know, a value where none belongs or two charged
    /// words allows nothing.
    function judge(address account, bytes calldata config, bytes calldata order)
        external
        pure
        override
        returns (address sellToken, uint256 mostSold, uint48 notBefore, uint48 validTo, bytes32 digest)
    {
        // A selector, then whole words
        if (order.length < 4) revert NotACall();
        bytes4 selector = bytes4(order[0:4]);
        Function memory f = _function(abi.decode(config, (Config)), selector);
        if (f.words.length > MAX_WORDS) revert InvalidConfig();
        // Exactly as long as its rules: nothing rides along after the last word
        if (order.length != 4 + 32 * f.words.length) revert NotTheFunctionsLength(order.length);

        bool charged;
        for (uint256 i; i < f.words.length; i++) {
            uint256 word = uint256(bytes32(order[4 + 32 * i:36 + 32 * i]));
            Word memory rule = f.words[i];
            if (rule.kind == IS_ACCOUNT) {
                // The whole word: an address with anything above it is another word
                if (rule.value != 0) revert InvalidConfig();
                if (word != uint256(uint160(account))) revert WordRefused(i);
            } else if (rule.kind == IS_VALUE) {
                if (word != rule.value) revert WordRefused(i);
            } else if (rule.kind == AT_MOST) {
                if (word > rule.value) revert WordRefused(i);
            } else if (rule.kind == CHARGED) {
                // One charge a call: the policy charges one token for a registration
                if (charged || rule.value == 0 || rule.value >> 160 != 0) revert InvalidConfig();
                charged = true;
                (sellToken, mostSold) = (address(uint160(rule.value)), word);
            } else if (rule.kind == ANY) {
                if (rule.value != 0) revert InvalidConfig();
            } else {
                revert InvalidConfig();
            }
        }
        // What the call can cost was set above; the one call it is
        (notBefore, validTo) = (0, 0);
        digest = VenueCalls.digest(0, order);
    }

    /// @inheritdoc IVenueDecoder
    /// @dev A call is made in the operation that registers it or not at all:
    /// nothing of it is left for later, and `AgentPolicy` keeps no record of
    /// it to give back. Always false.
    function untouched(address, bytes calldata) external pure override returns (bool) {
        return false;
    }

    /// @notice Whether `config` is a configuration the owner's tools can be
    /// shown: one to `MAX_FUNCTIONS` functions, none twice; for each, at
    /// most `MAX_WORDS` words, every kind a known one, a value only where
    /// its kind reads one, at most one charged word, and code at the charged
    /// token's address.
    /// @dev `judge` does not rely on this check having been asked, except
    /// for the code at the token: it runs inside validation, where an
    /// address without code may not be touched.
    /// @param config `abi.encode(Config)`.
    /// @return True if the config passes; otherwise the call reverts, so it never returns false.
    function checkConfig(bytes calldata config) external view returns (bool) {
        Config memory c = abi.decode(config, (Config));
        if (c.functions.length == 0 || c.functions.length > MAX_FUNCTIONS) revert InvalidConfig();
        for (uint256 i; i < c.functions.length; i++) {
            Function memory f = c.functions[i];
            // Not listed before (at most `MAX_FUNCTIONS`, so the quadratic scan stays small)
            for (uint256 j; j < i; j++) {
                if (c.functions[j].selector == f.selector) revert InvalidConfig();
            }
            if (f.words.length > MAX_WORDS) revert InvalidConfig();
            bool charged;
            for (uint256 k; k < f.words.length; k++) {
                Word memory rule = f.words[k];
                if (rule.kind == CHARGED) {
                    // One charged word, in a token: an address, with code
                    if (charged || rule.value == 0 || rule.value >> 160 != 0) revert InvalidConfig();
                    if (address(uint160(rule.value)).code.length == 0) revert InvalidConfig();
                    charged = true;
                } else if (rule.kind == IS_ACCOUNT || rule.kind == ANY) {
                    if (rule.value != 0) revert InvalidConfig();
                } else if (rule.kind != IS_VALUE && rule.kind != AT_MOST) {
                    revert InvalidConfig();
                }
            }
        }
        return true;
    }

    /// @dev The config's function with `selector`: listed exactly once,
    /// among at most `MAX_FUNCTIONS`. Every entry is read, not only up to
    /// the first match, so that a function listed twice is caught (which of
    /// its two rule lists would hold?).
    /// @param c The owner's config.
    /// @param selector The call's selector.
    /// @return f The function's rules.
    function _function(Config memory c, bytes4 selector) internal pure returns (Function memory f) {
        if (c.functions.length > MAX_FUNCTIONS) revert InvalidConfig();
        bool found;
        for (uint256 i; i < c.functions.length; i++) {
            if (c.functions[i].selector != selector) continue;
            if (found) revert FunctionListedTwice();
            found = true;
            f = c.functions[i];
        }
        if (!found) revert FunctionNotListed(selector);
    }
}
