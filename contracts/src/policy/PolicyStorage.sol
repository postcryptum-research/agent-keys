// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

/// @title PolicyStorage - the storage of AgentPolicy, in one layout
/// @notice Where `AgentPolicy` keeps the mandates (issue #251). One layout,
/// so that the policy and the fixed code it reaches by DELEGATECALL read and
/// write the same storage through this library, without inheritance.
/// @dev Validation reads and writes this storage on the account's behalf,
/// and ERC-7562 lets a bundler admit that only for slots that belong to the
/// account: `keccak256(account ‖ x) + n` with a small `n`. So the account is
/// the innermost key of every mapping below, and everything else that names
/// an entry (the permission id, its epoch, a target and selector, a token, a
/// payee, a digest) is hashed into the outer key first. A nested mapping
/// with the account outermost holds the same data in slots a rule-enforcing
/// bundler refuses (issue #83). The `mandate` in the keys below is
/// `_mandate(id, epoch)` of `AgentPolicy`: one installation of a permission.
/// Inside the layout struct a mapping's slot is the struct's slot plus its
/// place, and a value's slot is still `keccak256(account ‖ x)` with the
/// account innermost.

/// A permission's mandate as installed, and its native-value counters.
/// Three storage slots: (`validUntil`, `epoch`, `maxValuePerOp`),
/// (`budget`, `spent`), (`validAfter`, `period`, `periodSeen`).
struct Config {
    // The mandate's last valid second, inclusive, as EntryPoint v0.7 reads it.
    // 2^48 - 1 seconds is about 8.9 million years
    uint48 validUntil; // 0 = not installed
    // Uninstalls of this id so far, part of every key of an installation
    // (`_mandate`); 2^32 - 1 uninstalls of one id is far past any use
    uint32 epoch; // bumps on uninstall so stale entries die
    // The most native value (wei) one operation may move, its Safe
    // transactions and batch legs included; 2^128 - 1 wei is about 3.4e20 ETH
    uint128 maxValuePerOp;
    // The most native value, plus the gas the account pays for itself, the
    // mandate may spend: over its whole life, or in each period. Same range
    uint128 budget;
    // What has been charged to `budget`, in the current period if there is
    // one; never above `budget`
    uint128 spent;
    // The mandate's first valid second, inclusive. Same range as `validUntil`
    uint48 validAfter; // 0 = from installation on
    // The budgets' window in seconds; 0 = one budget for the mandate's
    // whole life. Windows are counted from the Unix epoch: with 86400,
    // a day from midnight UTC. 2^32 - 1 seconds is over 136 years.
    uint32 period;
    // The window `spent` counts for, plus one; 0 before the first.
    // The operation names the window (`_enterPeriod`)
    uint48 periodSeen;
}

/// What a mandate keeps of one of its venues, per (mandate, decoder,
/// account): two slots. A zero `codeHash` means the decoder is not one of
/// the mandate's venues.
struct VenuePin {
    // The decoder's code hash the owner pinned
    bytes32 codeHash;
    // keccak256 of the owner's config for the venue
    bytes32 configHash;
}

/// What a mandate keeps for one token, per (mandate, token, account):
/// three slots, (`maxPerOp`, `budget`), (`spent`, `set`, `payeesOnly`),
/// (`domainSeparator`). `tokenLimit()` returns it whole.
struct TokenLimit {
    // As `TokenCap.maxPerOp`
    uint128 maxPerOp;
    // As `TokenCap.budget`
    uint128 budget;
    // What has been charged to `budget`, in the current period if there
    // is one; never above `budget`
    uint128 spent;
    // True once the token has a limit; a token without one is unset
    bool set;
    // true: only the payees listed for the token may be paid or approved.
    // It sits before `domainSeparator`, so `tokenLimit()` returns the
    // separator as its sixth word (the fifth before payee lists).
    bool payeesOnly;
    // As `TokenCap.domainSeparator`: non-zero to allow x402 payments
    bytes32 domainSeparator;
}

/// A registered x402 authorization, keyed by its EIP-712 digest. A
/// registered order is kept the same way, under its digest. Two slots.
struct Pending {
    // The amount charged to the token's budget; 0 marks no registration,
    // so nothing of value 0 is registered. Same range as `TokenCap.budget`
    uint128 value;
    // x402: the authorization's `validBefore` (the token takes it before
    // that second); an order: its `validTo` (fillable up to and at it).
    // `checkSignaturePolicy` vouches up to and at this second. 2^48 - 1
    // seconds is about 8.9 million years
    uint48 validBefore;
    // The token charged: the digest names it only through its domain
    address token;
}

/// What a mandate keeps of a shape judge, per (mandate, selector, account):
/// one slot. A zero `judge` means no judge reads the selector.
struct ShapePin {
    // The judge, its code as the owner pinned it at install
    address judge;
    // Its role for the selector: `SHAPE_WALLET` or `SHAPE_BATCH`
    uint8 role;
    // Paused by the mandate's guardian (#251, decision 2): validation refuses
    // the selector's calls. In the pin's slot, so reading it costs nothing more
    bool paused;
}

library PolicyStorage {
    /// @dev The layout's slot: 0. The policy keeps nothing else in storage,
    /// and the code it reaches by DELEGATECALL reads it through this library
    /// only, so a namespaced slot (ERC-7201) would guard against nothing; at
    /// 0 every mapping keeps the slot it had as a state variable, in the same
    /// order, and an access costs what it cost then. A namespaced slot made
    /// the policy 544 bytes larger (2026-11-27).
    bytes32 internal constant SLOT = 0;

    /// The mandates and their counters.
    struct Layout {
    // Map of permission id => account => the mandate's limits and counters.
    // One `Config` per id, kept across installations; its `epoch` names the
    // current one
    mapping(bytes32 id => mapping(address account => Config)) configs;
    // Map of account => the number of its permissions with a mandate here; `isInitialized` reads it
    mapping(address account => uint256) usedIds;
    // Map of key => account => the kind of call the mandate allows: 0 none,
    // 1 a plain call, `SHAPE_WALLET` or `SHAPE_BATCH` a call that the
    // mandate's shape judge for its selector reads (issue #251).
    // key: `keccak256(mandate, target, selector)`
    mapping(bytes32 key => mapping(address account => uint8)) allowed;
    // Map of key => account => the token's limit and counter.
    // key: `keccak256(mandate, token)`
    mapping(bytes32 key => mapping(address account => TokenLimit)) tokens;
    // Map of key => account => a registered x402 authorization or order.
    // key: `keccak256(mandate, digest)`
    mapping(bytes32 key => mapping(address account => Pending)) x402;
    // Map of key => account => whether the token may reach the payee.
    // key: `keccak256(mandate, token, payee)`
    mapping(bytes32 key => mapping(address account => bool)) payees;
    // key: `keccak256(mandate, token)`. The window the token's `spent`
    // counts for, plus one. Beside `TokenLimit` and not in it, so that what
    // `tokenLimit()` returns keeps its shape.
    mapping(bytes32 key => mapping(address account => uint48)) tokenPeriod;
    // Map of key => account => whether the mandate limits ids of the
    // ERC-6909 contract. key: `keccak256(mandate, token)`. The limits
    // themselves are `TokenLimit`s in `_tokens`, under `idAsset(token, id)`.
    mapping(bytes32 key => mapping(address account => bool)) idContracts;
    // key: `keccak256(mandate, digest)`. The window a registered
    // authorization or order was charged in, plus one; 0 without periods.
    mapping(bytes32 key => mapping(address account => uint48)) chargedIn;
    // Map of key => account => the venue's pinned code and config.
    // key: `keccak256(mandate, decoder)`
    mapping(bytes32 key => mapping(address account => VenuePin)) venues;
    // The venues an account has ever pinned in a mandate: each venue's own
    // contract, its decoder and its spender. None of them is a target for
    // the agent under any mandate of the account, whichever was installed
    // first: at the venue itself an order could be signed past the decoder
    // (CoW: `setPreSignature`), and the spender holds the owner's allowance
    // of the sold tokens (CoW: the vault relayer), so through it they would
    // leave past their caps and payee lists. Never cleared: an address that
    // was a venue stays out of reach. One path leads to a venue's own
    // contract: a call its decoder judged, as the leg after that call's
    // registration (`_judgeVenueCall`).
    mapping(address place => mapping(address account => bool)) venuePlaces;
    // Map of key => account => the shape judge the mandate pinned for a
    // selector, and its role (issue #251). key: `keccak256(mandate, selector)`
    mapping(bytes32 key => mapping(address account => ShapePin)) shapes;
    // Map of key => account => the guardian the owner named for the mandate:
    // it may pause the mandate's modules, never widen anything (#251,
    // decision 2). key: `keccak256(mandate)`
    mapping(bytes32 key => mapping(address account => address)) guardians;
    // Map of key => account => whether the mandate's guardian paused the
    // module: validation reads it for a venue decoder; a shape judge's pins
    // carry their own flag, read in validation, and this one is what
    // `paused` answers. key: `keccak256(mandate, module)`
    mapping(bytes32 key => mapping(address account => bool)) modulePaused;
    }

    /// @dev The layout, at its slot.
    /// @return l The storage the policy keeps its mandates in.
    function store() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly ("memory-safe") {
            l.slot := slot
        }
    }
}
