//! What the build knows (docs/MOBILE_OWNER_DESIGN.md §6.7): the project's
//! canonical deployments and a small reviewed token table, embedded when the
//! crate is built. A laptop compromised at enrollment or later cannot name a
//! contract or a token on the phone; the price is that a new deployment or a
//! new chain needs a new build.

use std::collections::BTreeMap;

use alloy_primitives::{address, b256, Address, B256};

use crate::review::{Facts, Token, Venue};

/// `contracts/deployments/84532.json`, the canonical file. Variants such as
/// `84532.enclave.json` (a developer's test paymaster) are never embedded.
/// `build.rs` refuses to build when this file does not parse.
const BASE_SEPOLIA: &str = include_str!("../../../contracts/deployments/84532.json");

/// `contracts/deployments/11155111.json`: Sepolia, where CoW Protocol runs
/// and the first orders of issue #80 are placed.
const SEPOLIA: &str = include_str!("../../../contracts/deployments/11155111.json");

/// `(chain, token, symbol, decimals, EIP-712 domain separator)`. USDC on Base
/// Sepolia: `symbol()`, `decimals()` and `DOMAIN_SEPARATOR()` read from the
/// chain on 2026-11-12; the domain recomputed from name "USDC", version "2".
/// Sepolia, read on 2026-11-24: USDC the same way, and WETH, which has no
/// signing domain (zero: no x402 in it).
const TOKENS: &[(u64, Address, &str, u8, B256)] = &[
    (
        84532,
        address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
        "USDC",
        6,
        b256!("71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818"),
    ),
    (
        11155111,
        address!("1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"),
        "USDC",
        6,
        b256!("b90e5057db141a932946e64d09ccb7ffc9b00bd79fec26f698d29af0c83320a6"),
    ),
    (11155111, address!("fFf9976782d46CC05630D1f6eBAb18b2324d6B14"), "WETH", 18, B256::ZERO),
];

/// The current `AgentPolicy`, the same address on both chains: built from
/// commit `e48b93e001f34f460bd4845d231b8e0ee5d26ad6`, with every feature of
/// the source (payee lists, x402, a budget per period, venues, limits per
/// ERC-6909 id).
const CURRENT_POLICY: Address = address!("530DD3C000b3939294072409834c4c4dd160BCd9");

/// The tokens of `TOKENS` that wrap their chain's native currency: the review
/// reads `deposit()` and `withdraw(uint256)` there only (issue #213).
/// Sepolia's WETH is WETH9: its code holds both selectors, `0xd0e30db0` and
/// `0x2e1a7d4d`, and a plain transfer to it wraps for the sender (read from
/// the chain on 2026-11-26).
const WRAPPED_NATIVE: &[(u64, Address)] = &[(11155111, address!("fFf9976782d46CC05630D1f6eBAb18b2324d6B14"))];

/// `AgentPolicy` instances that enforce per-token payee lists (issue #66).
/// An earlier instance decodes such a mandate and ignores the lists, so the
/// review refuses to show payees for any module that is not here. The
/// instance deployed to Base Sepolia on 2026-11-20 was the first; the one of
/// 2026-11-21 (the storage layout of issue #83) followed it there, and on
/// Sepolia the second of 2026-11-24. The current instance is the third on
/// the list, and the anvil harness runs Base Sepolia's deployed code and
/// follows this list too.
const PAYEE_POLICIES: &[Address] =
    &[address!("12b7E79974CC4F4181a40Aa11f9d3170018ae0E2"), address!("2511FF556aa1534676A34F9B715232917e04FE5e"), CURRENT_POLICY];

/// `AgentPolicy` instances that hold a budget per period and venues (issue
/// #80), with a registration held to its period and no refund for an order:
/// Sepolia's second instance of 2026-11-24, and the current one on both
/// chains. The two before it on Sepolia are not listed: the one of
/// 2026-11-21 let a registration outlive its period, and the first of
/// 2026-11-24 refunded an order on the venue's word that it was unfilled,
/// which a filled order's record can be made to say.
const TRADING_POLICIES: &[Address] = &[address!("2511FF556aa1534676A34F9B715232917e04FE5e"), CURRENT_POLICY];

/// `AgentPolicy` instances that hold limits per id of an ERC-6909 contract
/// (issue #186): the current one, on both chains, is the first. Without its
/// entry here the review refuses a mandate with id limits on it.
const ID_POLICIES: &[Address] = &[CURRENT_POLICY];

/// `(chain, decoder, venue name, the decoder's code hash, the venue's own
/// contract, who takes the sold tokens, that address's name)`. CoW Swap:
/// the decoder built from `contracts/src/venues/CowSwapDecoder.sol` at
/// commit `60e773be7c7f071a4e5a69f84e7af3697092a4ef`, at the same address
/// on both chains. Its code differs by chain: the constructor stores the
/// settlement's EIP-712 domain separator, which names the chain. Each hash
/// is that build's runtime code with the settlement, the domain separator
/// and the vault relayer filled in as `domainSeparator()` and
/// `vaultRelayer()` of CoW's settlement return them on that chain (read on
/// 2026-11-25).
#[allow(clippy::type_complexity)]
const VENUES: &[(u64, Address, &str, B256, Address, Address, &str)] = &[
    (
        84532,
        address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a"),
        "CoW Swap",
        b256!("8ed2aee08c4faa05aba4104106931086449b62026b1e4e4bcfeac7d19727d6c1"),
        address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
        address!("C92E8bdf79f0507f65a392b0ab4667716BFE0110"),
        "CoW Swap vault relayer",
    ),
    (
        11155111,
        address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a"),
        "CoW Swap",
        b256!("e11511d23d679dd68a71be1cfd2d6714ba3fb10e077c4db6c4bf3fe96d21e47e"),
        address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
        address!("C92E8bdf79f0507f65a392b0ab4667716BFE0110"),
        "CoW Swap vault relayer",
    ),
];

/// The chains this build has facts for.
pub fn chains() -> Vec<u64> {
    let mut chains = vec![84532, 11155111];
    if cfg!(feature = "test-chains") {
        chains.push(31337);
    }
    chains
}

/// The facts for `chain_id`; empty for a chain the build does not know, where
/// the review then names nothing and refuses what it cannot classify.
pub fn for_chain(chain_id: u64) -> Facts {
    match chain_id {
        84532 => from_deployments(BASE_SEPOLIA, chain_id, true),
        11155111 => from_deployments(SEPOLIA, chain_id, true),
        // Development builds only. The CLI's anvil harness installs Base
        // Sepolia's runtime code at the same addresses
        // (agent-signer/tests/fixtures/chain-code.json), so the current
        // contracts are the same facts there; its paymaster and its tokens
        // are deployed afresh by each test and are not.
        #[cfg(feature = "test-chains")]
        31337 => from_deployments(BASE_SEPOLIA, chain_id, false),
        _ => Facts::default(),
    }
}

/// `canonical`: the chain the file describes. Otherwise only the current
/// contracts, without the paymaster and the superseded versions.
fn from_deployments(json: &str, chain_id: u64, canonical: bool) -> Facts {
    let mut f = Facts::default();
    let Ok(map) = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(json) else {
        return f; // build.rs has parsed these bytes; an empty table fails safe
    };
    for (key, value) in &map {
        let Some(addr) = value.as_str().and_then(|s| s.parse::<Address>().ok()) else { continue };
        let Some((name, superseded)) = contract_name(key) else { continue };
        if !canonical && (superseded || key == "whitelistPaymaster") {
            continue;
        }
        if key == "entryPoint" {
            f.entry_point = Some(addr); // checked, not named: nothing is sent to it by name
            continue;
        }
        f.names.insert(addr, name);
        match key.as_str() {
            // the modules whose init data this build decodes: the current versions only
            "agentPolicy" => {
                f.policy_modules.push(addr);
                if PAYEE_POLICIES.contains(&addr) {
                    f.payee_policy_modules.push(addr);
                }
                if TRADING_POLICIES.contains(&addr) {
                    f.trading_policy_modules.push(addr);
                }
                if ID_POLICIES.contains(&addr) {
                    f.id_policy_modules.push(addr);
                }
                // The local test chain runs this build's contracts at these addresses
                // (the CLI's fixtures, held to the build by scripts/test-fixtures.py):
                // the policy there holds everything the current source does.
                if chain_id == 31337 {
                    for list in [&mut f.payee_policy_modules, &mut f.trading_policy_modules, &mut f.id_policy_modules] {
                        if !list.contains(&addr) {
                            list.push(addr);
                        }
                    }
                }
            }
            "p256Signer" => f.signer_modules.push(addr),
            "demoCounter" => f.demo_counter = Some(addr),
            // no `postOp`, so it cannot charge the account (§6.4); the current instance only
            "whitelistPaymaster" => f.sponsoring_paymasters.push(addr),
            // a superseded recovery validator takes over an account just the same
            k if k.starts_with("p256RecoveryValidator") => f.recovery_validators.push(addr),
            _ => {}
        }
    }
    if canonical {
        // a venue is known only where the deployments file names its decoder
        for (_, decoder, name, code_hash, place, spender, spender_name) in VENUES.iter().filter(|v| v.0 == chain_id) {
            if map.get("cowSwapDecoder").and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) != Some(*decoder) {
                continue;
            }
            f.names.insert(*place, format!("{name} settlement"));
            f.names.insert(*spender, spender_name.to_string());
            f.venues.insert(*decoder, Venue { name: name.to_string(), code_hash: *code_hash, place: *place, spender: *spender });
        }
        for (_, token, symbol, decimals, domain) in TOKENS.iter().filter(|t| t.0 == chain_id) {
            f.names.insert(*token, symbol.to_string());
            f.tokens.insert(*token, Token { symbol: symbol.to_string(), decimals: *decimals, domain: *domain });
            if WRAPPED_NATIVE.contains(&(chain_id, *token)) {
                f.wrapped_native.push(*token);
            }
        }
    }
    f
}

/// The keys of a deployments file the review names: `(key, display name,
/// whether superseded instances follow as key + "V<n>")`. A key that is not
/// here — a new kind of contract, or a suffix on a base that is not
/// versioned — is not a fact until someone adds it; a test accounts for
/// every key of the embedded file.
const CONTRACTS: &[(&str, &str, bool)] = &[
    ("agentPolicy", "AgentPolicy", true),
    ("p256Signer", "P256Signer", true),
    ("p256Validator", "P256Validator", true),
    ("p256RecoveryValidator", "P256RecoveryValidator", true),
    ("whitelistPaymaster", "WhitelistPaymaster", true),
    ("safeNonceAssert", "SafeNonceAssert", true),
    ("demoCounter", "demo counter", true),
    ("cowSwapDecoder", "CoW Swap order decoder", true),
    ("entryPoint", "EntryPoint v0.7", false),
];

/// The display name for a key of a deployments file, and whether it is a
/// superseded version: `agentPolicyV5` → `AgentPolicy v5 (superseded)`.
/// `None` for a key the review does not name.
fn contract_name(key: &str) -> Option<(String, bool)> {
    CONTRACTS.iter().find_map(|(base, name, versioned)| {
        if key == *base {
            return Some((name.to_string(), false));
        }
        let version = key.strip_prefix(base)?.strip_prefix('V')?;
        (*versioned && !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()))
            .then(|| (format!("{name} v{version} (superseded)"), true))
    })
}

/// Whether `label` is a name this build gives to contracts and tokens it
/// verifies, with or without a version: a laptop's pin may not look like
/// one (§6.7), whatever address it is attached to.
pub fn is_build_name(label: &str) -> bool {
    let label = label.trim().to_ascii_lowercase();
    let label = label.strip_suffix(" (superseded)").unwrap_or(&label).trim_end();
    let base = match label.rsplit_once(" v") {
        Some((base, version)) if !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit() || b == b'.') => base,
        _ => label,
    };
    let venue_names = VENUES.iter().flat_map(|v| [format!("{} settlement", v.2), v.6.to_string()]);
    let names: Vec<String> = CONTRACTS.iter().map(|c| c.1.to_string()).chain(TOKENS.iter().map(|t| t.2.to_string())).chain(venue_names).collect();
    names.iter().any(|name| {
        let name = name.to_ascii_lowercase();
        name == label || name == base || name.rsplit_once(" v").is_some_and(|(n, _)| n == label || n == base)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys of the deployments file that are deliberately not facts: the
    /// chain id; an EOA; the Kernel implementation and factory, which no
    /// owner operation addresses — a name would only make value sent there
    /// look like a parameter instead of a payment; and the compiler settings
    /// the instances were built with, which are no addresses (issue #123).
    const NOT_FACTS: &[&str] =
        &["chainId", "paymasterOwner", "kernel", "kernelFactory", "kernelFactoryStaker", "solc", "evmVersion"];

    /// The table cannot lag the file silently: every key is either named or
    /// listed as not a fact, so a new kind of contract fails here until it
    /// is reviewed.
    #[test]
    fn every_key_of_the_embedded_file_is_accounted_for() {
        for (file, chain) in [(BASE_SEPOLIA, 84532), (SEPOLIA, 11155111)] {
            let map: BTreeMap<String, serde_json::Value> = serde_json::from_str(file).unwrap();
            assert_eq!(map["chainId"].as_u64(), Some(chain));
            for (key, value) in &map {
                if NOT_FACTS.contains(&key.as_str()) {
                    continue;
                }
                assert!(contract_name(key).is_some(), "deployments key {key:?} is neither named in facts.rs nor listed in NOT_FACTS");
                assert!(value.as_str().and_then(|s| s.parse::<Address>().ok()).is_some(), "{key}: not an address");
            }
        }
    }

    /// Sepolia: the current policy, CoW's venue and the two tokens of the
    /// first orders. The three earlier policy instances there are named as
    /// superseded and read no mandate, and so is the first decoder.
    #[test]
    fn sepolia() {
        let f = for_chain(11155111);
        assert!(chains().contains(&11155111));
        let policy = address!("530DD3C000b3939294072409834c4c4dd160BCd9");
        assert_eq!(f.names[&policy], "AgentPolicy");
        assert_eq!((&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules), (&vec![policy], &vec![policy], &vec![policy]));
        let first = address!("5Cfa68d42e4245c9Ba71e6103D4E2D99F3E40b42");
        assert_eq!(f.names[&first], "AgentPolicy v1 (superseded)");
        assert!(!f.policy_modules.contains(&first) && !f.trading_policy_modules.contains(&first));
        let second = address!("b15700E18D058BF83f5d9D38b5407f214df5E410");
        assert_eq!(f.names[&second], "AgentPolicy v2 (superseded)");
        assert!(!f.policy_modules.contains(&second) && !f.trading_policy_modules.contains(&second) && !f.payee_policy_modules.contains(&second));
        // the trading instance of 2026-11-24, before the redeploy: named, and no longer read
        let third = address!("2511FF556aa1534676A34F9B715232917e04FE5e");
        assert_eq!(f.names[&third], "AgentPolicy v3 (superseded)");
        assert!(!f.policy_modules.contains(&third) && !f.trading_policy_modules.contains(&third) && !f.payee_policy_modules.contains(&third));
        // the instance of 2026-11-25, replaced the next day by the one with the batch rule of #206
        let fourth = address!("e52825D44396d72cA17adF0c0260d468e94F8C94");
        assert_eq!(f.names[&fourth], "AgentPolicy v4 (superseded)");
        for list in [&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules, &f.id_policy_modules] {
            assert!(!list.contains(&fourth));
        }
        assert_eq!(f.signer_modules, vec![address!("d88d25Ca3e042A28893781935756ee90Bc2d2769")]);
        assert_eq!(f.entry_point, Some(address!("0000000071727De22E5E9d8BAf0edAc6f37da032")));

        let decoder = address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a");
        let (settlement, relayer) = (address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"), address!("C92E8bdf79f0507f65a392b0ab4667716BFE0110"));
        assert_eq!(f.venues.len(), 1);
        let v = &f.venues[&decoder];
        assert_eq!((v.name.as_str(), v.place, v.spender), ("CoW Swap", settlement, relayer));
        assert_eq!(v.code_hash, b256!("e11511d23d679dd68a71be1cfd2d6714ba3fb10e077c4db6c4bf3fe96d21e47e"));
        assert_eq!(f.names[&decoder], "CoW Swap order decoder");
        // the first decoder is a name only: no venue is read through it
        let old_decoder = address!("085883DD35e12d32de2F4f9d8CeFBE663ffa7cB0");
        assert_eq!(f.names[&old_decoder], "CoW Swap order decoder v1 (superseded)");
        assert!(!f.venues.contains_key(&old_decoder));
        assert_eq!(f.names[&settlement], "CoW Swap settlement");
        assert_eq!(f.names[&relayer], "CoW Swap vault relayer");
        // the names a laptop's pin may not carry
        for reserved in ["CoW Swap settlement", "CoW Swap vault relayer", "CoW Swap order decoder", "WETH"] {
            assert!(is_build_name(reserved), "{reserved:?}");
        }

        let usdc_at = address!("1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
        let usdc = &f.tokens[&usdc_at];
        assert_eq!((usdc.symbol.as_str(), usdc.decimals), ("USDC", 6));
        use alloy_primitives::{keccak256, U256};
        use alloy_sol_types::SolValue;
        let domain = keccak256(
            (
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("USDC"),
                keccak256("2"),
                U256::from(11155111),
                usdc_at,
            )
                .abi_encode(),
        );
        assert_eq!(usdc.domain, domain);
        let weth = &f.tokens[&address!("fFf9976782d46CC05630D1f6eBAb18b2324d6B14")];
        assert_eq!((weth.symbol.as_str(), weth.decimals, weth.domain), ("WETH", 18, B256::ZERO));
        // Sepolia's WETH is the chain's wrapped ether, and nothing else is; Base Sepolia has none
        assert_eq!(f.wrapped_native, vec![address!("fFf9976782d46CC05630D1f6eBAb18b2324d6B14")]);
        assert!(for_chain(84532).wrapped_native.is_empty());
    }

    /// The redeploys of 2026-11-25 and 2026-11-26 (the policy from
    /// `e48b93e001f34f460bd4845d231b8e0ee5d26ad6`): on both
    /// chains the current policy is read with every feature, CoW's venue is
    /// known with that chain's decoder code, and each instance it replaced
    /// is named under its versioned key as superseded.
    #[test]
    fn the_redeployed_contracts_are_current_on_both_chains() {
        let decoder = address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a");
        let mut hashes = Vec::new();
        for chain in [84532, 11155111] {
            let f = for_chain(chain);
            let p = vec![CURRENT_POLICY];
            assert_eq!(f.names[&CURRENT_POLICY], "AgentPolicy", "{chain}");
            assert_eq!((&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules), (&p, &p, &p), "{chain}");
            assert_eq!(f.id_policy_modules, p, "{chain}: the first instance with limits per ERC-6909 id");
            assert_eq!(f.signer_modules, vec![address!("d88d25Ca3e042A28893781935756ee90Bc2d2769")], "{chain}");
            assert_eq!(f.demo_counter, Some(address!("29da894F3E456CAC92b3EC76710524E74411E99f")), "{chain}");
            assert_eq!(f.sponsoring_paymasters, vec![address!("657792557C1D40f2Da031FD7aB277078D2c0a4cb")], "{chain}");
            assert!(f.recovery_validators.contains(&address!("b7a06e6c7B5cC9852578EF89f38d161C31218047")), "{chain}");
            for (addr, name) in [
                (address!("9b6f7A83e10F3360af6B34F672c0AC5295f72d63"), "P256Validator"),
                (address!("b7a06e6c7B5cC9852578EF89f38d161C31218047"), "P256RecoveryValidator"),
                (address!("29f600cBcdC5221a63bD5c88F4a75E20c5CBe219"), "SafeNonceAssert"),
                (decoder, "CoW Swap order decoder"),
            ] {
                assert_eq!(f.names[&addr], name, "{chain}");
            }
            let v = &f.venues[&decoder];
            assert_eq!((v.name.as_str(), v.place), ("CoW Swap", address!("9008D19f58AAbD9eD0D60971565AA8510560ab41")), "{chain}");
            hashes.push(v.code_hash);
        }
        // the decoder keeps the settlement's domain separator, which names the chain
        assert_ne!(hashes[0], hashes[1]);

        // what the redeploy replaced keeps its address under the next versioned name
        let superseded = [
            (84532, address!("12b7E79974CC4F4181a40Aa11f9d3170018ae0E2"), "AgentPolicy v9 (superseded)"),
            (84532, address!("dA4cd5c37a5B888826A7A9e09dF6A9033A1550c2"), "P256Validator v2 (superseded)"),
            (84532, address!("63dd80Fc5E109A44fd179F85050487E02c5e6958"), "P256RecoveryValidator v2 (superseded)"),
            (84532, address!("a19e6061b1C193573e5fe46c39363FfDd5CCA22E"), "P256Signer v2 (superseded)"),
            (84532, address!("C14AbFF54D40f4DAf665391E0B7079bd53EB8279"), "SafeNonceAssert v1 (superseded)"),
            (84532, address!("50Ab706dA586895D5775a1e51DcF1a66eAaAE001"), "WhitelistPaymaster v2 (superseded)"),
            (84532, address!("D2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1"), "demo counter v1 (superseded)"),
            (11155111, address!("2511FF556aa1534676A34F9B715232917e04FE5e"), "AgentPolicy v3 (superseded)"),
            (11155111, address!("dA4cd5c37a5B888826A7A9e09dF6A9033A1550c2"), "P256Validator v1 (superseded)"),
            (11155111, address!("63dd80Fc5E109A44fd179F85050487E02c5e6958"), "P256RecoveryValidator v1 (superseded)"),
            (11155111, address!("a19e6061b1C193573e5fe46c39363FfDd5CCA22E"), "P256Signer v1 (superseded)"),
            (11155111, address!("C14AbFF54D40f4DAf665391E0B7079bd53EB8279"), "SafeNonceAssert v1 (superseded)"),
            (11155111, address!("50Ab706dA586895D5775a1e51DcF1a66eAaAE001"), "WhitelistPaymaster v1 (superseded)"),
            (11155111, address!("0F5912777DFd7E385c1896b68885d1CC229DF559"), "demo counter v1 (superseded)"),
            (11155111, address!("085883DD35e12d32de2F4f9d8CeFBE663ffa7cB0"), "CoW Swap order decoder v1 (superseded)"),
        ];
        for (chain, addr, name) in superseded {
            let f = for_chain(chain);
            assert_eq!(f.names[&addr], name, "{chain} {addr}");
            // a superseded module is a name, never a module the build reads, sponsors with or counts on
            assert!(!f.policy_modules.contains(&addr) && !f.signer_modules.contains(&addr), "{chain} {addr}");
            assert!(!f.sponsoring_paymasters.contains(&addr) && f.demo_counter != Some(addr) && !f.venues.contains_key(&addr), "{chain} {addr}");
        }
    }

    #[test]
    fn names_follow_the_table_and_only_listed_bases_have_versions() {
        assert_eq!(contract_name("agentPolicy"), Some(("AgentPolicy".to_string(), false)));
        assert_eq!(contract_name("agentPolicyV12"), Some(("AgentPolicy v12 (superseded)".to_string(), true)));
        assert_eq!(contract_name("p256RecoveryValidatorV1"), Some(("P256RecoveryValidator v1 (superseded)".to_string(), true)));
        // every contract a redeploy replaces is kept under a versioned name (Deploy.s.sol)
        for (key, name) in [
            ("safeNonceAssertV1", "SafeNonceAssert v1 (superseded)"),
            ("demoCounterV1", "demo counter v1 (superseded)"),
            ("cowSwapDecoderV1", "CoW Swap order decoder v1 (superseded)"),
            ("whitelistPaymasterV2", "WhitelistPaymaster v2 (superseded)"),
            ("p256ValidatorV2", "P256Validator v2 (superseded)"),
            ("p256SignerV2", "P256Signer v2 (superseded)"),
            ("p256RecoveryValidatorV2", "P256RecoveryValidator v2 (superseded)"),
        ] {
            assert_eq!(contract_name(key), Some((name.to_string(), true)), "{key}");
        }
        // a suffix on a base that is not versioned, a version that is not a number, an unknown base
        assert_eq!(contract_name("entryPointV07"), None);
        assert_eq!(contract_name("demoCounterVx"), None);
        assert_eq!(contract_name("agentPolicyV"), None);
        assert_eq!(contract_name("agentPolicyVx"), None);
        assert_eq!(contract_name("usdcV2"), None);
        // the names a laptop's pin may not carry
        for reserved in ["AgentPolicy", "agentpolicy", " P256Validator ", "P256Validator v1", "AgentPolicy v6 (superseded)", "demo counter", "USDC", "EntryPoint", "EntryPoint v0.7"] {
            assert!(is_build_name(reserved), "{reserved:?}");
        }
        for free in ["policy module (config)", "my vault", "AgentPolicy2", "paymaster (config)", "counter"] {
            assert!(!is_build_name(free), "{free:?}");
        }
    }

    #[test]
    fn base_sepolia() {
        let f = for_chain(84532);
        let policy = address!("530DD3C000b3939294072409834c4c4dd160BCd9");
        let signer = address!("d88d25Ca3e042A28893781935756ee90Bc2d2769");
        assert_eq!(f.names[&policy], "AgentPolicy");
        assert_eq!((&f.policy_modules, &f.signer_modules), (&vec![policy], &vec![signer]), "the current policy and signer only, each in its slot");
        // superseded versions are named as such and are not readable modules
        let v6 = address!("8347dBC3d7A71DAFDeED5975ce85638494865F73");
        assert_eq!(f.names[&v6], "AgentPolicy v6 (superseded)");
        assert!(!f.policy_modules.contains(&v6));
        // the instance before payee lists: named, superseded, and not one that enforces lists
        let v7 = address!("dd544A6F0220778Fff16F51B468656e73E32ae85");
        assert_eq!(f.names[&v7], "AgentPolicy v7 (superseded)");
        assert!(!f.policy_modules.contains(&v7));
        // the first instance with payee lists, before the storage layout of #83
        let v8 = address!("2E6F47B2F3d0F3E6071eCdBc0b445a2B26d23D95");
        assert_eq!(f.names[&v8], "AgentPolicy v8 (superseded)");
        assert!(!f.policy_modules.contains(&v8));
        // the payee instance of 2026-11-21, before the redeploy
        let v9 = address!("12b7E79974CC4F4181a40Aa11f9d3170018ae0E2");
        assert_eq!(f.names[&v9], "AgentPolicy v9 (superseded)");
        assert!(!f.policy_modules.contains(&v9));
        // the instance of 772e8f1, which carries #190 and was replaced the same day: named, and read by nothing
        let v10 = address!("6b8F14421007FC49251F6B2d48071795A077B2D8");
        assert_eq!(f.names[&v10], "AgentPolicy v10 (superseded)");
        for list in [&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules, &f.id_policy_modules] {
            assert!(!list.contains(&v10));
        }
        // the instance of 60e773b, replaced by the one with the batch rule of #206: named, and read by nothing
        let v11 = address!("e52825D44396d72cA17adF0c0260d468e94F8C94");
        assert_eq!(f.names[&v11], "AgentPolicy v11 (superseded)");
        for list in [&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules, &f.id_policy_modules] {
            assert!(!list.contains(&v11));
        }
        assert_eq!(f.payee_policy_modules, vec![policy]);
        assert_eq!(f.names[&address!("68544284bfDbbd6bDB9F6A1D80D05C387015daA9")], "P256Signer v1 (superseded)");
        // every recovery validator can take over; only the current paymaster sponsors
        assert_eq!(f.recovery_validators.len(), 3);
        assert_eq!(f.sponsoring_paymasters, vec![address!("657792557C1D40f2Da031FD7aB277078D2c0a4cb")]);
        assert_eq!(f.demo_counter, Some(address!("29da894F3E456CAC92b3EC76710524E74411E99f")));
        // an EOA is not a named contract; the EntryPoint is a checked fact, not a name
        assert!(!f.names.contains_key(&address!("52370eE170c0E2767B32687166791973a0dE7966")));
        let entry = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
        assert_eq!(f.entry_point, Some(entry));
        assert!(!f.names.contains_key(&entry) && !f.names.contains_key(&address!("d6CEDDe84be40893d153Be9d467CD6aD37875b28")));
        let usdc = &f.tokens[&address!("036CbD53842c5426634e7929541eC2318f3dCF7e")];
        assert_eq!((usdc.symbol.as_str(), usdc.decimals), ("USDC", 6));
        // the embedded domain is the EIP-712 domain of (name "USDC", version "2", this chain, this address)
        use alloy_primitives::{keccak256, U256};
        use alloy_sol_types::SolValue;
        let domain = keccak256(
            (
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("USDC"),
                keccak256("2"),
                U256::from(84532),
                address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
            )
                .abi_encode(),
        );
        assert_eq!(usdc.domain, domain);
    }

    #[test]
    fn unknown_chains_have_no_facts_and_the_test_chain_is_opt_in() {
        let none = for_chain(1);
        assert!(none.names.is_empty() && none.policy_modules.is_empty() && none.sponsoring_paymasters.is_empty());
        let anvil = for_chain(31337);
        if cfg!(feature = "test-chains") {
            assert_eq!(chains(), vec![84532, 11155111, 31337]);
            assert!(anvil.demo_counter.is_some() && anvil.policy_modules.len() == 1 && anvil.signer_modules.len() == 1);
            assert!(anvil.sponsoring_paymasters.is_empty() && anvil.tokens.is_empty(), "the harness deploys those afresh");
            assert!(anvil.names.values().all(|n| !n.contains("superseded")));
        } else {
            assert_eq!(chains(), vec![84532, 11155111]);
            assert!(anvil.names.is_empty(), "a release build knows no test chain");
        }
    }
}
