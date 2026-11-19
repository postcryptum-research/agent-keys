//! What the build knows (docs/MOBILE_OWNER_DESIGN.md §6.7): the project's
//! canonical deployments and a small reviewed token table, embedded when the
//! crate is built. A laptop compromised at enrollment or later cannot name a
//! contract or a token on the phone; the price is that a new deployment or a
//! new chain needs a new build.

use std::collections::BTreeMap;

use alloy_primitives::{address, b256, Address, B256};

use crate::review::{Facts, Token};

/// `contracts/deployments/84532.json`, the canonical file. Variants such as
/// `84532.enclave.json` (a developer's test paymaster) are never embedded.
/// `build.rs` refuses to build when this file does not parse.
const BASE_SEPOLIA: &str = include_str!("../../../contracts/deployments/84532.json");

/// `(chain, token, symbol, decimals, EIP-712 domain separator)`. USDC on Base
/// Sepolia: `symbol()`, `decimals()` and `DOMAIN_SEPARATOR()` read from the
/// chain on 2026-11-12; the domain recomputed from name "USDC", version "2".
const TOKENS: &[(u64, Address, &str, u8, B256)] = &[(
    84532,
    address!("036CbD53842c5426634e7929541eC2318f3dCF7e"),
    "USDC",
    6,
    b256!("71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818"),
)];

/// `AgentPolicy` instances that enforce per-token payee lists (issue #66).
/// An earlier instance decodes such a mandate and ignores the lists, so the
/// review refuses to show payees for any module that is not here. Empty
/// until a version with payee lists is deployed; the anvil harness runs
/// Base Sepolia's deployed code and follows this list too.
const PAYEE_POLICIES: &[Address] = &[];

/// The chains this build has facts for.
pub fn chains() -> Vec<u64> {
    let mut chains = vec![84532];
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
        for (_, token, symbol, decimals, domain) in TOKENS.iter().filter(|t| t.0 == chain_id) {
            f.names.insert(*token, symbol.to_string());
            f.tokens.insert(*token, Token { symbol: symbol.to_string(), decimals: *decimals, domain: *domain });
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
    ("safeNonceAssert", "SafeNonceAssert", false),
    ("demoCounter", "demo counter", false),
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
    CONTRACTS.iter().map(|c| c.1).chain(TOKENS.iter().map(|t| t.2)).any(|name| {
        let name = name.to_ascii_lowercase();
        name == label || name == base || name.rsplit_once(" v").is_some_and(|(n, _)| n == label || n == base)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys of the deployments file that are deliberately not facts: the
    /// chain id; an EOA; and the Kernel implementation and factory, which no
    /// owner operation addresses — a name would only make value sent there
    /// look like a parameter instead of a payment.
    const NOT_FACTS: &[&str] = &["chainId", "paymasterOwner", "kernel", "kernelFactory"];

    /// The table cannot lag the file silently: every key is either named or
    /// listed as not a fact, so a new kind of contract fails here until it
    /// is reviewed.
    #[test]
    fn every_key_of_the_embedded_file_is_accounted_for() {
        let map: BTreeMap<String, serde_json::Value> = serde_json::from_str(BASE_SEPOLIA).unwrap();
        assert_eq!(map["chainId"].as_u64(), Some(84532));
        for (key, value) in &map {
            if NOT_FACTS.contains(&key.as_str()) {
                continue;
            }
            assert!(contract_name(key).is_some(), "deployments key {key:?} is neither named in facts.rs nor listed in NOT_FACTS");
            assert!(value.as_str().and_then(|s| s.parse::<Address>().ok()).is_some(), "{key}: not an address");
        }
    }

    #[test]
    fn names_follow_the_table_and_only_listed_bases_have_versions() {
        assert_eq!(contract_name("agentPolicy"), Some(("AgentPolicy".to_string(), false)));
        assert_eq!(contract_name("agentPolicyV12"), Some(("AgentPolicy v12 (superseded)".to_string(), true)));
        assert_eq!(contract_name("p256RecoveryValidatorV1"), Some(("P256RecoveryValidator v1 (superseded)".to_string(), true)));
        // a suffix on a base that is not versioned, a version that is not a number, an unknown base
        assert_eq!(contract_name("entryPointV07"), None);
        assert_eq!(contract_name("demoCounterV2"), None);
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
        let policy = address!("dd544A6F0220778Fff16F51B468656e73E32ae85");
        let signer = address!("a19e6061b1C193573e5fe46c39363FfDd5CCA22E");
        assert_eq!(f.names[&policy], "AgentPolicy");
        assert_eq!((&f.policy_modules, &f.signer_modules), (&vec![policy], &vec![signer]), "the current policy and signer only, each in its slot");
        // superseded versions are named as such and are not readable modules
        let v6 = address!("8347dBC3d7A71DAFDeED5975ce85638494865F73");
        assert_eq!(f.names[&v6], "AgentPolicy v6 (superseded)");
        assert!(!f.policy_modules.contains(&v6));
        assert_eq!(f.names[&address!("68544284bfDbbd6bDB9F6A1D80D05C387015daA9")], "P256Signer v1 (superseded)");
        // both recovery validators can take over; only the current paymaster sponsors
        assert_eq!(f.recovery_validators.len(), 2);
        assert_eq!(f.sponsoring_paymasters, vec![address!("50Ab706dA586895D5775a1e51DcF1a66eAaAE001")]);
        assert_eq!(f.demo_counter, Some(address!("D2Adc331B867435b82Ceba1D4f7f715eeF9FdbC1")));
        // an EOA is not a named contract; the EntryPoint is a checked fact, not a name
        assert!(!f.names.contains_key(&address!("Df52800CfeBc64951816F958c4E12fD68E4dCC22")));
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
            assert_eq!(chains(), vec![84532, 31337]);
            assert!(anvil.demo_counter.is_some() && anvil.policy_modules.len() == 1 && anvil.signer_modules.len() == 1);
            assert!(anvil.sponsoring_paymasters.is_empty() && anvil.tokens.is_empty(), "the harness deploys those afresh");
            assert!(anvil.names.values().all(|n| !n.contains("superseded")));
        } else {
            assert_eq!(chains(), vec![84532]);
            assert!(anvil.names.is_empty(), "a release build knows no test chain");
        }
    }
}
