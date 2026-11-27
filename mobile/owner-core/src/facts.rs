//! What the build knows (docs/MOBILE_OWNER_DESIGN.md §6.7): the project's
//! canonical deployments and a small reviewed token table, embedded when the
//! crate is built. A laptop compromised at enrollment or later cannot name a
//! contract or a token on the phone; the price is that a new deployment or a
//! new chain needs a new build.

use std::collections::BTreeMap;

use alloy_primitives::{address, b256, Address, B256};

use crate::review::{Facts, Native, Token, Venue, VenueKind};

/// `contracts/deployments/84532.json`, the canonical file. Variants such as
/// `84532.enclave.json` (a developer's test paymaster) are never embedded.
/// `build.rs` refuses to build when this file does not parse.
const BASE_SEPOLIA: &str = include_str!("../../../contracts/deployments/84532.json");

/// `contracts/deployments/11155111.json`: Sepolia, where CoW Protocol runs
/// and the first orders of issue #80 are placed.
const SEPOLIA: &str = include_str!("../../../contracts/deployments/11155111.json");

/// `contracts/deployments/5042002.json`: Arc testnet, whose gas token is
/// USDC. The same commit as on the other two chains, at the same addresses.
const ARC_TESTNET: &str = include_str!("../../../contracts/deployments/5042002.json");

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
    // Arc testnet, read on 2026-11-27: the ERC-20 face of the chain's gas
    // token, with name "USDC" and version "2" like the others
    (
        5042002,
        address!("3600000000000000000000000000000000000000"),
        "USDC",
        6,
        b256!("361191522483d32a83e70ae7183b4b9629442c13a78bc9921d6f707911c8c6b0"),
    ),
    // Circle's two other tokens there, read the same day: EURC (name "EURC")
    // and cirBTC (name "Circle Wrapped Bitcoin"), each with version "2"
    (
        5042002,
        address!("89B50855Aa3bE2F677cD6303Cec089B5F319D72a"),
        "EURC",
        6,
        b256!("649ec6b0634bd74f28684781d2c9ae49dff14ba3d5f9bb5d70c1e1f0e1ebf160"),
    ),
    (
        5042002,
        address!("f0C4a4CE82A5746AbAAd9425360Ab04fbBA432BF"),
        "cirBTC",
        8,
        b256!("5b21e39ccfd3b6622b70bb0d9fcf3d9db5b5199a6c7491708831130adcc95250"),
    ),
];

/// A chain whose gas token is not ether: `(chain, the symbol of its native
/// balance, the ERC-20 that moves the same balance)`. On Arc testnet the gas
/// token is USDC: 18 decimals as a native balance (value sent, gas) and 6 as
/// the token at `0x3600000000000000000000000000000000000000`, one balance
/// behind both (read on 2026-11-27: a native transfer and the token's
/// `balanceOf` moved together).
const NATIVE: &[(u64, &str, Address)] = &[(5042002, "USDC", address!("3600000000000000000000000000000000000000"))];

/// The most an owner's operation may cost in gas where an enrollment sets
/// no cap of its own: 0.005 of the gas token, and 3 on Arc testnet, where
/// the token is USDC. On 2026-11-27 the fee there moved between 30 and 566
/// gwei within hours, and a mandate's install came to a maximum of 0.83
/// USDC at the higher one (against a few wei of fee on Sepolia).
pub fn default_gas_cap_wei(chain_id: u64) -> u128 {
    match chain_id {
        5042002 => 3_000_000_000_000_000_000,
        _ => crate::review::DEFAULT_GAS_CAP_WEI,
    }
}

/// The current `AgentPolicy`, the same address on both chains: built from
/// commit `b11adb7cf2dcb2660b4c93c81c62f8945e246706`, with every feature of
/// the source (payee lists, x402, a budget per period, venues, limits per
/// ERC-6909 id), and the first with a call a venue's decoder judged (a swap
/// at a router, a call held to a rule for each argument): the kinds of venue
/// that judge calls are known to this build only together with it.
const CURRENT_POLICY: Address = address!("dA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6");

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

/// The venues this build knows, each by its decoder's address and code. CoW Swap:
/// the decoder built from `contracts/src/venues/CowSwapDecoder.sol` at
/// commit `60e773be7c7f071a4e5a69f84e7af3697092a4ef`, at the same address
/// on both chains. Its code differs by chain: the constructor stores the
/// settlement's EIP-712 domain separator, which names the chain. Each hash
/// is that build's runtime code with the settlement, the domain separator
/// and the vault relayer filled in as `domainSeparator()` and
/// `vaultRelayer()` of CoW's settlement return them on that chain (read on
/// 2026-11-25).
///
/// Each entry: the chain, the kind, the decoder, the venue's name, the
/// decoder's code hash, the venue's own contract, the spender and its name,
/// and the deployments key that names the decoder. A decoder of rules
/// (`CallRulesDecoder`) is one per contract, so each has a key of its own
/// (`callRules…`); the other kinds have one decoder a chain.
#[allow(clippy::type_complexity)]
const VENUES: &[(u64, VenueKind, Address, &str, B256, Address, Address, &str, &str)] = &[
    (
        84532,
        VenueKind::CowSwap,
        address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a"),
        "CoW Swap",
        b256!("8ed2aee08c4faa05aba4104106931086449b62026b1e4e4bcfeac7d19727d6c1"),
        address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
        address!("C92E8bdf79f0507f65a392b0ab4667716BFE0110"),
        "CoW Swap vault relayer",
        "cowSwapDecoder",
    ),
    (
        11155111,
        VenueKind::CowSwap,
        address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a"),
        "CoW Swap",
        b256!("e11511d23d679dd68a71be1cfd2d6714ba3fb10e077c4db6c4bf3fe96d21e47e"),
        address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"),
        address!("C92E8bdf79f0507f65a392b0ab4667716BFE0110"),
        "CoW Swap vault relayer",
        "cowSwapDecoder",
    ),
    // The four venues deployed on 2026-11-27 from commit
    // `b11adb7cf2dcb2660b4c93c81c62f8945e246706`, on each chain: 1inch's
    // limit orders, a swap at Uniswap's SwapRouter02, and calls held to
    // rules at Aave V3's pool and at CCTP's messenger. Each hash is the
    // decoder's code as read from the chain that day, and each venue and
    // spender is what the decoder itself answers there (`venue()`,
    // `spender()`).
    (
        84532,
        VenueKind::OneInchLimitOrder,
        address!("AD754dA240f27dCe0cF79F6d323e56d5C29D08E6"),
        "1inch",
        b256!("c92a126f6f7e1a4d7e23cb8ac0095583217cf70dee15ba725d437c9e1fb9f5e6"),
        address!("111111125421cA6dc452d289314280a0f8842A65"),
        address!("111111125421cA6dc452d289314280a0f8842A65"),
        "1inch router",
        "oneInchLimitOrderDecoder",
    ),
    (
        84532,
        VenueKind::SwapRouter02,
        address!("B29a80662d989c1C0E73dB824cD82d5890e795bC"),
        "Uniswap",
        b256!("ab35fcf0ec7fadd6334fee76ca12de98089a679071f24088508a5f74da2e02bd"),
        address!("94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"),
        address!("94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"),
        "Uniswap router",
        "swapRouter02Decoder",
    ),
    (
        84532,
        VenueKind::CallRules,
        address!("14b82e2cBF35926B6221d008e5A89DB1BD5D4887"),
        "Aave V3 pool",
        b256!("9573c5a426dc99b7897b4ea34e3657bf513e1efd8af85cde845c3bbd4325bf26"),
        address!("8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27"),
        address!("8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27"),
        "Aave V3 pool",
        "callRulesAaveV3Pool",
    ),
    (
        84532,
        VenueKind::CallRules,
        address!("C5135aC6A911B692173F2626dD57ff1D80d16F62"),
        "CCTP messenger",
        b256!("225c3d4bd0bd706e394b6341124c19430e7e5ee807bd249e1687664a89aef79b"),
        address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA"),
        address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA"),
        "CCTP messenger",
        "callRulesCctpMessenger",
    ),
    (
        11155111,
        VenueKind::OneInchLimitOrder,
        address!("AD754dA240f27dCe0cF79F6d323e56d5C29D08E6"),
        "1inch",
        b256!("8e3d50b49bd323ca9bb0cf19d4e520cae768b92cb895f07c8ca288321a3bbab5"),
        address!("111111125421cA6dc452d289314280a0f8842A65"),
        address!("111111125421cA6dc452d289314280a0f8842A65"),
        "1inch router",
        "oneInchLimitOrderDecoder",
    ),
    (
        11155111,
        VenueKind::SwapRouter02,
        address!("6D7e83461cd295AEf006F9A76009b662d6b06b6b"),
        "Uniswap",
        b256!("2794dd3a9eb98177a134d50783f43a3ac9bbb643d7ab95310f7b1d532721613f"),
        address!("3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"),
        address!("3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"),
        "Uniswap router",
        "swapRouter02Decoder",
    ),
    (
        11155111,
        VenueKind::CallRules,
        address!("112b620C87A7C4b9f53566dD422f20704140dbfe"),
        "Aave V3 pool",
        b256!("e4c94fa9fc749bc6946011db8711411432c433980b0116f9d170358337da8363"),
        address!("6Ae43d3271ff6888e7Fc43Fd7321a503ff738951"),
        address!("6Ae43d3271ff6888e7Fc43Fd7321a503ff738951"),
        "Aave V3 pool",
        "callRulesAaveV3Pool",
    ),
    (
        11155111,
        VenueKind::CallRules,
        address!("C5135aC6A911B692173F2626dD57ff1D80d16F62"),
        "CCTP messenger",
        b256!("225c3d4bd0bd706e394b6341124c19430e7e5ee807bd249e1687664a89aef79b"),
        address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA"),
        address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA"),
        "CCTP messenger",
        "callRulesCctpMessenger",
    ),
    // Sepolia, two more decoders of rules from the same commit (dry run of
    // 2026-11-27; the code hash is the build's with the venue filled in)
    (
        11155111,
        VenueKind::CallRules,
        address!("467b0caE921ceEaf64D832eFD242A2260e057E60"),
        "Compound v3 USDC market",
        b256!("69d1e9bf07069eb098604962272a415811ae4c4f2a6cd7e8af7f7dfada4f159d"),
        address!("Aec1F48e02Cfb822Be958B68C7957156EB3F0b6e"),
        address!("Aec1F48e02Cfb822Be958B68C7957156EB3F0b6e"),
        "Compound v3 USDC market",
        "callRulesCompoundV3Usdc",
    ),
    (
        11155111,
        VenueKind::CallRules,
        address!("1CC3c09765f4867e440Dd9b7F61c227E2338e254"),
        "Uniswap v3 position manager",
        b256!("c30fbabcfe8545837a22df63b331eec5435e8a00cb92d1044e759b1a1c751ed2"),
        address!("1238536071E1c677A632429e3655c799b22cDA52"),
        address!("1238536071E1c677A632429e3655c799b22cDA52"),
        "Uniswap v3 position manager",
        "callRulesUniswapV3Positions",
    ),
    // Arc testnet: the messenger and its decoder are at the same addresses,
    // with the same code, as on the other two chains
    (
        5042002,
        VenueKind::CallRules,
        address!("C5135aC6A911B692173F2626dD57ff1D80d16F62"),
        "CCTP messenger",
        b256!("225c3d4bd0bd706e394b6341124c19430e7e5ee807bd249e1687664a89aef79b"),
        address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA"),
        address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA"),
        "CCTP messenger",
        "callRulesCctpMessenger",
    ),
];

/// The name of a venue's own contract.
fn place_name(kind: VenueKind, venue: &str) -> String {
    match kind {
        VenueKind::CowSwap => format!("{venue} settlement"),
        VenueKind::OneInchLimitOrder | VenueKind::SwapRouter02 => format!("{venue} router"),
        // a venue of rules is named after the one contract it is
        VenueKind::CallRules => venue.to_string(),
    }
}

/// The chains this build has facts for.
pub fn chains() -> Vec<u64> {
    let mut chains = vec![84532, 11155111, 5042002];
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
        5042002 => from_deployments(ARC_TESTNET, chain_id, true),
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
        for (_, kind, decoder, name, code_hash, place, spender, spender_name, key) in VENUES.iter().filter(|v| v.0 == chain_id) {
            if map.get(*key).and_then(|v| v.as_str()).and_then(|s| s.parse::<Address>().ok()) != Some(*decoder) {
                continue;
            }
            // the venue's own contract, then who takes the tokens: one address at 1inch, whose router is both
            f.names.insert(*place, place_name(*kind, name));
            f.names.insert(*spender, spender_name.to_string());
            f.venues.insert(
                *decoder,
                Venue { name: name.to_string(), kind: *kind, code_hash: *code_hash, place: *place, spender: *spender },
            );
        }
        for (_, token, symbol, decimals, domain) in TOKENS.iter().filter(|t| t.0 == chain_id) {
            f.names.insert(*token, symbol.to_string());
            f.tokens.insert(*token, Token { symbol: symbol.to_string(), decimals: *decimals, domain: *domain });
            if WRAPPED_NATIVE.contains(&(chain_id, *token)) {
                f.wrapped_native.push(*token);
            }
        }
        f.native =
            NATIVE.iter().find(|n| n.0 == chain_id).map(|(_, symbol, token)| Native { symbol: symbol.to_string(), token: *token });
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
    ("oneInchLimitOrderDecoder", "1inch limit order decoder", true),
    ("swapRouter02Decoder", "Uniswap swap decoder", true),
    // deployed, and not a venue this build reads: a mandate that names it is refused
    ("seaportBidDecoder", "Seaport bid decoder", true),
    // a decoder of rules is one per contract, each under a key of its own
    ("callRulesAaveV3Pool", "Aave V3 pool rules decoder", false),
    ("callRulesCctpMessenger", "CCTP messenger rules decoder", false),
    ("callRulesCompoundV3Usdc", "Compound v3 USDC market rules decoder", false),
    ("callRulesUniswapV3Positions", "Uniswap v3 position manager rules decoder", false),
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
    let venue_names = VENUES.iter().flat_map(|v| [place_name(v.1, v.3), v.7.to_string()]);
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
        for (file, chain) in [(BASE_SEPOLIA, 84532), (SEPOLIA, 11155111), (ARC_TESTNET, 5042002)] {
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
        let policy = address!("dA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6");
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
        // the instance of 2026-11-26, replaced by the one that also judges calls
        let fifth = address!("530DD3C000b3939294072409834c4c4dd160BCd9");
        assert_eq!(f.names[&fifth], "AgentPolicy v5 (superseded)");
        for list in [&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules, &f.id_policy_modules] {
            assert!(!list.contains(&fifth));
        }
        assert_eq!(f.signer_modules, vec![address!("d88d25Ca3e042A28893781935756ee90Bc2d2769")]);
        assert_eq!(f.entry_point, Some(address!("0000000071727De22E5E9d8BAf0edAc6f37da032")));

        let decoder = address!("42F62bF7134F5eF6d46d4BC07d806E77D1Df641a");
        let (settlement, relayer) = (address!("9008D19f58AAbD9eD0D60971565AA8510560ab41"), address!("C92E8bdf79f0507f65a392b0ab4667716BFE0110"));
        // CoW Swap, 1inch, Uniswap, and rules for Aave V3's pool, CCTP's messenger, Compound's market and Uniswap's positions
        assert_eq!(f.venues.len(), 7);
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

    /// Arc testnet (chain 5042002), deployed on 2026-11-27 from the commit of
    /// the other two chains: the same contracts at the same addresses, the
    /// messenger's rules decoder as the one venue, USDC as a token with its
    /// signing domain, and USDC as the gas token, with a gas cap of its own.
    #[test]
    fn arc_testnet_is_known_with_usdc_as_its_gas_token() {
        assert!(chains().contains(&5042002));
        let f = for_chain(5042002);
        let p = vec![CURRENT_POLICY];
        assert_eq!(f.names[&CURRENT_POLICY], "AgentPolicy");
        assert_eq!(
            (
                &f.policy_modules,
                &f.payee_policy_modules,
                &f.trading_policy_modules,
                &f.id_policy_modules
            ),
            (&p, &p, &p, &p)
        );
        assert_eq!(
            f.signer_modules,
            vec![address!("d88d25Ca3e042A28893781935756ee90Bc2d2769")]
        );
        assert_eq!(
            f.sponsoring_paymasters,
            vec![address!("657792557C1D40f2Da031FD7aB277078D2c0a4cb")]
        );
        assert_eq!(
            f.recovery_validators,
            vec![address!("b7a06e6c7B5cC9852578EF89f38d161C31218047")]
        );
        assert_eq!(
            f.entry_point,
            Some(address!("0000000071727De22E5E9d8BAf0edAc6f37da032"))
        );
        // one venue: the rules decoder for CCTP's messenger, the code that is on the other chains
        let messenger = address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA");
        let decoder = address!("C5135aC6A911B692173F2626dD57ff1D80d16F62");
        assert_eq!(f.venues.len(), 1);
        let v = &f.venues[&decoder];
        assert_eq!(
            (v.name.as_str(), v.kind, v.place, v.spender),
            ("CCTP messenger", VenueKind::CallRules, messenger, messenger)
        );
        assert_eq!(v.code_hash, for_chain(11155111).venues[&decoder].code_hash);
        assert_eq!(f.names[&decoder], "CCTP messenger rules decoder");
        // USDC: the token, with the domain its name and version give on this chain
        let usdc_at = address!("3600000000000000000000000000000000000000");
        let usdc = &f.tokens[&usdc_at];
        assert_eq!((usdc.symbol.as_str(), usdc.decimals), ("USDC", 6));
        use alloy_primitives::{keccak256, U256};
        use alloy_sol_types::SolValue;
        let domain = keccak256(
            (
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("USDC"),
                keccak256("2"),
                U256::from(5042002),
                usdc_at,
            )
                .abi_encode(),
        );
        assert_eq!(usdc.domain, domain);
        // Circle's two other tokens there, each with the domain its name and version give
        for (at, symbol, decimals, name) in [
            (address!("89B50855Aa3bE2F677cD6303Cec089B5F319D72a"), "EURC", 6, "EURC"),
            (address!("f0C4a4CE82A5746AbAAd9425360Ab04fbBA432BF"), "cirBTC", 8, "Circle Wrapped Bitcoin"),
        ] {
            let t = &f.tokens[&at];
            assert_eq!((t.symbol.as_str(), t.decimals), (symbol, decimals));
            let domain = keccak256(
                (
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(name),
                    keccak256("2"),
                    U256::from(5042002),
                    at,
                )
                    .abi_encode(),
            );
            assert_eq!(t.domain, domain, "{symbol}");
            assert!(is_build_name(symbol));
        }
        // and the gas token: named on the screen, the same balance as the token
        assert_eq!(f.native_symbol(), "USDC");
        assert_eq!(f.native.as_ref().map(|n| n.token), Some(usdc_at));
        assert!(f.wrapped_native.is_empty());
        // a mandate's install came to 0.83 USDC there at a high fee: the default cap is 3, and 0.005 of ether elsewhere
        assert_eq!(default_gas_cap_wei(5042002), 3_000_000_000_000_000_000);
        for chain in [84532, 11155111, 31337, 1] {
            assert_eq!(
                default_gas_cap_wei(chain),
                crate::review::DEFAULT_GAS_CAP_WEI,
                "{chain}"
            );
            assert_eq!(for_chain(chain).native_symbol(), "ETH", "{chain}");
        }
        assert_eq!(
            crate::review::EnrolledAccount::new(5042002, Address::ZERO, Address::ZERO).gas_cap_wei,
            3_000_000_000_000_000_000
        );
    }

    /// Sepolia's two decoders of rules of 2026-11-27 for a live run of two
    /// recipes: Compound v3's USDC market and Uniswap v3's position manager.
    #[test]
    fn sepolia_knows_the_rules_decoders_of_the_recipes() {
        let f = for_chain(11155111);
        for (decoder, name, place) in [
            (
                address!("467b0caE921ceEaf64D832eFD242A2260e057E60"),
                "Compound v3 USDC market",
                address!("Aec1F48e02Cfb822Be958B68C7957156EB3F0b6e"),
            ),
            (
                address!("1CC3c09765f4867e440Dd9b7F61c227E2338e254"),
                "Uniswap v3 position manager",
                address!("1238536071E1c677A632429e3655c799b22cDA52"),
            ),
        ] {
            let v = &f.venues[&decoder];
            assert_eq!(
                (v.name.as_str(), v.kind, v.place, v.spender),
                (name, VenueKind::CallRules, place, place)
            );
            assert_eq!(f.names[&decoder], format!("{name} rules decoder"));
            assert_eq!(f.names[&place], name);
            assert!(is_build_name(name), "{name}");
            // not on the other chains
            assert!(!for_chain(84532).venues.contains_key(&decoder));
            assert!(!for_chain(5042002).venues.contains_key(&decoder));
        }
    }

    /// The redeploys of 2026-11-25 and 2026-11-27 (the policy from
    /// `b11adb7cf2dcb2660b4c93c81c62f8945e246706`): on both
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

        // the venues of 2026-11-27: each known by its decoder, with its kind, its contract and its spender
        let router = address!("111111125421cA6dc452d289314280a0f8842A65");
        let messenger = address!("8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA");
        for (chain, swap_decoder, swap_router, pool_decoder, pool) in [
            (
                84532,
                address!("B29a80662d989c1C0E73dB824cD82d5890e795bC"),
                address!("94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"),
                address!("14b82e2cBF35926B6221d008e5A89DB1BD5D4887"),
                address!("8bAB6d1b75f19e9eD9fCe8b9BD338844fF79aE27"),
            ),
            (
                11155111,
                address!("6D7e83461cd295AEf006F9A76009b662d6b06b6b"),
                address!("3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"),
                address!("112b620C87A7C4b9f53566dD422f20704140dbfe"),
                address!("6Ae43d3271ff6888e7Fc43Fd7321a503ff738951"),
            ),
        ] {
            let f = for_chain(chain);
            let known = |decoder: Address| {
                let v = &f.venues[&decoder];
                (v.name.clone(), v.kind, v.place, v.spender)
            };
            let limit = address!("AD754dA240f27dCe0cF79F6d323e56d5C29D08E6");
            assert_eq!(known(limit), ("1inch".to_string(), VenueKind::OneInchLimitOrder, router, router), "{chain}");
            assert_eq!(known(swap_decoder), ("Uniswap".to_string(), VenueKind::SwapRouter02, swap_router, swap_router), "{chain}");
            assert_eq!(known(pool_decoder), ("Aave V3 pool".to_string(), VenueKind::CallRules, pool, pool), "{chain}");
            let cctp = address!("C5135aC6A911B692173F2626dD57ff1D80d16F62");
            assert_eq!(known(cctp), ("CCTP messenger".to_string(), VenueKind::CallRules, messenger, messenger), "{chain}");
            for (addr, name) in [
                (limit, "1inch limit order decoder"),
                (swap_decoder, "Uniswap swap decoder"),
                (pool_decoder, "Aave V3 pool rules decoder"),
                (cctp, "CCTP messenger rules decoder"),
                (router, "1inch router"),
                (swap_router, "Uniswap router"),
                (pool, "Aave V3 pool"),
                (messenger, "CCTP messenger"),
            ] {
                assert_eq!(f.names[&addr], name, "{chain} {addr}");
            }
            // Seaport's bid decoder is deployed and named, and is no venue of this build
            let seaport = address!("713165a6157a4B2952A775A9D1C9948D9a703128");
            assert_eq!(f.names[&seaport], "Seaport bid decoder", "{chain}");
            assert!(!f.venues.contains_key(&seaport), "{chain}");
            // Sepolia has two decoders of rules more, for the recipes run there
            assert_eq!(f.venues.len(), if chain == 11155111 { 7 } else { 5 }, "{chain}");
        }
        // one decoder's code is the same on both chains only where nothing in it names the chain
        let code = |chain: u64, decoder: Address| for_chain(chain).venues[&decoder].code_hash;
        let (limit, cctp) = (address!("AD754dA240f27dCe0cF79F6d323e56d5C29D08E6"), address!("C5135aC6A911B692173F2626dD57ff1D80d16F62"));
        assert_ne!(code(84532, limit), code(11155111, limit), "1inch's domain separator names the chain");
        assert_eq!(code(84532, cctp), code(11155111, cctp), "the messenger is at one address on both");

        // what the redeploy replaced keeps its address under the next versioned name
        let superseded = [
            (84532, address!("12b7E79974CC4F4181a40Aa11f9d3170018ae0E2"), "AgentPolicy v9 (superseded)"),
            (84532, address!("530DD3C000b3939294072409834c4c4dd160BCd9"), "AgentPolicy v12 (superseded)"),
            (11155111, address!("530DD3C000b3939294072409834c4c4dd160BCd9"), "AgentPolicy v5 (superseded)"),
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
            ("oneInchLimitOrderDecoderV1", "1inch limit order decoder v1 (superseded)"),
            ("swapRouter02DecoderV1", "Uniswap swap decoder v1 (superseded)"),
            ("seaportBidDecoderV1", "Seaport bid decoder v1 (superseded)"),
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
        // a decoder of rules has a key of its own and no versions under it; another contract's rules are not named
        assert_eq!(contract_name("callRulesAaveV3Pool"), Some(("Aave V3 pool rules decoder".to_string(), false)));
        assert_eq!(contract_name("callRulesAaveV3PoolV1"), None);
        assert_eq!(contract_name("callRulesSomethingElse"), None);
        // the names a laptop's pin may not carry
        for reserved in ["AgentPolicy", "agentpolicy", " P256Validator ", "P256Validator v1", "AgentPolicy v6 (superseded)", "demo counter", "USDC", "EntryPoint", "EntryPoint v0.7", "1inch router", "Uniswap router", "Aave V3 pool", "CCTP messenger", "Seaport bid decoder"] {
            assert!(is_build_name(reserved), "{reserved:?}");
        }
        for free in ["policy module (config)", "my vault", "AgentPolicy2", "paymaster (config)", "counter"] {
            assert!(!is_build_name(free), "{free:?}");
        }
    }

    #[test]
    fn base_sepolia() {
        let f = for_chain(84532);
        let policy = address!("dA16ba0d5C8aC6D5599A444c1e1e3bCD6c97c0C6");
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
        // the instance of e48b93e, replaced by the one that also judges calls: named, and read by nothing
        let v12 = address!("530DD3C000b3939294072409834c4c4dd160BCd9");
        assert_eq!(f.names[&v12], "AgentPolicy v12 (superseded)");
        for list in [&f.policy_modules, &f.payee_policy_modules, &f.trading_policy_modules, &f.id_policy_modules] {
            assert!(!list.contains(&v12));
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
            assert_eq!(chains(), vec![84532, 11155111, 5042002, 31337]);
            assert!(anvil.demo_counter.is_some() && anvil.policy_modules.len() == 1 && anvil.signer_modules.len() == 1);
            assert!(anvil.sponsoring_paymasters.is_empty() && anvil.tokens.is_empty(), "the harness deploys those afresh");
            assert!(anvil.names.values().all(|n| !n.contains("superseded")));
        } else {
            assert_eq!(chains(), vec![84532, 11155111, 5042002]);
            assert!(anvil.names.is_empty(), "a release build knows no test chain");
        }
    }
}
