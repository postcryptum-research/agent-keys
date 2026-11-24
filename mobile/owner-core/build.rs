//! Refuses to build when the deployments file `src/facts.rs` embeds does not
//! parse (docs/MOBILE_OWNER_DESIGN.md §6.7): an app built without its facts
//! would name nothing and refuse almost everything.
fn main() {
    check("../../contracts/deployments/84532.json", 84532);
    check("../../contracts/deployments/11155111.json", 11155111);
}

fn check(path: &str, chain_id: u64) {
    println!("cargo:rerun-if-changed={path}");
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    let map = v.as_object().unwrap_or_else(|| panic!("{path}: not an object"));
    assert_eq!(map.get("chainId").and_then(|c| c.as_u64()), Some(chain_id), "{path}: chainId");
    for (key, value) in map.iter().filter(|(k, _)| k.as_str() != "chainId") {
        let a = value.as_str().unwrap_or_else(|| panic!("{path}: {key} is not a string"));
        let hex = a.strip_prefix("0x").unwrap_or_else(|| panic!("{path}: {key} is not 0x-prefixed"));
        assert!(hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()), "{path}: {key} is not an address");
    }
}
