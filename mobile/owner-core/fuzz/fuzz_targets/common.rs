// What every review must satisfy, whatever bytes it was opened from.
#![allow(dead_code)]
use alloy_primitives::Address;
use owner_core::request::{commitment, SignRequest};
use owner_core::review::{open_request_with_build_facts, EnrolledAccount, Review, Verdict, CLOCK_TOLERANCE_SECS};

pub const NOW: u64 = 1_800_000_000;

/// A character the review may put on the owner's screen: printable ASCII and
/// the four marks the review itself writes (a dash, a middle dot, an arrow, a
/// double bar). Anything else (a line break, a control or a direction mark, a
/// letter of another script) came from the laptop and could make one row
/// read as another.
fn shown(c: char) -> bool {
    (' '..='~').contains(&c) || ['\u{2014}', '\u{b7}', '\u{2192}', '\u{2016}'].contains(&c)
}

fn all_shown(what: &str, text: &str) {
    assert!(text.chars().all(shown), "{what} carries a character that is not plain text: {text:?}");
}

/// Opens `bytes` for a phone enrolled with `enrolled` and holds the review to
/// its rules.
pub fn open_and_check(bytes: &[u8], enrolled: &[EnrolledAccount]) -> Review {
    let review = open_request_with_build_facts(bytes, &commitment(bytes), NOW, enrolled);
    assert_eq!(review.request_commitment, commitment(bytes));
    for section in &review.sections {
        all_shown("a section title", &section.title);
        for row in &section.rows {
            all_shown("a row label", &row.label);
            all_shown("a row value", &row.value);
        }
    }
    match &review.verdict {
        Verdict::Refuse(_) => assert!(review.digest_to_sign().is_err(), "a refusal with a digest to sign"),
        verdict => {
            if let Verdict::SignWithWarnings(warnings) = verdict {
                assert!(!warnings.is_empty(), "warnings without a warning");
                for w in warnings {
                    all_shown("a warning", w);
                }
            }
            // what can be signed is the hash this code computes from the operation, for an enrolled account
            let request = SignRequest::parse(bytes, NOW, CLOCK_TOLERANCE_SECS).expect("a review to sign of a request that does not parse");
            let digest = review.digest_to_sign().expect("a review to sign without a digest");
            assert_eq!(digest, request.user_op_hash().unwrap());
            assert_eq!(digest, request.laptop.user_op_hash);
            let chain_id = request.chain_id().unwrap();
            assert!(
                enrolled.iter().any(|e| e.account == request.user_op.sender && e.chain_id == chain_id && e.entry_point == request.entry_point),
                "a review to sign for an account this phone is not enrolled for"
            );
            assert_eq!((review.account, review.chain_id), (request.user_op.sender, chain_id));
            let op = request.user_op.to_packed().unwrap();
            assert!(op.init_code.is_empty(), "a review to sign of an operation with initCode");
            assert!(op.nonce >> 64 == alloy_primitives::U256::ZERO, "a review to sign under a nonce key that is not the root's");
            if !op.paymaster_and_data.is_empty() {
                // only a paymaster the build knows to charge nothing
                let paymaster = Address::from_slice(&op.paymaster_and_data[..20]);
                assert!(
                    owner_core::facts::for_chain(chain_id).sponsoring_paymasters.contains(&paymaster),
                    "a review to sign with a paymaster the build does not know"
                );
            }
        }
    }
    // the screen's text is the rows and nothing else
    assert_eq!(review.text().lines().count(), review.sections.iter().map(|s| 1 + s.rows.len()).sum::<usize>());
    review
}

/// The account a request names, if its JSON can be read that far: the fuzzer
/// could not otherwise guess an enrolled account.
pub fn named_in(bytes: &[u8]) -> Option<(u64, Address, Address)> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    Some((
        v.get("chainId")?.as_str()?.parse().ok()?,
        v.get("entryPoint")?.as_str()?.parse().ok()?,
        v.get("userOp")?.get("sender")?.as_str()?.parse().ok()?,
    ))
}
