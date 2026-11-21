// The whole request, as the laptop serves it: any bytes.
#![no_main]
mod common;

use libfuzzer_sys::fuzz_target;
use owner_core::review::{EnrolledAccount, Verdict};

fuzz_target!(|data: &[u8]| {
    // a phone enrolled for nothing signs nothing
    let review = common::open_and_check(data, &[]);
    assert!(matches!(review.verdict, Verdict::Refuse(_)), "a phone with no account agreed to sign");
    // and one enrolled for the account the request names, with and without expert mode
    if let Some((chain_id, entry_point, account)) = common::named_in(data) {
        let mut enrolled = EnrolledAccount::new(chain_id, entry_point, account);
        common::open_and_check(data, std::slice::from_ref(&enrolled));
        enrolled.expert_mode = true;
        enrolled.validator = Some(account);
        common::open_and_check(data, std::slice::from_ref(&enrolled));
    }
});
