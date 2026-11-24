// The operation's callData inside an otherwise valid request for an enrolled
// account, with the build's own facts: the fuzzer's bytes go straight to the
// decoders of what the owner is shown. Input: one byte of options, the
// account's 20 bytes (a root operation calls the account itself, so the
// seeds carry theirs), then the callData.
#![no_main]
mod common;

use std::collections::BTreeMap;

use alloy_primitives::{address, Address, Bytes, B256, U256};
use libfuzzer_sys::fuzz_target;
use owner_core::request::SignRequest;
use owner_core::review::EnrolledAccount;
use owner_core::user_op::PackedUserOp;

const ENTRY_POINT: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

fuzz_target!(|data: &[u8]| {
    let Some((&options, rest)) = data.split_first() else { return };
    let Some((account, call_data)) = rest.split_at_checked(20) else { return };
    let account = Address::from_slice(account);
    let chain_id = if options & 1 == 0 { 84532 } else { 31337 };
    let op = PackedUserOp {
        sender: account,
        nonce: U256::from(7),
        init_code: Bytes::new(),
        call_data: Bytes::copy_from_slice(call_data),
        account_gas_limits: B256::with_last_byte(1),
        pre_verification_gas: U256::from(50_000),
        gas_fees: B256::with_last_byte(1),
        paymaster_and_data: Bytes::new(),
    };
    let request = SignRequest::new(&op, ENTRY_POINT, chain_id, common::NOW + 60, None, BTreeMap::new(), None).to_bytes();
    let mut enrolled = EnrolledAccount::new(chain_id, ENTRY_POINT, account);
    enrolled.expert_mode = options & 2 != 0;
    if options & 4 != 0 {
        enrolled.validator = Some(address!("dA4cd5c37a5B888826A7A9e09dF6A9033A1550c2"));
    }
    if options & 8 != 0 {
        enrolled.pins.insert(address!("000000000000000000000000000000000000bEEF"), "a pinned name".into());
    }
    common::open_and_check(&request, &[enrolled]);
});
