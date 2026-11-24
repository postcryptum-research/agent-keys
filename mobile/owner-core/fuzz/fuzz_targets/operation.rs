// Every field of the operation inside a request whose hash is right, for an
// enrolled account: what the whole-request target cannot reach, since a
// change to the operation there breaks the hash and ends in the first
// refusal. Input: options (1 byte), account (20), nonce (32), gas limits
// (32), gas fees (32), then three length-prefixed fields (initCode,
// paymasterAndData, the laptop's command label), then the callData.
#![no_main]
mod common;

use std::collections::BTreeMap;

use alloy_primitives::{address, Address, Bytes, B256, U256};
use libfuzzer_sys::fuzz_target;
use owner_core::request::SignRequest;
use owner_core::review::EnrolledAccount;
use owner_core::user_op::PackedUserOp;

const ENTRY_POINT: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = data.split_at_checked(n)?;
    *data = rest;
    Some(head)
}

fn field<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = take(data, 1)?[0] as usize;
    take(data, n)
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let parts = (|| {
        Some((take(&mut data, 1)?[0], take(&mut data, 20)?, take(&mut data, 32)?, take(&mut data, 32)?, take(&mut data, 32)?, field(&mut data)?, field(&mut data)?, field(&mut data)?))
    })();
    let Some((options, account, nonce, gas_limits, gas_fees, init_code, paymaster, command)) = parts else { return };
    let account = Address::from_slice(account);
    let chain_id = if options & 1 == 0 { 84532 } else { 31337 };
    let op = PackedUserOp {
        sender: account,
        nonce: U256::from_be_slice(nonce),
        init_code: Bytes::copy_from_slice(init_code),
        call_data: Bytes::copy_from_slice(data),
        account_gas_limits: B256::from_slice(gas_limits),
        pre_verification_gas: U256::from(50_000),
        gas_fees: B256::from_slice(gas_fees),
        paymaster_and_data: Bytes::copy_from_slice(paymaster),
    };
    let command = (options & 16 != 0).then(|| String::from_utf8_lossy(command).into_owned());
    let mut labels = BTreeMap::new();
    if options & 32 != 0 {
        labels.insert(address!("000000000000000000000000000000000000bEEF"), String::from_utf8_lossy(command.as_deref().unwrap_or("x").as_bytes()).into_owned());
    }
    let request = SignRequest::new(&op, ENTRY_POINT, chain_id, common::NOW + 60, command, labels, None).to_bytes();
    let mut enrolled = EnrolledAccount::new(chain_id, ENTRY_POINT, account);
    enrolled.expert_mode = options & 2 != 0;
    if options & 4 != 0 {
        enrolled.validator = Some(address!("dA4cd5c37a5B888826A7A9e09dF6A9033A1550c2"));
    }
    if options & 8 != 0 {
        enrolled.gas_cap_wei = u128::MAX;
    }
    common::open_and_check(&request, &[enrolled]);
});
