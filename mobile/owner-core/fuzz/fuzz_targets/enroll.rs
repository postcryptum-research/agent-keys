// Both directions of an enrollment: the request the phone reads and the
// response the laptop reads.
#![no_main]
use libfuzzer_sys::fuzz_target;
use owner_core::enroll::{EnrollRequest, EnrollResponse};

const NOW: u64 = 1_800_000_000;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = EnrollRequest::parse(data, NOW, 60) {
        // what was accepted says the same thing when written out and read again
        let again = EnrollRequest::parse(&request.to_bytes(), NOW, 60).expect("an accepted request does not survive its own encoding");
        assert_eq!(again.to_bytes(), request.to_bytes());
        assert!(request.chain_id().is_ok());
        assert!(request.label.chars().all(|c| (' '..='~').contains(&c)), "a label that is not plain text: {:?}", request.label);
        assert!(request.laptop_pins.values().all(|l| l.chars().all(|c| (' '..='~').contains(&c))));
    }
    // a response is read against a request; the fuzzer's bytes play both
    for allow_no_attestation in [false, true] {
        let _ = EnrollResponse::verify(data, b"{}", allow_no_attestation);
        let _ = EnrollResponse::verify(data, data, allow_no_attestation);
    }
});
