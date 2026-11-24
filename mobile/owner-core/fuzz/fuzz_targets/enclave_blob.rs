// The guard in front of CryptoKit (issue #78): any bytes as a key file.
#![no_main]
use libfuzzer_sys::fuzz_target;
use hw_signer::enclave_blob::check;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = check(data) {
        // an accepted file is one element from the first byte to the last, and its key is on the curve
        assert!(hw_signer::valid_public_key(&key));
        assert_eq!(data[0], 0x04, "accepted, but not an OCTET STRING");
        // the same bytes with anything appended are refused
        let mut longer = data.to_vec();
        longer.push(0);
        assert!(check(&longer).is_err(), "accepted with a byte after the end");
    }
});
