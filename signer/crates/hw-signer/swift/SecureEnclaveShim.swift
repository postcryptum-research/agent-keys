// Secure Enclave P-256 keys through CryptoKit, exported to Rust as C functions.
//
// Why CryptoKit and not Security.framework: a Security.framework Secure
// Enclave key can only persist in the data-protection keychain, which needs
// keychain-access-group entitlements an ad-hoc signed command-line tool does
// not have. CryptoKit instead hands out `dataRepresentation`, an opaque blob
// that only this device's Secure Enclave can unwrap; the private key itself
// never leaves the enclave. The Rust side stores the blob in a file.
//
// Status codes (keep in sync with secure_enclave.rs):
//   0 ok, 1 no Secure Enclave, 2 the blob is not a usable key,
//   3 the operation failed, 4 output buffer too small.

import CryptoKit
import Foundation
import Security

private let ok: Int32 = 0
private let notAvailable: Int32 = 1
private let badKey: Int32 = 2
private let failed: Int32 = 3
private let smallBuffer: Int32 = 4

/// Write `text` as a NUL-terminated UTF-8 string into `msg`, truncated.
private func report(_ code: Int32, _ text: String, _ msg: UnsafeMutablePointer<UInt8>, _ msgCap: Int) -> Int32 {
    let bytes = Array(text.utf8.prefix(max(msgCap - 1, 0)))
    bytes.withUnsafeBufferPointer { src in
        if let base = src.baseAddress { msg.update(from: base, count: bytes.count) }
    }
    if msgCap > 0 { msg[bytes.count] = 0 }
    return code
}

private func load(_ blob: UnsafePointer<UInt8>, _ blobLen: Int) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(bytes: blob, count: blobLen))
}

private func writePublic(_ key: SecureEnclave.P256.Signing.PrivateKey, _ out: UnsafeMutablePointer<UInt8>) {
    // rawRepresentation of a P-256 public key is x ‖ y, 64 bytes.
    key.publicKey.rawRepresentation.copyBytes(to: out, count: 64)
}

/// Generate a key inside the Secure Enclave. Usable only on this device and
/// while it is unlocked; no biometric prompt.
@_cdecl("tpmse_create")
public func tpmse_create(
    _ blob: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
    _ pub: UnsafeMutablePointer<UInt8>,
    _ msg: UnsafeMutablePointer<UInt8>, _ msgCap: Int
) -> Int32 {
    guard SecureEnclave.isAvailable else { return report(notAvailable, "no Secure Enclave on this Mac", msg, msgCap) }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error
    ) else {
        return report(failed, "access control: \(String(describing: error?.takeRetainedValue()))", msg, msgCap)
    }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let data = key.dataRepresentation
        guard data.count <= blobCap else { return report(smallBuffer, "key blob is \(data.count) bytes", msg, msgCap) }
        data.copyBytes(to: blob, count: data.count)
        blobLen.pointee = data.count
        writePublic(key, pub)
        return ok
    } catch {
        return report(failed, "create: \(error)", msg, msgCap)
    }
}

/// The public key (x ‖ y) of the key in `blob`.
@_cdecl("tpmse_public")
public func tpmse_public(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int,
    _ pub: UnsafeMutablePointer<UInt8>,
    _ msg: UnsafeMutablePointer<UInt8>, _ msgCap: Int
) -> Int32 {
    guard SecureEnclave.isAvailable else { return report(notAvailable, "no Secure Enclave on this Mac", msg, msgCap) }
    do {
        writePublic(try load(blob, blobLen), pub)
        return ok
    } catch {
        return report(badKey, "open: \(error)", msg, msgCap)
    }
}

/// Sign a 32-byte digest as is (no further hashing); writes r ‖ s.
@_cdecl("tpmse_sign")
public func tpmse_sign(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int,
    _ digest: UnsafePointer<UInt8>,
    _ rs: UnsafeMutablePointer<UInt8>,
    _ msg: UnsafeMutablePointer<UInt8>, _ msgCap: Int
) -> Int32 {
    guard SecureEnclave.isAvailable else { return report(notAvailable, "no Secure Enclave on this Mac", msg, msgCap) }
    let key: SecureEnclave.P256.Signing.PrivateKey
    do { key = try load(blob, blobLen) } catch { return report(badKey, "open: \(error)", msg, msgCap) }

    // CryptoKit signs a `Digest`, and has no public constructor for one from
    // bytes we already hashed (the userOpHash). SHA256Digest is a plain
    // 32-byte value: start from a real one and overwrite its bytes.
    guard MemoryLayout<SHA256Digest>.size == 32 else {
        return report(failed, "unexpected SHA256Digest layout (\(MemoryLayout<SHA256Digest>.size) bytes)", msg, msgCap)
    }
    var d = SHA256.hash(data: Data())
    withUnsafeMutableBytes(of: &d) { dst in
        dst.copyMemory(from: UnsafeRawBufferPointer(start: digest, count: 32))
    }
    guard Array(d) == Array(UnsafeBufferPointer(start: digest, count: 32)) else {
        return report(failed, "digest bytes did not round-trip", msg, msgCap)
    }
    do {
        let signature = try key.signature(for: d)
        signature.rawRepresentation.copyBytes(to: rs, count: 64)
        return ok
    } catch {
        return report(failed, "sign: \(error)", msg, msgCap)
    }
}
