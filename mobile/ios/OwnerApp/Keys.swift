// One key per enrolled account (docs/MOBILE_OWNER_DESIGN.md §5.1, §5.3). Development without an
// Apple organisation has no keychain entitlement to rely on, so the key is what the CLI's Mac
// backend already uses (docs/MOBILE_DEV_MODE.md §3.4; signer/crates/hw-signer/swift/SecureEnclaveShim.swift):
// a CryptoKit Secure Enclave key whose `dataRepresentation` — a handle only this phone's enclave
// can use, never the key — is kept in the app's files (Store.swift).
//
// The simulator has no Secure Enclave. There the key is a software key in the same file, its
// tier is "simulator", and the laptop takes it only with --allow-no-attestation.

import CryptoKit
import Foundation
import LocalAuthentication

enum OwnerKey {
    #if targetEnvironment(simulator)
    static let tier = "simulator"
    static let notice = "SIMULATOR — this key is software in the app's files, with no hardware and no biometric check behind it. For development only: agent-signer accepts it only with --allow-no-attestation."
    static let enrollLabel = "I understand, enroll"
    #else
    static let tier = "secure-enclave"
    static let notice = "This iPhone keeps the owner key in its Secure Enclave: it cannot be copied, and it signs only after Face ID or Touch ID."
    static let enrollLabel = "Enroll"
    #endif

    /// A new key: the handle to store, and the public key `x ‖ y`.
    static func create() throws -> (handle: Data, publicKey: Data) {
        #if targetEnvironment(simulator)
        let key = P256.Signing.PrivateKey()
        return (key.rawRepresentation, key.publicKey.rawRepresentation)
        #else
        guard SecureEnclave.isAvailable else { throw Failure("this device has no Secure Enclave") }
        var error: Unmanaged<CFError>?
        // a biometric check on every use, biometric only (D2); a new face or finger invalidates the key
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error) else {
            throw Failure("access control: \(String(describing: error?.takeRetainedValue()))")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        return (key.dataRepresentation, key.publicKey.rawRepresentation)
        #endif
    }

    /// A DER signature over the 32-byte `digest` as it is. On a phone this waits for the biometric
    /// check, so it is called off the main thread.
    static func sign(handle: Data, digest: Data, reason: String) throws -> Data {
        let prehashed = try prehashed(digest)
        #if targetEnvironment(simulator)
        return try P256.Signing.PrivateKey(rawRepresentation: handle).signature(for: prehashed).derRepresentation
        #else
        let context = LAContext()
        context.localizedReason = reason
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle, authenticationContext: context).signature(for: prehashed).derRepresentation
        #endif
    }

    /// The owner's presence for something that uses no key: deleting one (design §5.4). The same
    /// biometric check as for every use of a key; the simulator has none.
    static func confirmPresence(reason: String) async throws {
        #if !targetEnvironment(simulator)
        guard try await LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
            throw Failure("the biometric check did not pass")
        }
        #endif
    }

    /// CryptoKit signs a `Digest` and has no constructor for one from bytes already hashed (the
    /// userOpHash). SHA256Digest is a plain 32-byte value: start from a real one and overwrite
    /// it, as the Mac backend does. owner-core verifies the signature over the reviewed digest
    /// before it builds the answer, so a wrong digest here cannot leave the phone.
    private static func prehashed(_ digest: Data) throws -> SHA256Digest {
        guard digest.count == 32, MemoryLayout<SHA256Digest>.size == 32 else { throw Failure("the digest is not 32 bytes") }
        var d = SHA256.hash(data: Data())
        withUnsafeMutableBytes(of: &d) { $0.copyBytes(from: digest) }
        guard Data(d) == digest else { throw Failure("digest bytes did not round-trip") }
        return d
    }
}

struct Failure: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}
