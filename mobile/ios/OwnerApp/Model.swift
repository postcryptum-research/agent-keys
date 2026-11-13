// The owner app for the iPhone (docs/MOBILE_OWNER_PLAN.md, phase P4): the same loop as
// mobile/android. A QR opens a session with the laptop; owner-core checks the request, decides
// the verdict and gives the screen and the digest from one parse (design §6.1); the key signs
// that digest and nothing else; the laptop's confirmation is the only thing that makes an
// enrollment permanent (§3.3). Every rule lives in the core. This file moves bytes.

import CryptoKit
import Foundation

struct EnrollPrompt {
    let request: FfiEnrollment
    let qr: FfiQr
    /// An earlier enrollment of this account that the laptop never confirmed is replaced.
    let replacesUnconfirmed: Bool
}

struct ReviewPrompt: Identifiable {
    let id = UUID()
    let review: ReviewHandle
    let warnings: [String]
    let enrollment: Enrollment
    let qr: FfiQr
}

/// The laptop asks this phone to show that it holds a key (design §2.4).
struct ProofPrompt {
    let health: HealthHandle
    let enrollment: Enrollment
    let qr: FfiQr
}

/// The owner asked to delete an enrollment (design §5.4): owner-core's words, asked twice.
struct DeletePrompt {
    let enrollment: Enrollment
    let words: FfiDeletionPrompt
}

struct ShownFingerprint {
    let text: String
    let account: String
}

@MainActor
final class Model: ObservableObject {
    @Published var log: [String] = []
    @Published var enrollments: [Enrollment] = []
    /// A request waiting for the owner's decision: it holds the screen until it has one.
    @Published var enrollPrompt: EnrollPrompt?
    @Published var reviewPrompt: ReviewPrompt?
    @Published var proofPrompt: ProofPrompt?
    @Published var deletePrompt: DeletePrompt?
    /// The new key's fingerprint, kept on screen while the owner types it on the laptop.
    @Published var fingerprint: ShownFingerprint?
    /// Something the owner must not miss, kept at the top of the screen until acknowledged.
    @Published var notice: String?

    private var app: FfiApp { FfiApp(platform: "ios", version: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?") }
    private var now: UInt64 { UInt64(Date().timeIntervalSince1970) }

    init() {
        let stored = Store.load()
        enrollments = stored.enrollments
        say("owner-core \(coreVersion()) loaded; key tier on this device: \(OwnerKey.tier)")
        if let problem = stored.problem { say("ERROR \(problem)") }
        #if targetEnvironment(simulator)
        watchQrFile()
        #endif
    }

    func say(_ line: String) {
        log.append(line)
        // to the console of whoever launched the app (`xcrun devicectl device process launch --console`)
        print(line)
        #if targetEnvironment(simulator)
        // out to the run that drives the simulator: a request holds the whole screen, so the log is not on it
        if let file = Model.exchange?.appendingPathComponent("tpmsign-app-log.json") { try? JSONEncoder().encode(log).write(to: file, options: .atomic) }
        #endif
    }

    #if targetEnvironment(simulator)
    /// The simulated device's own tmp directory, where a simulator run (run-simulator.sh) and
    /// this app exchange files: the QR's text comes in, the app's log goes out. Not the app's
    /// Documents, which the simulator moves when a test run installs the app again.
    private static let exchange = ProcessInfo.processInfo.environment["SIMULATOR_SHARED_RESOURCES_DIRECTORY"].map { URL(fileURLWithPath: $0).appendingPathComponent("tmp") }
    #endif

    // ---- the session (design §3) ----------------------------------------------

    /// `tpmsign:1?u=<url>&h=<commitment>&k=<secret>`: owner-core's parser, one implementation of the §3.2 host rule.
    func handleQr(_ uri: String) {
        Task {
            do {
                // the secret came through the camera and goes nowhere: it only keys the MAC on this session's answers
                let qr = try parseQr(uri: uri)
                say("session: \(qr.url)")
                let bytes = try await Http.get(qr.url)
                // nothing of the request is read before it is the one the QR committed to
                let digest = Data(SHA256.hash(data: bytes)).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
                guard digest == qr.commitment else { throw Failure("the served request does not match the QR's commitment; refusing") }
                switch (try JSONSerialization.jsonObject(with: bytes) as? [String: Any])?["tpmSign"] as? String {
                case "enroll-request": try openEnroll(bytes, qr)
                case "sign-request": try openReview(bytes, qr)
                case "health-request": try openProof(bytes, qr)
                case let other: throw Failure("unknown request type \(other ?? "none")")
                }
            } catch { say("ERROR \(error.localizedDescription)") }
        }
    }

    #if targetEnvironment(simulator)
    /// The simulator has no camera: agent-signer writes the QR's text to a file
    /// (`--phone-qr-file`), and the app takes it from there. Simulator builds only.
    private func watchQrFile() {
        guard let file = Model.exchange?.appendingPathComponent("tpmsign-session.qr") else {
            return say("ERROR no SIMULATOR_SHARED_RESOURCES_DIRECTORY: nowhere to take a QR from")
        }
        Task {
            while true {
                // one request at a time: the next QR waits for the decision on this one
                if enrollPrompt == nil, reviewPrompt == nil, proofPrompt == nil, deletePrompt == nil, let text = try? String(contentsOf: file, encoding: .utf8), !text.isEmpty {
                    try? FileManager.default.removeItem(at: file)
                    handleQr(text.trimmingCharacters(in: .whitespacesAndNewlines))
                }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }
    #endif

    // ---- enrollment (design §2.1, §4.3, §5.3) -----------------------------------

    private func openEnroll(_ bytes: Data, _ qr: FfiQr) throws {
        // owner-core checks the request (commitment, type, version, expiry, the label and the pins as
        // plain text) and splits the laptop's pins by what this build knows itself (§4.3)
        let e = try openEnrollment(bytes: bytes, commitment: qr.commitment, now: now)
        let existing = enrollments.first { $0.id == Enrollment.id(e.chainId, e.account) }
        if existing?.confirmed == true {
            throw Failure("this phone already holds a key for \(e.account) on chain \(e.chainId); a new key needs a handover from the current one (§5.4)")
        }
        say("ENROLLMENT\n  chain \(e.chainId)\n  account \(e.account)\n  label \(e.label)\n  entryPoint \(e.entryPoint)")
        enrollPrompt = EnrollPrompt(request: e, qr: qr, replacesUnconfirmed: existing != nil)
    }

    func refuseEnrollment(_ prompt: EnrollPrompt) {
        enrollPrompt = nil
        say("enrollment refused — telling the laptop")
        let refusal = enrollRefusal(commitment: prompt.qr.commitment, reason: "user", detail: "declined on the phone", app: app)
        Task { _ = try? await Http.post(prompt.qr, refusal) }
    }

    func enroll(_ prompt: EnrollPrompt) {
        enrollPrompt = nil
        let e = prompt.request
        let id = Enrollment.id(e.chainId, e.account)
        Task {
            do {
                // only after the owner's yes: an unconfirmed key was never anyone's root
                enrollments.removeAll { $0.id == id }
                let key = try OwnerKey.create()
                let fp = try fingerprintOf(publicKey: key.publicKey)
                let answer = try enrollAnswer(commitment: prompt.qr.commitment, publicKey: key.publicKey, securityLevel: OwnerKey.tier, deviceCredential: false, attestation: [], app: app)
                enrollments.append(Enrollment(
                    label: e.label, chainId: e.chainId, account: e.account, entryPoint: e.entryPoint, enrolledAt: now, confirmed: false,
                    pins: e.pins.map { Pin(address: $0.address, label: $0.label) }, tier: OwnerKey.tier, publicKey: key.publicKey, keyHandle: key.handle
                ))
                try Store.save(enrollments)
                say("new key: tier \(OwnerKey.tier)\n  FINGERPRINT  \(fp)\n  the laptop confirms the enrollment once it has the answer, and by default only after you typed the fingerprint there (waiting up to 5 minutes)")
                fingerprint = ShownFingerprint(text: fp, account: e.account)
                let reply = try? await Http.post(prompt.qr, answer, timeout: 300)
                // the laptop itself says it has the answer: the enrollment is confirmed
                if reply?.confirmed == true, let i = enrollments.firstIndex(where: { $0.id == id }) {
                    enrollments[i].confirmed = true
                    try Store.save(enrollments)
                    say("enrollment confirmed by the laptop. Next there: owner set-root … --expect-fingerprint \(fp) --to-phone \(e.label)")
                } else {
                    // Anything else says nothing about what the laptop has: a lost reply, a reply
                    // replaced on the way, and a real rejection look the same from here. The key is
                    // kept, unconfirmed. Deleting it is the one step that cannot be undone, and the
                    // laptop may be about to make it root (issue #38).
                    let outcome = reply?.description ?? "the POST failed"
                    say("enrollment NOT confirmed (\(outcome)). The key is kept, unconfirmed: the laptop may have accepted it all the same. If the laptop says \"enrolled\", its handover asks this phone to show the key (--to-phone), which settles it. If it does not, enroll again: the unconfirmed key is replaced then.")
                    // said where it cannot be missed: the owner is looking at the laptop, which may be saying "enrolled"
                    notice = "The laptop did not confirm this enrollment to this phone (\(outcome)).\n\nThe key is kept, unconfirmed. If the laptop says \"enrolled\", it has the key all the same: its handover will ask this phone to show the key, and that settles it. If the laptop reports a failure, enroll again: the unconfirmed key is replaced then."
                }
            } catch { say("ERROR \(error.localizedDescription)") }
        }
    }

    // ---- signing (design §2.3, §6) ----------------------------------------------

    /// owner-core parses the request once; the screen, the verdict and the digest come from that parse (§6.1).
    private func openReview(_ bytes: Data, _ qr: FfiQr) throws {
        let confirmed = enrollments.filter(\.confirmed)
        let review = try openRequest(bytes: bytes, commitment: qr.commitment, now: now, enrolled: confirmed.map {
            FfiEnrolledAccount(
                chainId: $0.chainId, entryPoint: $0.entryPoint, account: $0.account, validator: nil, gasCapWei: defaultGasCapWei(), expertMode: false,
                pins: $0.pins.map { FfiPin(address: $0.address, label: $0.label) }
            )
        })
        var warnings: [String] = []
        switch review.verdict() {
        case .refuse(let reason):
            say("REFUSED by owner-core: \(reason)\n\n\(review.text())")
            let refusal = review.refuse(reason: "core", detail: reason, app: app)
            Task { _ = try? await Http.post(qr, refusal) }
            return
        case .signWithWarnings(let w): warnings = w
        case .sign: break
        }
        say("REVIEW (owner-core \(coreVersion()))\n\(review.text())" + (warnings.isEmpty ? "" : "\nWARNINGS: \(warnings.joined(separator: "; "))"))
        guard let enrollment = confirmed.first(where: { $0.id == Enrollment.id(review.chainId(), review.account()) }) else {
            throw Failure("no key for this account on this phone: enroll it first")
        }
        reviewPrompt = ReviewPrompt(review: review, warnings: warnings, enrollment: enrollment, qr: qr)
    }

    func refuse(_ prompt: ReviewPrompt, detail: String? = nil) {
        reviewPrompt = nil
        say("refused on the phone — telling the laptop")
        let refusal = prompt.review.refuse(reason: "user", detail: detail, app: app)
        Task { _ = try? await Http.post(prompt.qr, refusal) }
    }

    func sign(_ prompt: ReviewPrompt) {
        reviewPrompt = nil
        Task {
            let der: Data
            var hash = ""
            do {
                let digest = try prompt.review.digestToSign()
                let hex = digest.map { String(format: "%02x", $0) }.joined()
                hash = "0x\(hex.prefix(8))…\(hex.suffix(6))"
                let handle = prompt.enrollment.keyHandle
                // off the main thread: the Secure Enclave waits here for the biometric check
                der = try await Task.detached {
                    try OwnerKey.sign(handle: handle, digest: digest, reason: "Sign a root operation: userOpHash \(hash)")
                }.value
            } catch {
                // the biometric check was cancelled or failed, or the key is gone
                say("not signed: \(error.localizedDescription)")
                refuse(prompt, detail: error.localizedDescription)
                return
            }
            do {
                // owner-core converts DER to r‖s, normalizes low-s and verifies before it builds the response
                let response = try prompt.review.finish(derSignature: der, publicKey: prompt.enrollment.publicKey, app: app)
                say("signed \(hash) and posted: \(try await Http.post(prompt.qr, response).description)")
            } catch { say("ERROR \(error.localizedDescription)") }
        }
    }

    // ---- showing a key (design §2.2, §2.4) ---------------------------------------

    /// owner-core checks the request and decides whether this phone can answer it: it can for
    /// the key it holds for that account, confirmed by the laptop or not.
    private func openProof(_ bytes: Data, _ qr: FfiQr) throws {
        let health = try openHealth(bytes: bytes, commitment: qr.commitment, now: now, held: enrollments.map {
            FfiHeldKey(chainId: $0.chainId, account: $0.account, publicKey: $0.publicKey)
        })
        if let why = health.cannot() {
            say("CANNOT SHOW the key \(health.fingerprint()) for \(health.account()): \(why) — telling the laptop")
            let refusal = health.refuseAsUnable(app: app)
            Task { _ = try? await Http.post(qr, refusal) }
            return
        }
        guard let enrollment = enrollments.first(where: { $0.id == Enrollment.id((try? health.chainId()) ?? 0, health.account()) }) else {
            throw Failure("no key for this account on this phone")
        }
        say("PROOF asked: key \(health.fingerprint()), account \(health.account())")
        proofPrompt = ProofPrompt(health: health, enrollment: enrollment, qr: qr)
    }

    func refuseProof(_ prompt: ProofPrompt, detail: String? = nil) {
        proofPrompt = nil
        say("did not show the key — telling the laptop")
        let refusal = prompt.health.refuse(detail: detail, app: app)
        Task { _ = try? await Http.post(prompt.qr, refusal) }
    }

    func prove(_ prompt: ProofPrompt) {
        proofPrompt = nil
        let fp = prompt.health.fingerprint()
        Task {
            let der: Data
            do {
                let digest = try prompt.health.digestToSign()
                let handle = prompt.enrollment.keyHandle
                // off the main thread: the Secure Enclave waits here for the biometric check
                der = try await Task.detached { try OwnerKey.sign(handle: handle, digest: digest, reason: "Show the laptop that this phone holds the key \(fp)") }.value
            } catch {
                say("key not shown: \(error.localizedDescription)")
                refuseProof(prompt, detail: error.localizedDescription)
                return
            }
            do {
                // owner-core verifies the signature against the key the laptop named before the answer exists
                let answer = try prompt.health.finish(derSignature: der, app: app)
                // On this answer the laptop may make the key root, whatever becomes of its reply: from
                // here on the key is one in use, never one to replace.
                if let i = enrollments.firstIndex(where: { $0.id == prompt.enrollment.id }), !enrollments[i].confirmed {
                    enrollments[i].confirmed = true
                    try Store.save(enrollments)
                }
                say("showed the key \(fp) and posted: \(try await Http.post(prompt.qr, answer).description)")
            } catch { say("ERROR \(error.localizedDescription)") }
        }
    }

    // ---- deleting an enrollment on purpose (design §5.4) -------------------------

    /// The words are owner-core's, the same for a key the laptop confirmed and one it did not.
    func askToDelete(_ e: Enrollment) {
        do {
            deletePrompt = DeletePrompt(enrollment: e, words: try deletionPrompt(label: e.label, chainId: e.chainId, account: e.account, publicKey: e.publicKey))
        } catch { say("ERROR \(error.localizedDescription)") }
    }

    /// After both questions: the biometric check, then the key and its record go together.
    func delete(_ prompt: DeletePrompt) {
        deletePrompt = nil
        let e = prompt.enrollment
        Task {
            do { try await OwnerKey.confirmPresence(reason: prompt.words.reason) } catch {
                say("not deleted: \(error.localizedDescription)")
                return
            }
            // the key's handle lives in the record, so one write removes both, or neither
            let kept = enrollments
            enrollments.removeAll { $0.id == e.id }
            do {
                try Store.save(enrollments)
                say("deleted the key \((try? fingerprintOf(publicKey: e.publicKey)) ?? "?") and its record (account \(e.account), chain \(e.chainId))")
            } catch {
                enrollments = kept
                say("ERROR the key and its record could not be removed (\(error.localizedDescription)): nothing was deleted")
            }
        }
    }

    /// Development only: a local anvil is recreated on every run, so its accounts recur with new owners.
    func deleteTestEnrollments() {
        let before = enrollments.count
        enrollments.removeAll { $0.chainId == 31337 }
        do {
            try Store.save(enrollments)
            say("deleted \(before - enrollments.count) test-chain enrollment(s) and their keys")
        } catch { say("ERROR \(error.localizedDescription)") }
    }
}
