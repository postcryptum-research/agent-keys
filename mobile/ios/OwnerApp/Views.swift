// The screens: the accounts and the log, the enrollment prompt, the review (design §2.1, §6.6).
// Everything shown about a request comes from owner-core's sections; nothing is decided here.
// A request that waits for a decision takes the whole screen until it has one: there is
// nothing to swipe away, and nothing else to tap.

import SwiftUI

@main
struct OwnerApp: App {
    @StateObject private var model = Model()
    var body: some Scene {
        WindowGroup { ContentView().environmentObject(model) }
    }
}

struct ContentView: View {
    @EnvironmentObject private var model: Model
    @State private var scanning = false

    var body: some View {
        if let prompt = model.reviewPrompt {
            ReviewScreen(prompt: prompt).id(prompt.id)
        } else if let prompt = model.enrollPrompt {
            EnrollScreen(prompt: prompt)
        } else if let prompt = model.proofPrompt {
            ProofScreen(prompt: prompt)
        } else {
            accounts
        }
    }

    private var accounts: some View {
        NavigationStack {
            List {
                if let notice = model.notice {
                    Section("Not confirmed") {
                        Text(notice).bold().accessibilityIdentifier("notice")
                        Button("OK") { model.notice = nil }.accessibilityIdentifier("notice-ok")
                    }
                }
                if let fp = model.fingerprint {
                    Section("New key's fingerprint") {
                        Text(fp.text).font(.title2.monospaced()).textSelection(.enabled).accessibilityIdentifier("fingerprint")
                        Text(unhyphenated("Type at least its first two groups on the laptop when agent-signer asks (all four when in doubt). Account \(fp.account)."))
                        Button("Done") { model.fingerprint = nil }.accessibilityIdentifier("fingerprint-done")
                    }
                }
                Section("This phone") {
                    Text(OwnerKey.notice)
                    #if targetEnvironment(simulator)
                    Text("No camera here: agent-signer hands the QR's text to the simulator (mobile/ios/run-simulator.sh).")
                    #else
                    Button("Scan the laptop's QR") {
                        Task {
                            if await QrScanner.allowed() { scanning = true } else { model.say("ERROR the camera is not available to this app: allow it in Settings → TPM_sign owner → Camera") }
                        }
                    }
                    #endif
                }
                Section("Enrolled accounts") {
                    if model.enrollments.isEmpty { Text("none") }
                    ForEach(model.enrollments) { e in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(e.label) — chain \(e.chainId), tier \(e.tier)" + (e.confirmed ? "" : " — NOT CONFIRMED by the laptop"))
                            Text(unhyphenated(e.account)).font(.footnote.monospaced())
                            Text((try? fingerprintOf(publicKey: e.publicKey)) ?? "?").font(.footnote.monospaced())
                        }
                    }
                }
                if coreVersion().contains("+test-chains") {
                    Section("Development build") {
                        Button("Delete test-chain enrollments (anvil 31337)", role: .destructive) { model.deleteTestEnrollments() }
                    }
                }
                Section("Log") {
                    ForEach(Array(model.log.enumerated().reversed()), id: \.offset) { line in
                        Text(line.element).font(.footnote.monospaced()).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("TPM_sign owner")
            .navigationBarTitleDisplayMode(.inline)
        }
        #if !targetEnvironment(simulator)
        .sheet(isPresented: $scanning) {
            QrScanner { result in
                scanning = false
                switch result {
                case .success(let text): model.handleQr(text)
                case .failure(let error): model.say("ERROR the scanner stopped: \(error.localizedDescription)")
                }
            }
        }
        #endif
    }
}

/// Text the system must not hyphenate when it wraps: a hyphen at the end of a line would look
/// like a character of the address it breaks. Marked as being in no language, there is no
/// hyphenation to apply.
func unhyphenated(_ text: String) -> AttributedString {
    var out = AttributedString(text)
    out.languageIdentifier = "zxx"
    return out
}

/// §2.1 step 3: what is being enrolled, the tier this phone gives the key, the laptop's pins.
struct EnrollScreen: View {
    @EnvironmentObject private var model: Model
    let prompt: EnrollPrompt

    var body: some View {
        let e = prompt.request
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(unhyphenated("Account \(e.account) on chain \(String(e.chainId)), label \"\(e.label)\"."))
                    Text(OwnerKey.notice).bold()
                    if !e.chainKnown {
                        Text("This app has no built-in facts for chain \(String(e.chainId)): reviews there name no contract and refuse what they cannot classify.")
                    }
                    if !e.pins.isEmpty {
                        Text(unhyphenated("Names from the laptop — unverified, and shown as such in every review:\n" + e.pins.map { "\($0.address) \"\($0.label)\"" }.joined(separator: "\n")))
                    }
                    if !e.ignoredPins.isEmpty {
                        Text(unhyphenated("Names from the laptop that are IGNORED, because this app knows these addresses itself:\n" + e.ignoredPins.joined(separator: "\n")))
                    }
                    if prompt.replacesUnconfirmed {
                        Text("An earlier enrollment of this account was never confirmed by the laptop, and this phone never showed its key to the laptop; that key is replaced. If root was handed to it all the same, refuse here.").bold()
                    }
                    Text("A new key is created on this phone for this account. Nothing changes on-chain until the laptop hands root to it.")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .safeAreaInset(edge: .bottom) {
                HStack {
                    Button("Refuse", role: .cancel) { model.refuseEnrollment(prompt) }
                    Spacer()
                    Button(OwnerKey.enrollLabel) { model.enroll(prompt) }.buttonStyle(.borderedProminent).accessibilityIdentifier("enroll")
                }
                .padding()
                .background(.bar)
            }
            .navigationTitle("Enroll this phone as the owner key?")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

/// §2.4: the laptop asks whether this phone holds a key. What the key signs is a check value
/// both sides contribute to, never an operation.
struct ProofScreen: View {
    @EnvironmentObject private var model: Model
    let prompt: ProofPrompt

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(unhyphenated("The laptop asks this phone to show that it holds the key \(prompt.health.fingerprint()) of account \(prompt.health.account()) (\(prompt.enrollment.label), chain \(String(prompt.enrollment.chainId)))."))
                    Text("The key signs a one-time check value, not an operation: nothing goes to the chain, and nothing changes on it.")
                    if !prompt.enrollment.confirmed {
                        Text("The laptop never confirmed this key's enrollment to this phone. Showing the key is how the laptop learns that the phone has it; the laptop may then hand the account's root to it.").bold()
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            .safeAreaInset(edge: .bottom) {
                HStack {
                    Button("Refuse", role: .cancel) { model.refuseProof(prompt) }
                    Spacer()
                    Button("Show the key") { model.prove(prompt) }.buttonStyle(.borderedProminent).accessibilityIdentifier("prove")
                }
                .padding()
                .background(.bar)
            }
            .navigationTitle("Show that this phone holds the key?")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

/// §6.6: one Sign action, enabled once the end of the review has been on screen; the bold
/// effects get a second confirmation in plain words. That one is a step of this screen, not a
/// system alert: an alert hyphenates the addresses it wraps.
struct ReviewScreen: View {
    @EnvironmentObject private var model: Model
    let prompt: ReviewPrompt
    private let lines: [Line]
    /// The bold rows, for the second confirmation.
    private let effects: [String]
    @State private var reachedEnd = false
    @State private var confirming = false

    /// One row of the screen. The ids are unique across the whole review: rows that share an id
    /// with a row of another section are silently not drawn.
    private struct Line: Identifiable {
        let id: Int
        let text: String
        let bold: Bool
        let title: Bool
    }

    /// The y of the review's end inside the scroll view's frame.
    private struct EndOfReview: PreferenceKey {
        static var defaultValue: CGFloat = .infinity
        static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
    }

    init(prompt: ReviewPrompt) {
        self.prompt = prompt
        var lines: [Line] = []
        for section in prompt.review.sections() {
            lines.append(Line(id: lines.count, text: section.title.uppercased(), bold: true, title: true))
            for row in section.rows {
                lines.append(Line(id: lines.count, text: (row.emphasis ? "⚠ " : "") + "\(row.label): \(row.value)", bold: row.emphasis, title: false))
            }
        }
        if !prompt.warnings.isEmpty {
            lines.append(Line(id: lines.count, text: "WARNINGS: \(prompt.warnings.joined(separator: "; "))", bold: true, title: true))
        }
        self.lines = lines
        effects = prompt.review.effects()
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if confirming { secondConfirmation } else { review }
                HStack {
                    Button("Refuse", role: .cancel) { model.refuse(prompt) }
                    Spacer()
                    if confirming {
                        Button("Yes, sign") { model.sign(prompt) }.buttonStyle(.borderedProminent).accessibilityIdentifier("confirm-sign")
                    } else {
                        Button("Sign") {
                            if prompt.review.needsSecondConfirmation() { confirming = true } else { model.sign(prompt) }
                        }
                        .buttonStyle(.borderedProminent).disabled(!reachedEnd).accessibilityIdentifier("sign")
                    }
                }
                .padding()
                .background(.bar)
            }
            .navigationTitle(confirming ? "Are you sure?" : "Sign this operation?")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var review: some View {
        GeometryReader { visible in
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(lines) { line in
                        Text(unhyphenated(line.text)).fontWeight(line.bold ? .bold : .regular).padding(.top, line.title ? 10 : 0)
                    }
                    GeometryReader { end in
                        Color.clear.preference(key: EndOfReview.self, value: end.frame(in: .named("review")).maxY)
                    }
                    .frame(height: 1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding()
            }
            .coordinateSpace(name: "review")
            // the scroll view ends above the buttons, so "inside its frame" is "on screen"
            .onPreferenceChange(EndOfReview.self) { y in
                if visible.size.height > 0 && y <= visible.size.height { reachedEnd = true }
            }
        }
    }

    private var secondConfirmation: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("This operation:")
                ForEach(Array(effects.enumerated()), id: \.offset) { effect in
                    Text(unhyphenated("⚠ " + effect.element)).bold()
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
        }
    }
}
