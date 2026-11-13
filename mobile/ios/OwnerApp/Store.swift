// What the phone stores per enrollment (docs/MOBILE_OWNER_DESIGN.md §5.4). None of it is secret:
// the key handle is useless off this phone. It stays out of backups all the same, which would
// otherwise tell which accounts this phone controls (docs/MOBILE_DEV_MODE.md §3.4).

import Foundation

struct Pin: Codable {
    let address: String
    let label: String
}

struct Enrollment: Codable, Identifiable {
    let label: String
    let chainId: UInt64
    let account: String
    let entryPoint: String
    let enrolledAt: UInt64
    /// False until the laptop itself confirmed that it has the answer: such a key was never anyone's root.
    var confirmed: Bool
    /// Names the laptop gave to addresses this build does not know; shown as unverified.
    let pins: [Pin]
    let tier: String
    /// `x ‖ y`.
    let publicKey: Data
    let keyHandle: Data

    var id: String { Enrollment.id(chainId, account) }
    static func id(_ chainId: UInt64, _ account: String) -> String { "\(chainId)-\(account.lowercased())" }
}

enum Store {
    private static let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("enrollments")
    private static let file = directory.appendingPathComponent("enrollments.json")

    /// The stored enrollments. A file that cannot be read is moved aside, never overwritten: it
    /// holds the only handles to keys that may be someone's root.
    static func load() -> (enrollments: [Enrollment], problem: String?) {
        guard let data = try? Data(contentsOf: file) else { return ([], nil) }
        if let all = try? JSONDecoder().decode([Enrollment].self, from: data) { return (all, nil) }
        let aside = directory.appendingPathComponent("enrollments.unreadable-\(Int(Date().timeIntervalSince1970)).json")
        try? FileManager.default.moveItem(at: file, to: aside)
        return ([], "the stored enrollments could not be read; the file is kept as \(aside.lastPathComponent)")
    }

    static func save(_ all: [Enrollment]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try JSONEncoder().encode(all).write(to: file, options: [.atomic, .completeFileProtection])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var dir = directory
        try dir.setResourceValues(values)
    }
}
