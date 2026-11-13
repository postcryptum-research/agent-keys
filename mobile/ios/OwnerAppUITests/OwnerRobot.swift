// The owner's hands for the simulator run (README.md, run-simulator.sh): agent-signer's phone
// test drives an enrollment, the proof that the phone holds the new key, and two signatures
// into the app and checks what comes back, and this taps what a person would. It keeps each screen it saw, and checks what only the screen
// can show (design §6.6): every row owner-core produced is on the review, Sign is not offered
// before the end of the review is on screen, and a review with bold effects asks a second time.

import XCTest

final class OwnerRobot: XCTestCase {
    func testActAsTheOwner() throws {
        let app = XCUIApplication()
        app.launch()
        let seconds = Double(ProcessInfo.processInfo.environment["TPMSIGN_ROBOT_SECONDS"] ?? "") ?? 300
        let end = Date().addingTimeInterval(seconds)
        var reviewing = false
        var tappedSign = false
        var emphasised = false
        /// The app's log line for the signature in flight, once the laptop has confirmed it.
        var awaited: String?
        var signatures = 0
        var secondConfirmations = 0
        var proofs = 0
        while Date() < end {
            if let line = awaited, appLog().contains(where: { $0.contains(line) }) {
                awaited = nil
                signatures += 1
                keep("after signature \(signatures)")
                // the run's two signatures are with the laptop: a permission install, then the change of the root key
                if signatures == 2 {
                    XCTAssertEqual(secondConfirmations, 1, "exactly the change of the root key asks a second time")
                    XCTAssertEqual(proofs, 1, "the handover to this phone waits for the phone to show the key, once")
                    return
                }
            }
            let enroll = app.buttons["enroll"]
            if enroll.exists && enroll.isHittable {
                keep("the enrollment prompt")
                enroll.tap()
            }
            let done = app.buttons["fingerprint-done"]
            if done.exists && done.isHittable {
                keep("the new key's fingerprint")
                done.tap()
            }
            let prove = app.buttons["prove"]
            if prove.exists && prove.isHittable {
                XCTAssertEqual(signatures, 0, "the key is shown before it is root, not after")
                keep("the proof prompt")
                proofs += 1
                prove.tap()
            }
            let yes = app.buttons["confirm-sign"]
            if yes.exists && yes.isHittable {
                XCTAssertTrue(emphasised, "a second confirmation for a review without bold effects")
                keep("the second confirmation")
                secondConfirmations += 1
                yes.tap()
            }
            let sign = app.buttons["sign"]
            guard sign.exists else { reviewing = false; tappedSign = false; usleep(300_000); continue }
            // Sign is tapped: the second confirmation or the end of this screen is on its way
            if tappedSign { usleep(300_000); continue }
            let lastRow = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'userOpHash: '")).firstMatch
            if !reviewing {
                reviewing = true
                keep("review \(signatures + 1) as it opens")
                emphasised = try everyRowIsOnTheReview(app)
                // both reviews of this run are longer than the screen
                XCTAssertFalse(lastRow.isHittable, "the reviews of this run were expected to need scrolling")
                XCTAssertFalse(sign.isEnabled, "Sign was offered as the review opened, before its end was on screen")
            }
            if sign.isEnabled {
                XCTAssertTrue(lastRow.isHittable, "Sign was offered before the end of the review was on screen")
                keep("review \(signatures + 1) at its end")
                // "userOpHash: 0x<64 hex>" on the screen; the app logs "signed 0x<8>…<6> and posted: <the laptop's reply>"
                let hash = lastRow.label.dropFirst("userOpHash: ".count)
                awaited = "signed \(hash.prefix(10))…\(hash.suffix(6)) and posted: confirmed by the laptop"
                sign.tap()
                tappedSign = true
            } else {
                app.swipeUp()
            }
        }
        XCTFail("\(signatures) of 2 signatures confirmed by the laptop within \(Int(seconds)) seconds")
    }

    /// The app logs each review as owner-core's text, where "! " marks an emphasised row; the
    /// screen must show every row, the emphasised ones with their mark and no other with it.
    /// Returns whether the review has emphasised rows.
    private func everyRowIsOnTheReview(_ app: XCUIApplication) throws -> Bool {
        var shown: [String] = []
        func walk(_ element: XCUIElementSnapshot) {
            if element.elementType == .staticText { shown.append(element.label) }
            element.children.forEach(walk)
        }
        walk(try app.snapshot())
        let logged = try XCTUnwrap(appLog().last { $0.hasPrefix("REVIEW (owner-core") }, "the app did not log the review")
        let rows = logged.split(separator: "\n").dropFirst().map(String.init).filter { !$0.hasPrefix("## ") && !$0.hasPrefix("WARNINGS: ") }
        XCTAssertGreaterThan(rows.count, 10, "the reviews of this run have more rows than that")
        XCTAssertTrue(rows.contains(shown.last ?? ""), "the log read is not this review's: \(shown.last ?? "nothing shown")")
        print("ROBOT reads review:\n" + shown.joined(separator: "\n"))
        for row in rows {
            let expected = row.hasPrefix("! ") ? "⚠ " + row.dropFirst(2) : row
            XCTAssertTrue(shown.contains(expected), "the review does not show the row: \(expected)")
        }
        return rows.contains { $0.hasPrefix("! ") }
    }

    /// The app's log, which a simulator build also writes to the simulated device's tmp
    /// directory: the review holds the whole screen, so the log is not on it.
    private func appLog() -> [String] {
        let device = ProcessInfo.processInfo.environment["SIMULATOR_SHARED_RESOURCES_DIRECTORY"] ?? ""
        guard let data = FileManager.default.contents(atPath: device + "/tmp/tpmsign-app-log.json") else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    private func keep(_ name: String) {
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }
}
