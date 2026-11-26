// The owner's hands for the simulator run (README.md, run-simulator.sh): agent-signer's phone
// test drives an enrollment, the proof that the phone holds the new key, and two signatures
// into the app and checks what comes back, and this taps what a person would. It keeps each screen it saw, and checks what only the screen
// can show (design §6.6): every row owner-core produced is on the review, Sign is not offered
// before the end of the review is on screen, and a review with bold effects asks a second time.
// At the end it deletes the enrollment as an owner would, which the app asks about twice.

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
        var noticeKept = false
        var fingerprintKept = false
        while Date() < end {
            if let line = awaited, appLog().contains(where: { $0.contains(line) }) {
                awaited = nil
                signatures += 1
                keep("after signature \(signatures)")
                // the run's two signatures are with the laptop: a permission install, then the change of the root key
                if signatures == 2 {
                    XCTAssertEqual(secondConfirmations, 1, "exactly the change of the root key asks a second time")
                    XCTAssertEqual(proofs, 1, "the handover to this phone waits for the phone to show the key, once")
                    try deleteTheEnrollment(app)
                    return
                }
            }
            let enroll = app.buttons["enroll"]
            if enroll.exists && enroll.isHittable {
                keep("the enrollment prompt")
                enroll.tap()
            }
            // What the main screen says is recorded and left there: a request can take the screen over
            // at any moment, and a tap aimed at a row that has just gone fails the whole run. The robot
            // taps only on a request's own screen, which stays until it is decided.
            if !noticeKept && app.buttons["notice-ok"].exists {
                noticeKept = true
                keep("the not-confirmed notice")
            }
            if !fingerprintKept && app.buttons["fingerprint-done"].exists {
                fingerprintKept = true
                keep("the new key's fingerprint")
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

    /// The run ends as an owner's would after handing root on: the phone's key is deleted on
    /// purpose (design §5.4). Asked twice, in owner-core's words; one tap deletes nothing.
    private func deleteTheEnrollment(_ app: XCUIApplication) throws {
        let row = app.buttons["delete-enrollment"].firstMatch
        var swipes = 0
        while !(row.exists && row.isHittable) && swipes < 6 {
            app.swipeUp()
            swipes += 1
        }
        row.tap()
        let first = app.buttons["delete"]
        XCTAssertTrue(first.waitForExistence(timeout: 5), "the delete prompt did not open")
        let text = app.staticTexts.allElementsBoundByIndex.map(\.label).joined(separator: "\n")
        for needed in ["takes the account with it", "recovery key", "agent-signer owner status", "cannot be brought back"] {
            XCTAssertTrue(text.contains(needed), "the delete prompt does not say: \(needed)")
        }
        XCTAssertFalse(app.buttons["confirm-delete"].exists, "the second question comes after the first")
        keep("the delete prompt")
        first.tap()
        let second = app.buttons["confirm-delete"]
        XCTAssertTrue(second.waitForExistence(timeout: 5), "the second question did not come")
        XCTAssertFalse(appLog().contains { $0.hasPrefix("deleted the key") }, "one tap deleted the key")
        keep("the second question before the delete")
        second.tap()
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline && !appLog().contains(where: { $0.hasPrefix("deleted the key") }) { usleep(200_000) }
        XCTAssertTrue(appLog().contains { $0.hasPrefix("deleted the key") }, "the app did not delete the enrollment")
        XCTAssertFalse(app.buttons["delete-enrollment"].waitForExistence(timeout: 1), "the enrollment is still listed")
        keep("after the delete")
    }

    /// A session that fails is put in front of the owner (issue #215): the reason is at the top
    /// of the screen until it is dismissed, not only in the log. A QR that is no session is the
    /// plainest failure; it reaches the app the way agent-signer's QR does.
    func testAFailedSessionIsShown() throws {
        let app = XCUIApplication()
        app.launch()
        let device = ProcessInfo.processInfo.environment["SIMULATOR_SHARED_RESOURCES_DIRECTORY"] ?? ""
        try "not a session".write(toFile: device + "/tmp/tpmsign-session.qr", atomically: true, encoding: .utf8)
        let failure = app.staticTexts["failure"]
        XCTAssertTrue(failure.waitForExistence(timeout: 20), "a failed session put nothing on the screen")
        XCTAssertFalse(failure.label.isEmpty, "the failure is shown without its reason")
        XCTAssertTrue(appLog().contains { $0 == "ERROR \(failure.label)" }, "the screen and the log give different reasons: \(failure.label)")
        keep("a failed session")
        app.buttons["failure-ok"].tap()
        XCTAssertFalse(failure.waitForExistence(timeout: 1), "the failure is still shown after OK")
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
