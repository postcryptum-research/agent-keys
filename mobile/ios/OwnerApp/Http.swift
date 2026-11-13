// The LAN session's two requests (docs/MOBILE_OWNER_DESIGN.md §3.3): fetch the request, post the
// answer. Plain HTTP to the laptop; integrity comes from the QR's commitment and its secret.

import Foundation

/// The laptop's reply to a POST: `confirmed` when it is the confirmation MAC under the session's secret.
struct Reply {
    let code: Int
    let text: String
    let confirmed: Bool

    var description: String {
        if confirmed { return "confirmed by the laptop" }
        if code == 200 { return "HTTP 200 without the laptop's confirmation — not the laptop's answer" }
        return "HTTP \(code): \(text.prefix(300))"
    }
}

enum Http {
    static let maxRequestBytes = 64 * 1024
    private static let session = URLSession(configuration: .ephemeral)

    /// The request is a few KiB; anything past 64 KiB is not ours.
    static func get(_ url: String) async throws -> Data {
        guard let url = URL(string: url) else { throw Failure("the session URL is not a URL") }
        let (stream, response) = try await session.bytes(for: URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10))
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw Failure("HTTP \(code)") }
        var body = Data()
        for try await byte in stream {
            body.append(byte)
            if body.count > maxRequestBytes { throw Failure("the request exceeds \(maxRequestBytes / 1024) KiB; refusing") }
        }
        return body
    }

    /// Every answer of a session carries the MAC of the QR's secret, so the laptop knows it comes
    /// from the phone that scanned the QR. `timeout`: a sign response is answered at once; an
    /// enrollment answer may be held while the owner confirms the fingerprint on the laptop.
    static func post(_ qr: FfiQr, _ body: Data, timeout: TimeInterval = 10) async throws -> Reply {
        guard let url = URL(string: qr.url) else { throw Failure("the session URL is not a URL") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(try answerMac(secret: qr.secret, body: body), forHTTPHeaderField: answerMacHeader())
        let (data, response) = try await session.upload(for: request, from: body)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let text = String(decoding: data.prefix(4096), as: UTF8.self)
        // only the laptop can write this: a bare 200 could come from any host in the path that dropped our POST
        return Reply(code: code, text: text, confirmed: code == 200 && verifyConfirmation(secret: qr.secret, answerBody: body, reply: text))
    }
}
