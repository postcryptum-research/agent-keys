// The camera side of the QR (docs/MOBILE_OWNER_DESIGN.md §3.2), with the system's own scanner.
// Phones only: the simulator has no camera (Model.watchQrFile).

#if !targetEnvironment(simulator)
import AVFoundation
import SwiftUI
import VisionKit

struct QrScanner: UIViewControllerRepresentable {
    /// The text of a `tpmsign:` QR, or why the camera could not look for one.
    let done: (Result<String, Error>) -> Void

    /// Asks for the camera the first time; `false` when this phone cannot scan or may not.
    static func allowed() async -> Bool {
        guard DataScannerViewController.isSupported else { return false }
        return await AVCaptureDevice.requestAccess(for: .video)
    }

    func makeCoordinator() -> Coordinator { Coordinator(done) }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        do { try scanner.startScanning() } catch { DispatchQueue.main.async { done(.failure(error)) } }
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let done: (Result<String, Error>) -> Void
        init(_ done: @escaping (Result<String, Error>) -> Void) { self.done = done }

        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let code) in addedItems {
                // another QR in view is not ours: owner-core parses and judges the one that is
                guard let text = code.payloadStringValue, text.hasPrefix("tpmsign:") else { continue }
                scanner.stopScanning()
                done(.success(text))
                return
            }
        }

        func dataScanner(_ scanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            done(.failure(error))
        }
    }
}
#endif
