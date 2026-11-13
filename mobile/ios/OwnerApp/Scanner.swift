// The camera side of the QR (docs/MOBILE_OWNER_DESIGN.md §3.2), with the system's own scanner.
// Phones only: the simulator has no camera (Model.watchQrFile).

#if !targetEnvironment(simulator)
import SwiftUI
import VisionKit

struct QrScanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(found) }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let found: (String) -> Void
        init(_ found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let code) in addedItems {
                // another QR in view is not ours: owner-core parses and judges the one that is
                guard let text = code.payloadStringValue, text.hasPrefix("tpmsign:") else { continue }
                scanner.stopScanning()
                found(text)
                return
            }
        }
    }
}
#endif
