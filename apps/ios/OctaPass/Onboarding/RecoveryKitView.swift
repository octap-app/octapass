import CoreImage.CIFilterBuiltins
import OctaPassResources
import OctaPassVault
import SwiftUI
#if canImport(UIKit)
import UIKit
#else
import AppKit
import PDFKit
#endif

/// What a Recovery Kit shows. Sign-up and a reset always make a recovery code; replacing the
/// Secret Key can keep the old one (`NewRecoveryKit`).
protocol RecoveryKitContents {
    var email: String { get }
    var serverUrl: String { get }
    var secretKey: String { get }
    /// Nil when the previous kit's recovery code still works.
    var shownRecoveryCode: String? { get }
    var createdAt: String { get }
}

extension RecoveryKit: RecoveryKitContents {
    var shownRecoveryCode: String? { recoveryCode }
}

extension NewRecoveryKit: RecoveryKitContents {
    var shownRecoveryCode: String? { recoveryCode }
}

extension RecoveryKitContents {
    /// What a new device scans. It never holds the recovery code, so the one here is left blank.
    var setupUri: String {
        recoveryKitSetupUri(kit: RecoveryKit(
            email: email, serverUrl: serverUrl, secretKey: secretKey, recoveryCode: "", createdAt: createdAt))
    }
}

/// The Recovery Kit as the web vault lays it out (`RecoveryKitSheet`): made on this phone,
/// nothing uploaded. The QR code fills in a new device; it never holds the recovery code.
struct RecoveryKitCard: View {
    let kit: any RecoveryKitContents
    /// The printed page: fixed colours, no Dynamic Type, so it fits one sheet.
    var page = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image("LogoTile").resizable().frame(width: 36, height: 36).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.kit.sheetTitle).font(.headline).foregroundStyle(ink)
                    Text(L10n.kit.createdOn(date: Dates.long(kit.createdAt))).font(.footnote).foregroundStyle(mist)
                }
            }
            field(L10n.fields.email, kit.email)
            field(L10n.kit.server, kit.serverUrl)
            field(L10n.fields.secretKey, kit.secretKey, mono: true)
                .accessibilityIdentifier("kit-secret-key")
            VStack(alignment: .leading, spacing: 4) {
                Text(L10n.fields.masterPassword).font(.caption.weight(.medium)).foregroundStyle(mist)
                Rectangle().fill(Color.clear).frame(height: 28)
                    .overlay(alignment: .bottom) { Rectangle().fill(mist.opacity(0.5)).frame(height: 1) }
                    .accessibilityLabel(L10n.kit.writeItDown)
            }
            HStack(alignment: .center, spacing: 14) {
                QRCodeImage(text: kit.setupUri)
                    .frame(width: 112, height: 112)
                    .accessibilityLabel(L10n.kit.qrLabel)
                Text(L10n.kit.qrHelp).font(.footnote).foregroundStyle(mist)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(L10n.kit.recoveryCode).font(.subheadline.weight(.semibold)).foregroundStyle(ink)
                if let code = kit.shownRecoveryCode {
                    Text(code).font(.secret(.callout)).foregroundStyle(ink).textSelection(.enabled)
                        .accessibilityIdentifier("kit-recovery-code")
                } else {
                    Text(L10n.kit.recoveryKept).font(.callout).foregroundStyle(ink)
                        .accessibilityIdentifier("kit-recovery-kept")
                }
                Text(L10n.kit.recoveryHelp).font(.footnote).foregroundStyle(mist)
            }
            Text(L10n.kit.keepSafe).font(.footnote).foregroundStyle(mist)
        }
        .padding(18)
        .background(page ? Color.white : Color.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(page ? Color.gray.opacity(0.3) : Color.line))
    }

    private var ink: Color { page ? .black : .ink }
    private var mist: Color { page ? Color(white: 0.35) : .mist }

    private func field(_ label: String, _ value: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption.weight(.medium)).foregroundStyle(mist)
            Text(value)
                .font(mono ? .secret(.callout) : .callout)
                .foregroundStyle(ink)
                .textSelection(.enabled)
                .environment(\.layoutDirection, .leftToRight)
        }
        .accessibilityElement(children: .combine)
    }
}

/// Save (Files, AirDrop, …) and print the kit as a one-page PDF. The PDF is written to the app's
/// own temporary folder and deleted when the screen goes.
struct RecoveryKitActions: View {
    let kit: any RecoveryKitContents
    @State private var pdf: URL?

    var body: some View {
        VStack(spacing: 10) {
            if let pdf {
                ShareLink(item: pdf) {
                    Label(L10n.phone.native.kitSave, systemImage: "square.and.arrow.up")
                        .fontWeight(.medium)
                        .frame(maxWidth: .infinity, minHeight: 50)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("kit-save")
            }
            SecondaryButton(title: L10n.kit.print, systemImage: "printer") { print() }
                .accessibilityIdentifier("kit-print")
        }
        .task { pdf = try? RecoveryKitPDF.write(kit) }
        .onDisappear { RecoveryKitPDF.remove() }
    }

    private func print() {
        guard let data = try? RecoveryKitPDF.data(kit) else { return }
        #if os(macOS)
        guard let document = PDFDocument(data: data),
              let operation = document.printOperation(for: NSPrintInfo.shared, scalingMode: .pageScaleToFit, autoRotate: true)
        else { return }
        operation.jobTitle = L10n.kit.sheetTitle
        operation.runModal(for: NSApp.keyWindow ?? NSWindow(), delegate: nil, didRun: nil, contextInfo: nil)
        #else
        let controller = UIPrintInteractionController.shared
        let info = UIPrintInfo.printInfo()
        info.outputType = .general
        info.jobName = L10n.kit.sheetTitle
        controller.printInfo = info
        controller.printingItem = data
        controller.present(animated: true)
        #endif
    }
}

@MainActor
enum RecoveryKitPDF {
    static var folder: URL { FileManager.default.temporaryDirectory.appending(path: "kit") }

    /// A4-sized, one page.
    static func data(_ kit: any RecoveryKitContents) throws -> Data {
        let size = CGSize(width: 595, height: 842)
        let renderer = ImageRenderer(content:
            RecoveryKitCard(kit: kit, page: true)
                .padding(36)
                .frame(width: size.width, height: size.height, alignment: .top)
                .background(Color.white)
                .environment(\.colorScheme, .light)
                .environment(\.dynamicTypeSize, .medium))
        let output = NSMutableData()
        var box = CGRect(origin: .zero, size: size)
        guard let consumer = CGDataConsumer(data: output as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &box, nil)
        else { throw CocoaError(.fileWriteUnknown) }
        renderer.render { _, draw in
            context.beginPDFPage(nil)
            draw(context)
            context.endPDFPage()
            context.closePDF()
        }
        return output as Data
    }

    static func write(_ kit: any RecoveryKitContents) throws -> URL {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appending(path: "\(L10n.kit.sheetTitle).pdf")
        try data(kit).write(to: url, options: [.completeFileProtection])
        return url
    }

    static func remove() {
        try? FileManager.default.removeItem(at: folder)
    }
}

/// A new Recovery Kit waiting for the user to save it, and what to say around it.
struct PendingRecoveryKit {
    let kit: NewRecoveryKit
    let title: String
    let message: String
    /// Shown as a toast once the kit is saved.
    var done: String?
}

/// A kit from replacing a Secret Key or taking over an account: the only copy away from this
/// phone, so it covers the app until the user says it's saved. Nothing else on screen can close
/// it. `RootView` shows it from `AppModel.newKit`, so a lock on the way hides it and an unlock
/// brings it back.
struct NewRecoveryKitView: View {
    @Environment(AppModel.self) private var model
    let pending: PendingRecoveryKit
    @State private var saved = false

    var body: some View {
        AuthLayout(title: pending.title, subtitle: pending.message) {
            VStack(alignment: .leading, spacing: 16) {
                RecoveryKitCard(kit: pending.kit)
                RecoveryKitActions(kit: pending.kit)
                Toggle(L10n.reset.kitConfirm, isOn: $saved)
                    .toggleStyle(CheckboxToggleStyle())
                    .accessibilityIdentifier("new-kit-saved")
                PrimaryButton(title: L10n.kit.continue, disabled: !saved) {
                    model.newKit = nil
                    if let done = pending.done { model.confirm(done) }
                }
                .accessibilityIdentifier("new-kit-continue")
            }
        }
    }
}

/// A QR code for `text`, drawn crisp at any size.
struct QRCodeImage: View {
    let text: String

    var body: some View {
        if let image = Self.image(text) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .padding(6)
                .background(Color.white)
        }
    }

    static func image(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage,
              let cgImage = CIContext().createCGImage(output, from: output.extent)
        else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

/// Dates as the web vault shows them, in the shown language.
enum Dates {
    private static let parser: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let plain = ISO8601DateFormatter()

    static func parse(_ text: String) -> Date? {
        parser.date(from: text) ?? plain.date(from: text)
    }

    static func long(_ text: String) -> String {
        guard let date = parse(text) else { return text }
        return date.formatted(Date.FormatStyle(date: .long, time: .omitted).locale(L10n.formatLocale))
    }

    static func medium(_ text: String) -> String {
        guard let date = parse(text) else { return text }
        return date.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(L10n.formatLocale))
    }

    static func relative(_ text: String) -> String {
        guard let date = parse(text) else { return text }
        return date.formatted(Date.RelativeFormatStyle(presentation: .named).locale(L10n.formatLocale))
    }
}
