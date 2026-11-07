import OctaPassResources
import OctaPassVault
import SwiftUI
import UniformTypeIdentifiers

/// Settings → Devices: where the account is signed in; rename this phone, sign others out.
struct DevicesView: View {
    @Environment(AppModel.self) private var model
    @State private var devices: [Device]?
    @State private var renaming: String?
    @State private var signingOut: Device?

    var body: some View {
        List {
            Section { Text(L10n.devices.help).font(.subheadline).foregroundStyle(Color.mist) }
            if let devices {
                ForEach(devices, id: \.id) { device in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Label(device.name, systemImage: ["ios", "android"].contains(device.platform) ? "iphone" : "desktopcomputer")
                            if device.current {
                                Text(L10n.devices.current).font(.caption.weight(.semibold)).foregroundStyle(Color.freeText)
                            }
                        }
                        Text("\(Self.platform(device.platform)) · \(L10n.devices.lastSeen(date: Dates.relative(device.lastSeenAt)))")
                            .font(.footnote).foregroundStyle(Color.mist)
                    }
                    .swipeActions {
                        if device.current {
                            Button(L10n.common.rename) { renaming = device.name }
                        } else {
                            Button(L10n.devices.signOut, role: .destructive) { signingOut = device }
                        }
                    }
                    .contextMenu {
                        if device.current {
                            Button(L10n.common.rename) { renaming = device.name }
                        } else {
                            Button(L10n.devices.signOutWhat(name: device.name), role: .destructive) { signingOut = device }
                        }
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.devices.title)
        .task { await load() }
        .alert(L10n.devices.rename, isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField(L10n.devices.rename, text: Binding(get: { renaming ?? "" }, set: { renaming = String($0.prefix(64)) }))
            Button(L10n.common.save) { Task { await rename() } }
            Button(L10n.common.cancel, role: .cancel) {}
        }
        .confirmationDialog(signingOut.map { L10n.devices.signOutTitle(name: $0.name) } ?? "",
                            isPresented: Binding(get: { signingOut != nil }, set: { if !$0 { signingOut = nil } }), titleVisibility: .visible) {
            Button(L10n.devices.signOut, role: .destructive) { Task { await signOut() } }
        } message: {
            Text(L10n.devices.signOutBody)
        }
    }

    static func platform(_ platform: String) -> String {
        L10n.text(forKey: "devices.platforms.\(platform)") ?? L10n.devices.platforms.other
    }

    private func load() async {
        do { devices = try await model.vault.listDevices() } catch { model.show(error) }
    }

    private func rename() async {
        guard let name = renaming?.trimmingCharacters(in: .whitespaces), !name.isEmpty else { return }
        do {
            try await model.vault.renameDevice(name: name)
            model.confirm(L10n.devices.renamed)
            await load()
        } catch { model.show(error) }
    }

    private func signOut() async {
        guard let device = signingOut else { return }
        do {
            try await model.vault.signOutDevice(deviceId: device.id)
            model.confirm(L10n.devices.signedOut(name: device.name))
            await load()
        } catch { model.show(error) }
    }
}

/// Settings → Security log: the account's own events, newest first.
struct SecurityLogView: View {
    @Environment(AppModel.self) private var model
    @State private var events: [SecurityEvent]?

    var body: some View {
        List {
            Section { Text(L10n.securityLog.subtitle).font(.subheadline).foregroundStyle(Color.mist) }
            if let events {
                if events.isEmpty {
                    Text(L10n.securityLog.empty).foregroundStyle(Color.mist)
                }
                ForEach(Array(events.enumerated()), id: \.offset) { _, event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(Self.describe(event))
                        Text([Self.exportDetails(event), Dates.medium(event.createdAt)].compactMap { $0 }.joined(separator: " · "))
                            .font(.footnote).foregroundStyle(Color.mist)
                    }
                }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.securityLog.title)
        .task {
            do { events = try await model.vault.securityLog() } catch { model.show(error) }
        }
    }

    /// `two-step-enabled` → the catalog's `securityLog.events.two-step-enabled`. An export names the device.
    static func describe(_ event: SecurityEvent) -> String {
        if event.eventType == "vault-exported" {
            return L10n.securityLog.events.vaultExported(device: event.deviceName ?? L10n.securityLog.unknownDevice)
        }
        let email = event.otherAccountEmail ?? L10n.securityLog.someone
        return L10n.text(forKey: "securityLog.events.\(event.eventType)", email) ?? event.eventType
    }

    /// An export's format, and whether the file held the attachments.
    static func exportDetails(_ event: SecurityEvent) -> String? {
        switch event.exportFormat {
        case .json: L10n.securityLog.exportDetails.json
        case .csv: L10n.securityLog.exportDetails.csv
        case .cxf: L10n.securityLog.exportDetails.cxf
        case .encrypted: event.exportAttachments == true ? L10n.securityLog.exportDetails.encryptedFiles : L10n.securityLog.exportDetails.encrypted
        case nil: nil
        }
    }
}

/// Settings → Export (plan 07): a format, the master password, and for the encrypted export a
/// password for the file. The file goes to the share sheet and is deleted afterwards.
struct ExportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var format = ExportFormat.encrypted
    @State private var password = ""
    @State private var confirm = ""
    @State private var error: String?
    @State private var busy = false
    @State private var file: URL?

    /// Anyone with the file can try guesses offline.
    static let minPassword = 10

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker(L10n.settings.exportFormat, selection: $format) {
                        Text(L10n.export.formatEncrypted).tag(ExportFormat.encrypted)
                        Text(L10n.settings.formatJson).tag(ExportFormat.json)
                        Text(L10n.settings.formatCsv).tag(ExportFormat.csv)
                        Text(L10n.export.formatCxf).tag(ExportFormat.cxf)
                    }
                    .pickerStyle(.menu)
                    .accessibilityIdentifier("export-format")
                    Text(help).font(.footnote).foregroundStyle(Color.mist)
                }
                if format == .encrypted {
                    Section {
                        MaskedField(label: L10n.export.password, text: $password)
                        MaskedField(label: L10n.export.confirmPassword, text: $confirm)
                    } footer: {
                        Text(L10n.export.encryptedNote)
                    }
                } else {
                    Section { Notice(text: L10n.settings.exportWarning, tone: .warn) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
                }
                Section {
                    if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                    if let file {
                        ShareLink(item: file) { Label(L10n.phone.native.kitShare, systemImage: "square.and.arrow.up") }
                            .accessibilityIdentifier("export-share")
                    } else {
                        Button {
                            Task { await export() }
                        } label: {
                            HStack { Label(L10n.settings.exportAction, systemImage: "square.and.arrow.up"); if busy { Spacer(); ProgressView() } }
                        }
                        .disabled(busy)
                        .accessibilityIdentifier("export-action")
                    }
                }
            }
            .navigationTitle(L10n.settings.exportTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(file == nil ? L10n.common.cancel : L10n.common.done) { dismiss() } }
            }
            .onChange(of: format) { file = nil }
            .onDisappear { if let file { model.vault.closeAttachment(path: file.path) } }
        }
    }

    private var help: String {
        switch format {
        case .encrypted: L10n.export.encryptedHelp
        case .json: L10n.settings.jsonHelp
        case .csv: L10n.settings.csvHelp
        case .cxf: L10n.export.cxfHelp
        }
    }

    private func export() async {
        if format == .encrypted {
            if password.count < Self.minPassword { error = L10n.export.passwordTooShort(count: Self.minPassword); return }
            if password != confirm { error = L10n.export.passwordMismatch; return }
        }
        // The device lock, or the master password without one (plan 03).
        guard await model.confirmIdentity() else { return }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let path = try await model.vault.exportVault(format: format, password: format == .encrypted ? password : nil, masterPassword: nil)
            file = URL(fileURLWithPath: path)
            Haptics.success()
        } catch {
            self.error = error.message
        }
    }
}

/// Settings → Import: every source the core reads, from a file the user picks.
struct ImportView: View {
    @Environment(AppModel.self) private var model
    @State private var source = ImportSource.chrome
    @State private var file: URL?
    @State private var keyFile: URL?
    @State private var password = ""
    @State private var needsPassword = false
    @State private var choosing = false
    @State private var choosingKey = false
    @State private var busy = false
    @State private var result: ImportSummary?
    @State private var review: ImportReview?
    @State private var error: String?

    struct Group: Identifiable {
        let label: String
        let sources: [(ImportSource, String)]
        var id: String { label }
    }

    static var groups: [Group] {
        [
            Group(label: L10n.import.groupOctaPass, sources: [(.octaPass, "Octa Pass"), (.cxf, L10n.import.cxf)]),
            Group(label: L10n.import.groupManagers, sources: [
                (.onePassword1Pux, "1Password (1PUX)"), (.onePasswordCsv, "1Password (CSV)"), (.bitwardenJson, "Bitwarden (JSON)"), (.bitwardenCsv, "Bitwarden (CSV)"),
                (.dashlane, "Dashlane"), (.enpass, "Enpass"), (.keePass, "KeePass, KeePassXC"), (.keeper, "Keeper"),
                (.lastPassCsv, "LastPass"), (.nordPass, "NordPass"), (.protonPass, "Proton Pass"), (.roboForm, "RoboForm"),
                (.avira, "Avira"), (.kaspersky, "Kaspersky"), (.mcAfee, "McAfee True Key"), (.norton, "Norton"), (.zohoVault, "Zoho Vault"),
            ]),
            Group(label: L10n.import.groupBrowsers, sources: [(.chrome, L10n.import.chrome), (.firefox, "Firefox"), (.safari, L10n.import.safari)]),
            Group(label: L10n.import.groupAuthenticators, sources: [(.aegis, "Aegis"), (.twoFas, "2FAS"), (.andOtp, "andOTP"), (.enteAuth, "Ente Auth"), (.raivo, "Raivo OTP"), (.otpauth, L10n.import.otpauth)]),
            Group(label: L10n.import.groupOther, sources: [(.genericCsv, L10n.import.generic)]),
        ]
    }

    /// Authenticator apps: each code goes through the review, joining the login the user picks.
    static let authenticators: Set<ImportSource> = [.aegis, .twoFas, .andOtp, .enteAuth, .raivo, .otpauth]

    /// Files that can be password-protected.
    static let protected: Set<ImportSource> = [.octaPass, .bitwardenJson, .keePass, .protonPass, .aegis, .twoFas, .andOtp, .enteAuth, .raivo]

    var body: some View {
        Form {
            Section {
                Picker(L10n.import.from, selection: $source) {
                    ForEach(Self.groups) { group in
                        Section(group.label) {
                            ForEach(group.sources, id: \.0) { Text($0.1).tag($0.0) }
                        }
                    }
                }
                .pickerStyle(.platformLong)
                .accessibilityIdentifier("import-source")
                if let help = L10n.text(forKey: "import.help.\(Self.helpKey(source))") {
                    Text(help).font(.footnote).foregroundStyle(Color.mist)
                }
            } footer: {
                Text(L10n.settings.importHelp)
            }
            Section {
                Button { choosing = true } label: {
                    LabeledContent(L10n.import.file, value: file?.lastPathComponent ?? L10n.import.chooseFile)
                }
                .accessibilityIdentifier("import-choose-file")
                if Self.protected.contains(source) || needsPassword {
                    SecureField(source == .octaPass ? L10n.import.exportPassword : L10n.import.filePassword, text: $password)
                    if !needsPassword { Text(L10n.import.filePasswordHint).font(.footnote).foregroundStyle(Color.mist) }
                }
                if source == .keePass {
                    Button { choosingKey = true } label: {
                        LabeledContent(L10n.import.keyFile, value: keyFile?.lastPathComponent ?? "")
                    }
                }
                if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                Button {
                    Task { await run() }
                } label: {
                    HStack { Label(L10n.import.action, systemImage: "square.and.arrow.down"); if busy { Spacer(); ProgressView() } }
                }
                .disabled(busy)
                .accessibilityIdentifier("import-action")
            }
            if let result {
                Section {
                    Text(Self.summary(result))
                    ForEach(result.warnings, id: \.self) { Text($0).font(.footnote).foregroundStyle(Color.warnText) }
                    Text(L10n.import.deleteFile).font(.footnote).foregroundStyle(Color.mist)
                }
            }
        }
        .navigationTitle(L10n.settings.import)
        .navigationDestination(item: Binding(get: { review.map(ReviewRoute.init) }, set: { if $0 == nil { review = nil } })) { route in
            ImportReviewView(review: route.review) { _ in review = nil }
        }
        .filePicker(isPresented: $choosing) { urls in file = urls.first; error = nil }
        .fileImporter(isPresented: $choosingKey, allowedContentTypes: [.item]) { if case let .success(url) = $0 { keyFile = url } }
        .onChange(of: source) {
            password = ""
            keyFile = nil
            needsPassword = false
            error = nil
        }
    }

    /// What an import did. Importing a file again updates what's there instead of adding copies.
    static func summary(_ result: ImportSummary) -> String {
        [result.updated + result.unchanged > 0
            ? L10n.import.summary(added: "\(result.imported)", updated: "\(result.updated)", unchanged: "\(result.unchanged)")
            : L10n.import.done(count: Int(result.imported)),
         result.skipped > 0 ? L10n.import.skipped(count: Int(result.skipped)) : nil,
         result.files > 0 ? L10n.import.files(count: Int(result.files)) : nil].compactMap { $0 }.joined(separator: " ")
    }

    static func helpKey(_ source: ImportSource) -> String {
        switch source {
        case .chrome: "chrome"
        case .firefox: "firefox"
        case .safari: "safari"
        case .bitwardenJson: "bitwarden-json"
        case .bitwardenCsv: "bitwarden-csv"
        case .onePassword1Pux: "onepassword-1pux"
        case .onePasswordCsv: "onepassword-csv"
        case .lastPassCsv: "lastpass-csv"
        case .genericCsv: "generic-csv"
        case .otpauth: "otpauth"
        case .octaPass: "octapass"
        case .cxf: "cxf"
        case .protonPass: "protonpass"
        case .dashlane: "dashlane"
        case .keeper: "keeper"
        case .nordPass: "nordpass"
        case .keePass: "keepass"
        case .enpass: "enpass"
        case .roboForm: "roboform"
        case .aegis: "aegis"
        case .twoFas: "2fas"
        case .andOtp: "andotp"
        case .enteAuth: "ente-auth"
        case .raivo: "raivo"
        case .zohoVault: "zoho-vault"
        case .avira: "avira"
        case .norton: "norton"
        case .mcAfee: "mcafee"
        case .kaspersky: "kaspersky"
        }
    }

    private func run() async {
        guard let file else {
            error = L10n.import.chooseFile
            return
        }
        busy = true
        error = nil
        result = nil
        defer { busy = false }
        // The pickers hand out scoped URLs: copy into the app's own temporary folder first.
        guard let copy = try? PickedFiles.copy(file) else {
            error = L10n.errors.invalidImportFile
            return
        }
        let key = keyFile.flatMap { try? PickedFiles.copy($0) }
        defer {
            PickedFiles.discard(copy)
            if let key { PickedFiles.discard(key) }
        }
        do {
            if Self.authenticators.contains(source) {
                let found = try await model.vault.reviewImport(source: source, path: copy.url.path, password: password.isEmpty ? nil : password, keyFilePath: key?.url.path)
                self.file = nil
                password = ""
                // A file without codes has nothing to review.
                if found.codes.isEmpty {
                    result = try await model.vault.finishImport(reviewId: found.id, links: [])
                } else {
                    review = found
                }
                return
            }
            result = try await model.vault.importFile(source: source, path: copy.url.path, password: password.isEmpty ? nil : password, keyFilePath: key?.url.path)
            self.file = nil
            password = ""
            needsPassword = false
            Haptics.success()
        } catch {
            if error.isVault(.importPasswordRequired) { needsPassword = true }
            self.error = error.message
            Haptics.error()
        }
    }
}

private struct ReviewRoute: Hashable, Identifiable {
    let review: ImportReview
    var id: String { review.id }
}

/// Settings → Account → Delete account: what goes, export first, then the email and the master
/// password.
struct DeleteAccountSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var summary: AccountSummary?
    @State private var confirming = false
    @State private var email = ""
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false
    @State private var exporting = false

    var body: some View {
        NavigationStack {
            Form {
                if let summary {
                    if !confirming {
                        Section {
                            Text(L10n.deleteAccount.intro)
                            Label("\(L10n.deleteAccount.items(count: Int(summary.itemCount))) \(L10n.deleteAccount.vaults(count: Int(summary.vaultCount)))", systemImage: "key")
                            Label(L10n.deleteAccount.devices(count: Int(summary.deviceCount)), systemImage: "iphone")
                            Label(L10n.deleteAccount.emailFreed(email: summary.email), systemImage: "envelope")
                        }
                        if !summary.sharedVaultsOwned.isEmpty {
                            Section { Notice(text: L10n.deleteAccount.sharedVaults(vaults: summary.sharedVaultsOwned.joined(separator: ", "), count: summary.sharedVaultsOwned.count), tone: .warn) }
                        }
                        Section {
                            Notice(text: L10n.deleteAccount.permanent)
                            Text(L10n.deleteAccount.exportFirst).font(.footnote)
                            Button { exporting = true } label: { Label(L10n.settings.exportVault, systemImage: "square.and.arrow.up") }
                        }
                        Section {
                            Button(L10n.deleteAccount.keep) { dismiss() }
                            Button(L10n.deleteAccount.continue, role: .destructive) { confirming = true }
                                .accessibilityIdentifier("delete-continue")
                        }
                    } else {
                        Section {
                            Text(L10n.deleteAccount.confirmIntro)
                            TextField(L10n.deleteAccount.typeEmail(email: summary.email), text: $email)
                                .keyboardType(.emailAddress)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .accessibilityIdentifier("delete-email")
                            if !email.isEmpty, normalizeEmail(email: email) != summary.email, normalizeEmail(email: email).count >= summary.email.count {
                                Text(L10n.errors.emailMismatch).font(.footnote).foregroundStyle(Color.dangerText)
                            }
                            SecureField(L10n.fields.masterPassword, text: $password)
                                .accessibilityIdentifier("delete-password")
                            if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
                            Button(role: .destructive) {
                                Task { await delete(summary) }
                            } label: {
                                HStack { Text(L10n.deleteAccount.confirm); if busy { Spacer(); ProgressView() } }
                            }
                            .disabled(busy || normalizeEmail(email: email) != summary.email || password.isEmpty)
                            .accessibilityIdentifier("delete-confirm")
                        }
                    }
                } else {
                    ProgressView().frame(maxWidth: .infinity)
                }
            }
            .navigationTitle(L10n.deleteAccount.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() }.disabled(busy) }
            }
            .sheet(isPresented: $exporting) { ExportSheet() }
        }
        .interactiveDismissDisabled(busy)
        .task {
            do { summary = try await model.vault.accountSummary() } catch { self.error = error.message }
        }
    }

    private func delete(_ summary: AccountSummary) async {
        busy = true
        error = nil
        do {
            try await model.vault.deleteAccount(confirmEmail: email, password: password)
            UserDefaults.standard.removePersistentDomain(forName: Bundle.main.bundleIdentifier ?? "")
            model.accountDeleted = true
        } catch {
            self.error = error.message
            password = ""
            busy = false
        }
    }
}
