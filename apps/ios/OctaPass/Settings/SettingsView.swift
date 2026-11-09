import OctaPassResources
import OctaPassVault
import SwiftUI

/// Settings (the web vault's `SettingsPage`): appearance and language, security, AutoFill,
/// equivalent domains, two-step sign-in, devices, export, import, other password managers, and the
/// account. Every preference is this phone's own (`settings.json` next to the vault).
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var exporting = false
    @State private var deleting = false
    @State private var secretKey: String?
    /// Loaded here, not in the device unlock row: a row that shows nothing has no view for its
    /// `.task` to run on, so it never loaded and never showed.
    @State private var unlockMethods: UnlockMethods?

    var body: some View {
        List {
            if model.isLocal { ThisDeviceSection() }
            appearance
            // On the Mac, what runs with the window closed and AutoFill come first: the Settings
            // window shows only the top of this list (apps/macos/OctaPassMac/MacSettings.swift).
            #if os(macOS)
            BackgroundSection()
            AutoFillSection()
            BrowserExtensionSection()
            SshAgentSection()
            #endif
            security
            DeviceAuthSection()
            #if os(iOS)
            AutoFillSection()
            #endif
            // The Mac's Wi-Fi reading comes in plan 19 phase 2.
            Section {
                NavigationLink { EquivalentDomainsView() } label: { Label(L10n.equivalent.title, systemImage: "link") }
                    .accessibilityIdentifier("settings-equivalent-domains")
            }
            #if os(iOS)
            WifiOffersSection()
            #endif
            NearbySettingsSection()
            if !model.isLocal {
                Section(L10n.settings.twoStep) {
                    NavigationLink { TwoStepSettingsView() } label: { Label(L10n.settings.twoStep, systemImage: "lock.shield") }
                        .accessibilityIdentifier("settings-two-step")
                    NavigationLink { DevicesView() } label: { Label(L10n.devices.title, systemImage: "iphone") }
                    NavigationLink { SecurityLogView() } label: { Label(L10n.settings.securityLog, systemImage: "clock.arrow.circlepath") }
                }
            }
            Section {
                Button { exporting = true } label: { Label(L10n.settings.exportVault, systemImage: "square.and.arrow.up") }
                    .accessibilityIdentifier("settings-export")
                NavigationLink { ImportView() } label: { Label(L10n.settings.import, systemImage: "square.and.arrow.down") }
                    .accessibilityIdentifier("settings-import")
            } header: {
                Text(L10n.settings.export)
            } footer: {
                Text(L10n.settings.exportHelp)
            }
            OtherAppsSection()
            if !model.isLocal { account }
            Section {
                Text(L10n.settings.about).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        .navigationTitle(L10n.settings.title)
        .task(id: model.session.status) { unlockMethods = try? await model.vault.unlockMethods() }
        .sheet(isPresented: $exporting) { ExportSheet() }
        .sheet(isPresented: $deleting) { DeleteAccountSheet() }
    }

    private var appearance: some View {
        Section(L10n.settings.appearance) {
            Picker(L10n.settings.theme, selection: Binding(get: { model.settings.theme }, set: { theme in model.update { $0.theme = theme } })) {
                Text(L10n.settings.themeSystem).tag(ThemePreference.system)
                Text(L10n.settings.themeLight).tag(ThemePreference.light)
                Text(L10n.settings.themeDark).tag(ThemePreference.dark)
            }
            Picker(L10n.settings.language, selection: Binding(get: { model.settings.language }, set: { language in model.update { $0.language = language } })) {
                Text(L10n.settings.languageSystem).tag(LanguagePreference.system)
                // Each language's name in that language.
                Text("English").tag(LanguagePreference.en)
                Text("العربية").tag(LanguagePreference.ar)
            }
            .accessibilityIdentifier("settings-language")
            Toggle(isOn: Binding(get: { model.settings.showSiteIcons }, set: { on in model.update { $0.showSiteIcons = on } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.settings.siteIcons)
                    Text(L10n.settings.siteIconsHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
        }
    }

    private var security: some View {
        Section(L10n.settings.security) {
            // Neither applies while stay unlocked is on (plan 18): there's no timer and no lock in
            // the background. Shown, greyed out, so turning it off brings back what's there.
            Picker(selection: Binding(get: { model.settings.autoLockMinutes }, set: { minutes in model.update { $0.autoLockMinutes = minutes } })) {
                ForEach([UInt32(1), 5, 15, 30, 60, 240, 0], id: \.self) { minutes in
                    Text(Self.autoLock(minutes)).tag(minutes)
                }
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.settings.autoLock)
                    Text(L10n.settings.autoLockHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .disabled(model.staysUnlocked)
            .accessibilityIdentifier("settings-auto-lock")
            Toggle(isOn: Binding(get: { model.settings.lockOnBackground }, set: { on in model.update { $0.lockOnBackground = on } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.settings.lockOnHide)
                    Text(L10n.settings.lockOnHideHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .disabled(model.staysUnlocked)
            .accessibilityIdentifier("settings-lock-on-background")
            DeviceUnlockToggle(methods: $unlockMethods)
            WatchCodesToggle()
            NavigationLink { ChangePasswordView() } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Label(L10n.fields.masterPassword, systemImage: "key.horizontal")
                    // It talks of every device and the Secret Key; a local vault has neither.
                    if !model.isLocal {
                        Text(L10n.changePassword.rowHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
            }
            .accessibilityIdentifier("settings-change-password")
            Button { model.lockNow() } label: { Label(L10n.settings.lockNow, systemImage: "lock") }
            if !model.isLocal {
                if let secretKey {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(L10n.fields.secretKey).font(.caption).foregroundStyle(Color.mist)
                            Text(secretKey).font(.secret(.footnote)).textSelection(.enabled).environment(\.layoutDirection, .leftToRight)
                        }
                        Spacer()
                        CopyButton(value: secretKey, what: L10n.fields.secretKey, secret: true, gate: .always)
                        Button { self.secretKey = nil } label: { Image(systemName: "eye.slash") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.common.hideWhat(what: L10n.fields.secretKey))
                    }
                } else {
                    Button {
                        Task {
                            guard await model.confirmIdentity() else { return }
                            do { secretKey = try await model.vault.secretKey() } catch { model.show(error) }
                        }
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Label(L10n.fields.secretKey, systemImage: "key")
                            Text(L10n.settings.secretKeyHelp).font(.footnote).foregroundStyle(Color.mist)
                        }
                    }
                }
            }
            // Both need the server: a vault on this device only has neither.
            if !model.isLocal {
                NavigationLink { RotateSecretKeyView() } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(L10n.rotateSecretKey.row, systemImage: "arrow.triangle.2.circlepath")
                        Text(L10n.rotateSecretKey.rowHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .accessibilityIdentifier("settings-rotate-secret-key")
                NavigationLink { VaultKeysView() } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(L10n.vaultKeys.row, systemImage: "lock.rotation")
                        Text(L10n.vaultKeys.rowHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .accessibilityIdentifier("settings-vault-keys")
            }
        }
        .onDisappear { secretKey = nil }
        // A key shown before it was replaced no longer works.
        .onChange(of: model.newKit == nil) { secretKey = nil }
    }

    static func autoLock(_ minutes: UInt32) -> String {
        if minutes == 0 { return L10n.settings.autoLockNever }
        if minutes >= 60 { return L10n.settings.hours(count: Int(minutes / 60)) }
        return L10n.settings.minutes(count: Int(minutes))
    }

    private var account: some View {
        Section(L10n.settings.account) {
            if let email = model.session.email {
                LabeledContent(L10n.fields.email) { Text(email).environment(\.layoutDirection, .leftToRight) }
            }
            ServerRow()
            StorageRow()
            Button {
                Task {
                    do { try await model.vault.signOut() } catch { model.show(error) }
                }
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Label(L10n.settings.signOut, systemImage: "rectangle.portrait.and.arrow.right")
                    Text(L10n.settings.signOutHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .accessibilityIdentifier("settings-sign-out")
            Button(role: .destructive) { deleting = true } label: {
                Label(L10n.settings.deleteAccount, systemImage: "trash")
            }
            .accessibilityIdentifier("settings-delete-account")
        }
    }
}

/// Sites that share one sign-in (the web vault's `EquivalentDomainsSection`). The list is an
/// encrypted vault item, so it follows the account; what a domain may be (never a public suffix
/// like `co.uk`) is decided by the vault when saving.
struct EquivalentDomainsView: View {
    @Environment(AppModel.self) private var model
    @State private var list: EquivalentDomains?
    @State private var rows: [String] = []
    @State private var rejected: [String] = []
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        List {
            Section { Text(L10n.equivalent.help).font(.subheadline).foregroundStyle(Color.mist) }
            if let list {
                groups
                if !list.defaults.isEmpty { builtIn(list) }
            } else if let error {
                Section { Notice(text: error) }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
        .navigationTitle(L10n.equivalent.title)
        .navigationBarTitleDisplayMode(.inline)
        .task { await load() }
    }

    private var groups: some View {
        Section {
            ForEach(rows.indices, id: \.self) { index in
                HStack {
                    EditorField(label: L10n.equivalent.group(n: index + 1), text: $rows[index], placeholder: "example.com, example.org",
                                keyboard: .asciiCapable, mono: true, ltr: true)
                        .accessibilityIdentifier("equivalent-group-\(index)")
                    Button(role: .destructive) { rows.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(L10n.equivalent.removeGroup(n: index + 1))
                }
            }
            Button { rows.append("") } label: { Label(L10n.equivalent.addGroup, systemImage: "plus") }
                .accessibilityIdentifier("equivalent-add")
            Button {
                Task { await save() }
            } label: {
                HStack { Text(L10n.common.save); if busy { Spacer(); ProgressView() } }
            }
            .disabled(busy)
            .accessibilityIdentifier("equivalent-save")
            if !rejected.isEmpty {
                Text(L10n.equivalent.rejected(domains: rejected.joined(separator: ", ")))
                    .font(.footnote)
                    .foregroundStyle(Color.dangerText)
                    .accessibilityIdentifier("equivalent-rejected")
            }
        }
    }

    /// The built-in groups: on unless turned off, saved straight away.
    private func builtIn(_ list: EquivalentDomains) -> some View {
        Section {
            ForEach(list.defaults, id: \.self) { group in
                let name = group.first ?? ""
                Toggle(isOn: Binding(
                    get: { !list.excludedDefaults.contains(name) },
                    set: { on in
                        let excluded = on ? list.excludedDefaults.filter { $0 != name } : list.excludedDefaults + [name]
                        Task { await save(excluded: excluded) }
                    })) {
                    Text(group.prefix(3).joined(separator: ", ") + (group.count > 3 ? " …" : ""))
                        .environment(\.layoutDirection, .leftToRight)
                }
                .disabled(busy)
                .accessibilityIdentifier("equivalent-default-\(name)")
            }
        }
    }

    private func load() async {
        guard list == nil else { return }
        do {
            show(try await model.vault.equivalentDomains())
            error = nil
        } catch {
            self.error = error.message
        }
    }

    private func save(excluded: [String]? = nil) async {
        guard let list else { return }
        busy = true
        defer { busy = false }
        let groups = rows.map { $0.split { $0 == "," || $0.isWhitespace }.map(String.init) }
        do {
            let saved = try await model.vault.saveEquivalentDomains(groups: groups, excludedDefaults: excluded ?? list.excludedDefaults)
            show(saved)
            rejected = saved.rejected
            model.confirm(L10n.equivalent.saved)
        } catch {
            model.show(error)
        }
    }

    private func show(_ next: EquivalentDomains) {
        list = next
        rows = next.groups.map { $0.joined(separator: ", ") }
    }
}

/// Stay unlocked (plan 18) and the two gates (plan 03), this phone only: asking when the app opens,
/// and asking on every fill (the AutoFill extension), with its warning while it's off. With no
/// lock Octa Pass can use there's nothing to ask with: opening and filling don't ask while the
/// vault stays unlocked, and this says so. The gates apply only with stay unlocked off: they're
/// shown under the switch, greyed out while it's on.
private struct DeviceAuthSection: View {
    @Environment(AppModel.self) private var model
    @State private var methods: UnlockMethods?
    @State private var status: StayUnlockedStatus?

    var body: some View {
        let lockless = methods.map { !$0.deviceUnlockEnabled } ?? false
        let staysUnlocked = model.staysUnlocked
        Section {
            stayUnlocked
            Toggle(isOn: Binding(get: { model.settings.deviceAuthOnOpen }, set: { on in model.update { $0.deviceAuthOnOpen = on } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.deviceAuth.appOpen)
                    Text(L10n.deviceAuth.appOpenHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .disabled(lockless || staysUnlocked)
            // `.disabled` greys the switch but not text with its own colour: dim the whole row.
            .opacity(lockless || staysUnlocked ? 0.5 : 1)
            .accessibilityIdentifier("settings-device-auth-open")
            Toggle(isOn: Binding(get: { model.settings.deviceAuthOnAutofill }, set: { on in model.update { $0.deviceAuthOnAutofill = on } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.deviceAuth.autofill)
                    Text(L10n.deviceAuth.autofillHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .disabled(lockless || staysUnlocked)
            .opacity(lockless || staysUnlocked ? 0.5 : 1)
            .accessibilityIdentifier("settings-device-auth-autofill")
            if !staysUnlocked && !model.settings.deviceAuthOnAutofill {
                Notice(text: L10n.deviceAuth.autofillOff, tone: .warn)
                    .accessibilityIdentifier("settings-device-auth-autofill-off")
            }
            if !staysUnlocked {
                Text(L10n.deviceAuth.revealHelp).font(.footnote).foregroundStyle(Color.mist)
                if lockless { Notice(text: L10n.deviceAuth.lockless, tone: .info) }
            }
        } header: {
            Text(L10n.deviceAuth.title)
        } footer: {
            if staysUnlocked { Text(L10n.deviceAuth.stayUnlockedGates).accessibilityIdentifier("settings-stay-unlocked-gates") }
        }
        .task(id: "\(model.itemsVersion)/\(model.settings.stayUnlocked)/\(model.session.status)") { await load() }
    }

    @ViewBuilder
    private var stayUnlocked: some View {
        let available = status?.available ?? true
        Toggle(isOn: Binding(get: { model.settings.stayUnlocked && available }, set: { on in model.update { $0.stayUnlocked = on } })) {
            Text(L10n.deviceAuth.stayUnlocked)
        }
        .disabled(!available)
        .accessibilityIdentifier("settings-stay-unlocked")
        if !available {
            Notice(text: DeviceWords.noDeviceLock, tone: .info)
                .accessibilityIdentifier("settings-stay-unlocked-no-passcode")
        } else if model.settings.stayUnlocked {
            // What "Confirm it's you" asks for: the device lock where device unlock is on, the master password otherwise.
            let method = methods?.deviceUnlockEnabled == false ? L10n.deviceAuth.stayUnlockedPassword : DeviceLockName.offer(methods?.label ?? "")
            Text(L10n.deviceAuth.stayUnlockedOn(method: method))
                .font(.footnote)
                .foregroundStyle(Color.mist)
                .accessibilityIdentifier("settings-stay-unlocked-on")
            if status?.passwordRequired == true {
                Notice(text: L10n.deviceAuth.stayUnlockedPasswordDue, tone: .info)
                    .accessibilityIdentifier("settings-stay-unlocked-password-due")
            }
        }
    }

    private func load() async {
        methods = try? await model.vault.unlockMethods()
        let vault = model.vault
        status = await Task.detached { vault.stayUnlockedStatus() }.value
    }
}

/// Unlock with Face ID / Touch ID or the passcode, for this phone only.
/// Device unlock as each platform says it: a phone's passcode, Face ID and Touch ID; a Mac's
/// Touch ID and password.
private enum DeviceWords {
    static var noDeviceLock: String {
        #if os(macOS)
        L10n.deviceAuth.stayUnlockedNoScreenLock
        #else
        L10n.deviceAuth.stayUnlockedNoPasscode
        #endif
    }

    static var unlockHelp: String {
        #if os(macOS)
        L10n.unlock.help.mac
        #else
        L10n.unlock.help.ios
        #endif
    }
}

private struct DeviceUnlockToggle: View {
    @Environment(AppModel.self) private var model
    @Binding var methods: UnlockMethods?
    @State private var busy = false

    var body: some View {
        Group {
            if let methods, methods.deviceUnlockSupported {
                let name = DeviceLockName.name(methods.label)
                Toggle(isOn: Binding(get: { methods.deviceUnlockEnabled }, set: { on in Task { await set(on, name: name) } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(L10n.unlock.settingTitle(method: name))
                        Text(methods.deviceUnlockEnabled ? L10n.unlock.onHelp : DeviceWords.unlockHelp).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
                .disabled(busy)
                .accessibilityIdentifier("settings-device-unlock")
            }
        }
    }

    private func set(_ on: Bool, name: String) async {
        busy = true
        defer { busy = false }
        do {
            if on { try await model.vault.enableDeviceUnlock() } else { try await model.vault.disableDeviceUnlock() }
            methods = try? await model.vault.unlockMethods()
            model.confirm(on ? L10n.unlockOffer.enabled(method: name) : L10n.unlock.disabled(method: name))
        } catch {
            if !error.isVault(.deviceUnlockCancelled) { model.show(error) }
        }
    }
}

/// Codes on the Apple Watch: off until asked for, and turning it on is a reveal, so it confirms
/// it's the owner first. This phone's choice, never synced.
private struct WatchCodesToggle: View {
    @Environment(AppModel.self) private var model
    @State private var confirming = false

    var body: some View {
        if WatchCodesLink.isSupported {
            Toggle(isOn: Binding(get: { model.settings.showCodesOnWatch }, set: { on in
                if on { confirming = true } else { model.update { $0.showCodesOnWatch = false } }
            })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.phone.native.watchCodes)
                    Text(L10n.phone.native.watchCodesHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .accessibilityIdentifier("settings-watch-codes")
            .sheet(isPresented: $confirming) {
                ConfirmItsYou(note: L10n.phone.native.watchConfirmBody) {
                    confirming = false
                    model.update { $0.showCodesOnWatch = true }
                }
                .padding()
                .presentationDetents([.medium, .large])
            }
        }
    }
}

/// Settings → AutoFill: on or off, and the button that turns Octa Pass on (iOS 18 asks in place).
private struct AutoFillSection: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var enabled: Bool?
    @State private var busy = false

    var body: some View {
        Section {
            HStack {
                Text(L10n.phone.autoFill)
                Spacer()
                Text(enabled == true ? L10n.phone.autoFillOn : L10n.phone.autoFillOff)
                    .foregroundStyle(enabled == true ? Color.freeText : Color.mist)
            }
            if enabled == false {
                Button {
                    Task {
                        busy = true
                        enabled = await AutoFillSettings.turnOn()
                        busy = false
                    }
                } label: {
                    Label(AutoFillSettings.canAsk ? L10n.phone.autoFillTurnOn : L10n.phone.autoFillSettings, systemImage: "key.fill")
                }
                .disabled(busy)
                .accessibilityIdentifier("autofill-turn-on")
            }
            Button {
                Task { await AutoFillSettings.openCodeSettings() }
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.phone.autoFillCodes)
                    Text(L10n.phone.autoFillCodesHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
        } header: {
            Text(L10n.phone.autoFill)
        } footer: {
            Text(L10n.phone.autoFillHelp)
        }
        .task(id: scenePhase) { enabled = await AutoFillSettings.isEnabled() }
    }
}

private struct ServerRow: View {
    @Environment(AppModel.self) private var model
    @State private var info: ServerInfo?
    @State private var failed = false

    var body: some View {
        let url = model.session.serverUrl ?? ""
        VStack(alignment: .leading, spacing: 2) {
            Text(L10n.settings.server)
            Text(info.map { L10n.settings.serverInfo(name: $0.name, url: url, version: $0.version) } ?? (failed ? L10n.settings.serverUnreachable(url: url) : url))
                .font(.footnote)
                .foregroundStyle(Color.mist)
        }
        .task {
            do { info = try await model.vault.serverInfo(serverUrl: url) } catch { failed = true }
        }
    }
}

private struct StorageRow: View {
    @Environment(AppModel.self) private var model
    @State private var usage: StorageUsage?
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.settings.storage)
            if let usage {
                ProgressView(value: Double(usage.attachmentBytes), total: Double(max(usage.maxAttachmentBytes, 1)))
                Text("\(L10n.settings.storageUsed(used: Self.size(usage.attachmentBytes), total: Self.size(usage.maxAttachmentBytes))) · \(L10n.settings.storageFileLimit(size: Self.size(usage.maxFileBytes)))")
                    .font(.footnote).foregroundStyle(Color.mist)
                Text(L10n.settings.storageHelp).font(.footnote).foregroundStyle(Color.mist)
            } else if failed {
                Text(L10n.settings.storageFailed).font(.footnote).foregroundStyle(Color.mist)
            }
        }
        .task {
            do { usage = try await model.vault.storageUsage() } catch { failed = true }
        }
    }

    static func size(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}
