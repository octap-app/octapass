import OctaPassResources
import OctaPassVault
import SwiftUI

/// The security dashboard, loaded once per unlock and on Check again. The vault builds it
/// (weak, reused and breached passwords, missing two-step sign-in, the recovery map); only the
/// first five characters of each password's SHA-1 hash leave the phone. Email breach alerts are
/// the one exception and are off until the user turns them on.
@MainActor @Observable
final class HealthStore {
    static let shared = HealthStore()
    private(set) var report: HealthReport?
    private(set) var loading = false
    private(set) var error: Error?
    /// Dismissed since the last report, so a row leaves at once.
    private(set) var hidden: Set<String> = []
    private(set) var emailCheck: EmailBreachCheck?
    private(set) var emailChecksAvailable = false
    private var askedAboutEmails = false

    func load(_ vault: OctaPassVault, again: Bool = false) async {
        guard !loading, again || report == nil else { return }
        loading = true
        defer { loading = false }
        do {
            report = try await vault.healthReport()
            hidden = []
            error = nil
        } catch {
            self.error = error
        }
        emailChecksAvailable = (try? await vault.emailBreachChecksAvailable()) ?? false
        // Sends nothing unless alerts are on and a day has passed.
        if report?.emailAlertsEnabled == true, !askedAboutEmails {
            askedAboutEmails = true
            await checkEmails(vault, force: false)
        }
    }

    func isShown(_ entry: HealthEntry) -> Bool {
        guard let warning = entry.warning else { return true }
        return !hidden.contains(warning)
    }

    func dismiss(_ warnings: [String], vault: OctaPassVault) async {
        hidden.formUnion(warnings)
        do {
            try await vault.dismissHealthWarnings(warnings: warnings)
        } catch {
            hidden.subtract(warnings)
            self.error = error
        }
    }

    func restore(_ warnings: [String], vault: OctaPassVault) async {
        try? await vault.restoreHealthWarnings(warnings: warnings)
        await load(vault, again: true)
    }

    func setEmailAlerts(_ enabled: Bool, vault: OctaPassVault) async {
        try? await vault.setEmailBreachAlerts(enabled: enabled)
        if enabled { await checkEmails(vault, force: true) } else { emailCheck = nil }
        await load(vault, again: true)
    }

    func checkEmails(_ vault: OctaPassVault, force: Bool) async {
        let result = try? await vault.checkEmailBreaches(force: force)
        emailCheck = result ?? .failed
        if result == .checked { await load(vault, again: true) }
    }

    func clear() {
        report = nil
        error = nil
        hidden = []
        emailCheck = nil
        askedAboutEmails = false
    }
}

struct HealthView: View {
    @Environment(AppModel.self) private var model
    @State private var store = HealthStore.shared

    var body: some View {
        Group {
            if let report = store.report {
                HealthReportList(report: report)
            } else if let error = store.error {
                EmptyStateView(icon: "exclamationmark.triangle", title: L10n.health.title, message: error.message) {
                    Button(L10n.common.tryAgain) { Task { await store.load(model.vault, again: true) } }
                }
            } else {
                VStack(spacing: 12) {
                    ProgressView()
                    Text(L10n.health.checking).foregroundStyle(Color.mist)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(L10n.health.title)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await store.load(model.vault, again: true) }
                } label: {
                    if store.loading, store.report != nil { ProgressView() } else { Label(L10n.health.recheck, systemImage: "arrow.clockwise") }
                }
                .disabled(store.loading)
            }
        }
        .task { await store.load(model.vault) }
        // After edits, and for what changed elsewhere.
        .task(id: model.itemsVersion) {
            if store.report != nil { await store.load(model.vault, again: true) }
        }
        .refreshable { await store.load(model.vault, again: true) }
    }
}

/// One of Health's checks, with its page. The first five always have a row on Health; the rest get
/// one when they find something. `dismissed` isn't one of those rows: Health links to it below them.
enum HealthCheck: String, CaseIterable, Identifiable {
    case weak, reused, breached, twoStep, recoveryEmails, insecure, old, passkeys, expiring, backupCodes, emailBreaches, dismissed

    var id: String { rawValue }

    var title: String {
        switch self {
        case .weak: L10n.health.weak
        case .reused: L10n.health.reused
        case .breached: L10n.health.breached
        case .twoStep: L10n.health.missing2fa
        case .recoveryEmails: L10n.health.recoveryNo2fa
        case .insecure: L10n.health.insecureUrls
        case .old: L10n.health.old
        case .passkeys: L10n.health.passkeyAvailable
        case .expiring: L10n.health.expiring
        case .backupCodes: L10n.health.backupCodes
        case .emailBreaches: L10n.health.email.title
        case .dismissed: L10n.health.dismissedTitle
        }
    }

    var help: String {
        switch self {
        case .weak: L10n.health.weakHelp
        case .reused: L10n.health.reusedHelp
        case .breached: L10n.health.breachedHelp
        case .twoStep: L10n.health.missing2faHelp
        case .recoveryEmails: L10n.health.recoveryNo2faHelp
        case .insecure: L10n.health.insecureUrlsHelp
        case .old: L10n.health.oldHelp
        case .passkeys: L10n.health.passkeyAvailableHelp
        case .expiring: L10n.health.expiringHelp
        case .backupCodes: L10n.health.backupCodesHelp
        case .emailBreaches: L10n.health.email.help
        case .dismissed: L10n.health.dismissedHelp
        }
    }

    var icon: String {
        switch self {
        case .weak: "exclamationmark.triangle"
        case .reused: "doc.on.doc"
        case .breached: "shield.lefthalf.filled"
        case .twoStep: "clock"
        case .recoveryEmails: "envelope"
        case .insecure: "lock.open"
        case .old: "calendar"
        case .passkeys: "person.badge.key"
        case .expiring: "creditcard"
        case .backupCodes: "key"
        case .emailBreaches: "at"
        case .dismissed: "eye.slash"
        }
    }

    var always: Bool { [.weak, .reused, .breached, .twoStep, .recoveryEmails].contains(self) }

    /// What the check found, less what was dismissed since the report was made.
    @MainActor
    func count(_ report: HealthReport, _ store: HealthStore) -> Int {
        switch self {
        case .weak: report.weak.filter { store.isShown($0.entry) }.count
        case .reused: report.reused.reduce(0) { $0 + $1.filter(store.isShown).count }
        case .breached: report.breached.filter { store.isShown($0.entry) }.count
        case .twoStep: report.missing2fa.filter(store.isShown).count
        case .recoveryEmails: report.recoveryNo2fa.filter { store.isShown($0.entry) }.count
        case .insecure: report.insecureUrls.filter { store.isShown($0.entry) }.count
        case .old: report.old.filter { store.isShown($0.entry) }.count
        case .passkeys: report.passkeyAvailable.filter(store.isShown).count
        case .expiring: report.expiring.filter { store.isShown($0.entry) }.count
        case .backupCodes: report.lowBackupCodes.filter { store.isShown($0.entry) }.count
        case .emailBreaches: report.emailBreaches.filter { !store.hidden.contains($0.warning) }.count
        case .dismissed: report.dismissed.count
        }
    }
}

/// Health's overview: the score, then a row per check that opens its list.
private struct HealthReportList: View {
    @Environment(AppModel.self) private var model
    @State private var store = HealthStore.shared
    let report: HealthReport

    var body: some View {
        List {
            Section {
                HStack(spacing: 18) {
                    ScoreRing(score: Int(report.score), size: 104)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(Self.verdict(Int(report.score))).font(.title3.weight(.bold))
                        Text(L10n.health.summary(count: Int(report.checked))).font(.subheadline).foregroundStyle(Color.mist)
                        Text(L10n.health.checkedAt(date: Dates.long(report.generatedAt))).font(.caption).foregroundStyle(Color.mist)
                    }
                }
                .padding(.vertical, 8)
                if !report.breachCheckCompleted {
                    Notice(text: L10n.health.breachUnavailable, tone: .warn)
                }
                if report.emailBreaches.contains(where: \.isNew) {
                    Notice(text: L10n.health.email.newAlert, tone: .warn)
                }
                if model.isLocal, let vault = model.currentLocalVault {
                    Label(
                        vault.lastBackupAt.map { L10n.localVault.lastBackupHealth(date: Dates.long($0)) } ?? L10n.localVault.neverBackedUp,
                        systemImage: "clock.arrow.circlepath")
                        .font(.subheadline)
                        .foregroundStyle(Color.mist)
                        .accessibilityIdentifier("health-last-backup")
                }
            }
            Section(L10n.health.checks) {
                ForEach(HealthCheck.allCases.filter { $0 != .dismissed }) { check in
                    let count = check.count(report, store)
                    if check == .emailBreaches {
                        // Its page is where the switch is, so the row shows whenever the switch would.
                        if report.emailAlertsEnabled || store.emailChecksAvailable || count > 0 {
                            checkRow(check, value: report.emailAlertsEnabled ? Self.number(count) : L10n.health.email.offTile, clear: report.emailAlertsEnabled && count == 0, off: !report.emailAlertsEnabled)
                        }
                    } else if check.always || count > 0 {
                        checkRow(check, value: Self.number(count), clear: count == 0)
                    }
                }
            }
            Section {
                RouteLink(route: .recoveryMap) {
                    Label(L10n.health.viewRecoveryMap, systemImage: "point.3.connected.trianglepath.dotted")
                }
                .accessibilityIdentifier("recovery-map")
                if !report.dismissed.isEmpty {
                    RouteLink(route: .healthCheck(.dismissed)) {
                        Label(L10n.health.dismissedCount(count: report.dismissed.count), systemImage: HealthCheck.dismissed.icon)
                    }
                    .accessibilityIdentifier("health-dismissed")
                }
            }
        }
    }

    /// A check and its count; opens the check's list.
    private func checkRow(_ check: HealthCheck, value: String, clear: Bool, off: Bool = false) -> some View {
        RouteLink(route: .healthCheck(check)) {
            HStack {
                Label(check.title, systemImage: clear ? "checkmark.circle" : check.icon)
                    .foregroundStyle(clear ? Color.freeText : off ? Color.mist : Color.ink)
                Spacer()
                Text(value).font(.headline.monospacedDigit()).foregroundStyle(off ? Color.mist : Color.ink)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("health-\(check.rawValue)")
    }

    static func number(_ count: Int) -> String { count.formatted(.number.locale(L10n.formatLocale)) }

    static func verdict(_ score: Int) -> String {
        score >= 90 ? L10n.health.verdict.great : score >= 70 ? L10n.health.verdict.good : score >= 50 ? L10n.health.verdict.fair : L10n.health.verdict.poor
    }
}

/// One check's list, opened from its row on Health. It reads the shared report, so a dismissal
/// shows on Health too.
struct HealthCheckView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @State private var store = HealthStore.shared
    @State private var changing: HealthEntry?
    @State private var confirmingAlerts = false
    let check: HealthCheck

    var body: some View {
        Group {
            if let report = store.report {
                List {
                    Section {
                        Text(help(report)).font(.subheadline).foregroundStyle(Color.mist)
                    }
                    content(report)
                }
            } else {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(check.title)
        .task { await store.load(model.vault) }
        .task(id: model.itemsVersion) {
            if store.report != nil { await store.load(model.vault, again: true) }
        }
        .refreshable { await store.load(model.vault, again: true) }
        .sheet(item: $changing) { entry in
            GeneratorSheet { password in
                Task {
                    do {
                        try await model.vault.updatePassword(itemId: entry.itemId, password: password)
                        await store.load(model.vault, again: true)
                    } catch {
                        // The sheet is gone; Health shows the error in place of the report.
                        await store.load(model.vault, again: true)
                    }
                }
            }
        }
    }

    private func help(_ report: HealthReport) -> String {
        check == .recoveryEmails ? "\(check.help) \(L10n.health.recoveryMapSummary(count: report.recovery.count))" : check.help
    }

    @ViewBuilder
    private func content(_ report: HealthReport) -> some View {
        switch check {
        case .weak:
            let entries = report.weak.filter { store.isShown($0.entry) }
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.entry.itemId) { row($0.entry, tag: StrengthMeter.label($0.score), tone: .danger, changes: true) }
            }
        case .reused:
            let groups = report.reused.filter { $0.contains(where: store.isShown) }
            if groups.isEmpty {
                rows(empty: true) { EmptyView() }
            } else {
                ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                    Section {
                        ForEach(group, id: \.itemId) { row($0, changes: true, dismissible: false) }
                    } header: {
                        HStack {
                            Text(L10n.health.reuseGroup(count: group.count))
                            Spacer()
                            Button(L10n.health.dismissGroup) { dismiss(group) }.font(.footnote).buttonStyle(.borderless)
                        }
                        .textCase(nil)
                    }
                }
            }
        case .breached:
            if !report.breachCheckCompleted {
                Section { Notice(text: L10n.health.breachUnavailable, tone: .warn) }
            }
            let entries = report.breached.filter { store.isShown($0.entry) }
            if report.breachCheckCompleted || !entries.isEmpty {
                rows(empty: entries.isEmpty) {
                    ForEach(entries, id: \.entry.itemId) { row($0.entry, tag: L10n.health.seenTimes(count: Int($0.count)), tone: .danger, changes: true) }
                }
            }
        case .twoStep:
            let entries = report.missing2fa.filter(store.isShown)
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.itemId) { row($0, tag: L10n.health.supports2fa, tone: .warn) }
            }
        case .recoveryEmails:
            let entries = report.recoveryNo2fa.filter { store.isShown($0.entry) }
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.entry.itemId) { row($0.entry, subtitle: $0.email, tag: L10n.health.recoveryResets(count: Int($0.accounts)), tone: .warn) }
            }
            Section {
                NavigationLink(value: Route.recoveryMap) {
                    Label(L10n.health.viewRecoveryMap, systemImage: "point.3.connected.trianglepath.dotted")
                }
            }
        case .insecure:
            let entries = report.insecureUrls.filter { store.isShown($0.entry) }
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.entry.itemId) { row($0.entry, subtitle: $0.url, tag: "http://", tone: .warn) }
            }
        case .old:
            let entries = report.old.filter { store.isShown($0.entry) }
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.entry.itemId) { row($0.entry, tag: L10n.health.changedOn(date: Dates.long($0.changedAt)), changes: true) }
            }
        case .passkeys:
            let entries = report.passkeyAvailable.filter(store.isShown)
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.itemId) { row($0, tag: L10n.health.supportsPasskeys) }
            }
        case .expiring:
            let entries = report.expiring.filter { store.isShown($0.entry) }
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.entry.itemId) { row($0.entry, tag: Self.expiryTag($0.daysLeft), tone: $0.daysLeft < 0 ? .danger : .warn) }
            }
        case .backupCodes:
            let entries = report.lowBackupCodes.filter { store.isShown($0.entry) }
            rows(empty: entries.isEmpty) {
                ForEach(entries, id: \.entry.itemId) { row($0.entry, tag: L10n.health.codesLeft(count: Int($0.unused)), tone: .warn) }
            }
        case .emailBreaches:
            emailAlerts(report)
        case .dismissed:
            rows(empty: report.dismissed.isEmpty) {
                ForEach(report.dismissed, id: \.warning) { item in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.entry.title).lineLimit(1)
                            Text(Self.checkLabel(item.check)).font(.subheadline).foregroundStyle(Color.mist)
                        }
                        Spacer()
                        Button(L10n.health.restore) {
                            Task { await store.restore([item.warning], vault: model.vault) }
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
        }
    }

    /// A check's rows, or "None found." once there's nothing left to fix.
    private func rows<Content: View>(empty: Bool, @ViewBuilder content: () -> Content) -> some View {
        Section {
            if empty {
                Label(L10n.health.noneFound, systemImage: "checkmark").foregroundStyle(Color.freeText)
            } else {
                content()
            }
        }
    }

    private func dismiss(_ entries: [HealthEntry]) {
        Task { await store.dismiss(entries.compactMap(\.warning), vault: model.vault) }
    }

    /// Opens the site's change-password page, then the generator to make and save the new one.
    private func change(_ entry: HealthEntry) {
        if let url = entry.changePasswordUrl.flatMap(URL.init(string:)) { openURL(url) }
        changing = entry
    }

    private func row(_ entry: HealthEntry, subtitle: String? = nil, tag: String? = nil, tone: Notice.Tone = .info, changes: Bool = false, dismissible: Bool = true) -> some View {
        HealthRow(entry: entry, subtitle: subtitle, tag: tag, tone: tone)
            .swipeActions(edge: .trailing) {
                if dismissible {
                    Button(L10n.health.dismiss) { dismiss([entry]) }
                }
            }
            .swipeActions(edge: .leading) {
                if changes {
                    Button(L10n.health.change.action) { change(entry) }.tint(.accentColor)
                }
            }
            .contextMenu {
                if changes { Button(L10n.health.change.action) { change(entry) } }
                if dismissible { Button(L10n.health.dismiss) { dismiss([entry]) } }
            }
    }

    /// Off by default. Turning it on sends addresses off the phone, so it asks first and says so.
    @ViewBuilder
    private func emailAlerts(_ report: HealthReport) -> some View {
        if !report.emailAlertsEnabled && !store.emailChecksAvailable {
            Section { Notice(text: L10n.health.email.unavailable, tone: .info) }
        } else {
            Section {
                Toggle(L10n.health.email.switch, isOn: Binding(
                    get: { report.emailAlertsEnabled },
                    set: { on in
                        if on { confirmingAlerts = true } else { Task { await store.setEmailAlerts(false, vault: model.vault) } }
                    }
                ))
                .accessibilityIdentifier("email-breach-alerts")
                if report.emailAlertsEnabled {
                    if store.emailCheck == .failed { Notice(text: L10n.health.email.failed, tone: .warn) }
                    Button(L10n.health.email.checkNow) { Task { await store.checkEmails(model.vault, force: true) } }
                    ForEach(report.emailBreaches.filter { !store.hidden.contains($0.warning) }, id: \.warning) { finding in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(finding.title).lineLimit(1)
                                if finding.isNew {
                                    Text(L10n.health.email.new).font(.caption.weight(.semibold)).foregroundStyle(Color.dangerText)
                                }
                            }
                            Text(finding.address).font(.subheadline).foregroundStyle(Color.mist).lineLimit(1)
                            if !finding.dataClasses.isEmpty {
                                Text(finding.dataClasses.joined(separator: ", ")).font(.footnote).foregroundStyle(Color.mist)
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            Button(L10n.health.dismiss) { Task { await store.dismiss([finding.warning], vault: model.vault) } }
                        }
                    }
                    if report.emailBreachesCheckedAt != nil, report.emailBreaches.isEmpty {
                        Label(L10n.health.email.none, systemImage: "checkmark").foregroundStyle(Color.freeText)
                    }
                }
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(report.emailAlertsEnabled ? L10n.health.email.onNote : L10n.health.email.offNote)
                    if report.emailAlertsEnabled {
                        Link("\(L10n.health.email.source) Have I Been Pwned", destination: URL(string: "https://haveibeenpwned.com")!)
                    }
                }
            }
            .alert(L10n.health.email.confirmTitle, isPresented: $confirmingAlerts) {
                Button(L10n.common.cancel, role: .cancel) {}
                Button(L10n.health.email.confirm) { Task { await store.setEmailAlerts(true, vault: model.vault) } }
            } message: {
                Text([L10n.health.email.sendsAddresses, L10n.health.email.sendsTo, L10n.health.email.aliasNote, L10n.health.email.notStored].joined(separator: "\n\n"))
            }
        }
    }

    static func expiryTag(_ daysLeft: Int32) -> String {
        daysLeft < 0 ? L10n.health.expired : daysLeft == 0 ? L10n.health.expiresToday : L10n.health.expiresIn(count: Int(daysLeft))
    }

    static func checkLabel(_ check: String) -> String {
        switch check {
        case "weak": L10n.health.weak
        case "reused": L10n.health.reused
        case "breached": L10n.health.breached
        case "old": L10n.health.old
        case "missing2fa": L10n.health.missing2fa
        case "passkeyAvailable": L10n.health.passkeyAvailable
        case "insecureUrl": L10n.health.insecureUrls
        case "expiring": L10n.health.expiring
        case "backupCodes": L10n.health.backupCodes
        case "recoveryNo2fa": L10n.health.recoveryNo2fa
        default: L10n.health.email.title
        }
    }
}

/// A login the report names; opens it.
struct HealthRow: View {
    let entry: HealthEntry
    var subtitle: String?
    var tag: String?
    var tone: Notice.Tone = .info

    var body: some View {
        NavigationLink(value: Route.item(entry.itemId)) {
            HStack(spacing: 12) {
                Avatar(name: entry.title)
                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.title).foregroundStyle(Color.ink).lineLimit(1)
                    if let subtitle = subtitle ?? entry.subtitle {
                        Text(subtitle).font(.subheadline).foregroundStyle(Color.mist).lineLimit(1)
                    }
                }
                Spacer()
                if let tag {
                    Text(tag)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(tone == .danger ? Color.dangerText : Color.warnText)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background((tone == .danger ? Color.danger : Color.warn).opacity(0.12), in: Capsule())
                }
            }
        }
    }
}

/// The score as a ring in the brand gradient.
struct ScoreRing: View {
    let score: Int
    var size: CGFloat = 104

    var body: some View {
        ZStack {
            Circle().stroke(Color.line, lineWidth: size * 0.08)
            Circle()
                .trim(from: 0, to: CGFloat(score) / 100)
                .stroke(LinearGradient.brand, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 0) {
                Text("\(score)").font(.system(size: size * 0.3, weight: .bold)).monospacedDigit()
                Text(L10n.health.outOf).font(.caption2).foregroundStyle(Color.mist)
            }
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(L10n.nav.health) \(score) \(L10n.health.outOf)")
    }
}

/// The recovery map as a route: Health's report when it has one, or one made for it.
struct RecoveryMapRoute: View {
    @Environment(AppModel.self) private var model
    @State private var store = HealthStore.shared
    @State private var own: HealthReport?

    var body: some View {
        Group {
            if let report = store.report ?? own { RecoveryMapView(report: report) } else { ProgressView() }
        }
        .task { if store.report == nil { own = try? await model.vault.healthReport() } }
    }
}

/// The recovery map (plan 01): which email or phone can reset which logins.
struct RecoveryMapView: View {
    let report: HealthReport

    var body: some View {
        List {
            if report.recovery.isEmpty {
                EmptyStateView(icon: "envelope", title: L10n.recoveryMap.empty, message: L10n.recoveryMap.emptyBody)
            } else {
                Section { Text(L10n.recoveryMap.help).font(.subheadline).foregroundStyle(Color.mist) }
                ForEach(report.recovery, id: \.value) { contact in
                    Section {
                        tags(contact)
                        ForEach(contact.logins, id: \.itemId) { HealthRow(entry: $0) }
                    } header: {
                        Label(L10n.recoveryMap.canReset(count: contact.logins.count, value: contact.value),
                              systemImage: contact.kind == .email ? "envelope" : "phone")
                            .textCase(nil)
                    }
                }
                Section { Notice(text: L10n.recoveryMap.breachGap, tone: .info) }
                    .listRowBackground(Color.clear)
            }
        }
        .navigationTitle(L10n.recoveryMap.title)
    }

    @ViewBuilder
    private func tags(_ contact: RecoveryContact) -> some View {
        if let provider = contact.aliasProvider {
            Text(L10n.recoveryMap.masked(provider: MaskedEmailNames.name(provider))).font(.footnote).foregroundStyle(Color.mist)
        } else if contact.kind == .email, let account = contact.account {
            NavigationLink(value: Route.item(account.entry.itemId)) {
                Text(account.twoStep ? L10n.recoveryMap.accountTwoStep : L10n.recoveryMap.accountNoTwoStep)
                    .font(.footnote)
                    .foregroundStyle(account.twoStep ? Color.freeText : Color.warnText)
            }
        } else if contact.kind == .email {
            Text(L10n.recoveryMap.accountMissing).font(.footnote).foregroundStyle(Color.warnText)
        }
        if let identityId = contact.identityId {
            NavigationLink(value: Route.item(identityId)) {
                Text(L10n.recoveryMap.fromIdentity).font(.footnote)
            }
        }
    }
}

extension HealthEntry: Identifiable {
    public var id: String { itemId }
}
