import OctaPassResources
import OctaPassVault
import SwiftUI

/// Networks already asked about, and those never to ask about: this phone's own, never synced.
struct WifiOffers: Codable {
    var asked: [String] = []
    var never: [String] = []

    private static let key = "octapass.wifiOffers"

    static func load() -> WifiOffers {
        guard let data = UserDefaults.standard.data(forKey: key), let offers = try? JSONDecoder().decode(WifiOffers.self, from: data) else { return WifiOffers() }
        return offers
    }

    func save() {
        if let data = try? JSONEncoder().encode(self) { UserDefaults.standard.set(data, forKey: Self.key) }
    }
}

/// "Save “Home” in Octa Pass?" (the web vault's `WifiSaveOffer`): when the phone is on a network
/// the vault doesn't have, checked when the app comes back. Asked once per network; Never stops
/// it for good. Only with location already allowed: this never asks for it.
struct WifiSaveOffer: ViewModifier {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.scenePhase) private var scenePhase
    @State private var offering: String?
    @State private var draft: IdentifiedDraft?

    func body(content: Content) -> some View {
        content
            .task(id: scenePhase) { await check() }
            .alert(offering.map { L10n.wifi.offerTitle(ssid: $0) } ?? "", isPresented: Binding(get: { offering != nil }, set: { if !$0 { offering = nil } })) {
                Button(L10n.wifi.offerSave) {
                    if let offering { save(offering) }
                }
                Button(L10n.wifi.offerNotNow, role: .cancel) { done(never: false) }
                Button(L10n.wifi.offerNever, role: .destructive) { done(never: true) }
            } message: {
                Text(L10n.wifi.offerPhone)
            }
            .sheet(item: $draft) { ItemEditorSheet(draft: $0.draft) }
    }

    private func check() async {
        let radar = WifiRadar.shared
        guard scenePhase == .active, model.settings.wifiOffers, radar.permission == "granted" else { return }
        await radar.refresh()
        guard let ssid = radar.connected else { return }
        let offers = WifiOffers.load()
        guard !offers.asked.contains(ssid), !offers.never.contains(ssid) else { return }
        let saved = (try? await model.vault.listItems(filter: ListScope.type(.wifi).filter)) ?? []
        if !saved.contains(where: { $0.subtitle == ssid }) { offering = ssid }
    }

    private func done(never: Bool) {
        guard let offering else { return }
        var offers = WifiOffers.load()
        if !offers.asked.contains(offering) { offers.asked.append(offering) }
        if never, !offers.never.contains(offering) { offers.never.append(offering) }
        offers.save()
        self.offering = nil
    }

    private func save(_ ssid: String) {
        done(never: false)
        guard let vault = directory.vaults.first(where: { $0.vaultType == .personal && $0.canWrite }) ?? directory.vaults.first(where: \.canWrite) else { return }
        var next = newItemDraft(itemType: .wifi, vaultId: vault.id)
        if case var .wifi(details) = next.details {
            details.ssid = ssid
            next.details = .wifi(wifi: details)
        }
        draft = next.identified
    }
}

/// A draft a sheet can be presented for.
struct IdentifiedDraft: Identifiable {
    let id = UUID()
    let draft: ItemDraft
}

extension ItemDraft {
    var identified: IdentifiedDraft { IdentifiedDraft(draft: self) }
}

/// Settings → Wi-Fi: the "Save this network?" offers.
struct WifiOffersSection: View {
    @Environment(AppModel.self) private var model
    @State private var never = WifiOffers.load().never.count

    var body: some View {
        Section {
            Toggle(isOn: Binding(get: { model.settings.wifiOffers }, set: { on in model.update { $0.wifiOffers = on } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.wifi.offerSetting)
                    Text(L10n.wifi.offerSettingHelp).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .accessibilityIdentifier("settings-wifi-offers")
            if never > 0 {
                HStack {
                    Text(L10n.wifi.forgetNever(count: never))
                    Spacer()
                    Button(L10n.wifi.forgetNeverAction) {
                        var offers = WifiOffers.load()
                        offers.never = []
                        offers.save()
                        never = 0
                    }
                    .buttonStyle(.borderless)
                }
            }
        } header: {
            Text(L10n.wifi.settings)
        } footer: {
            Text(L10n.wifi.settingsHelp)
        }
    }
}
