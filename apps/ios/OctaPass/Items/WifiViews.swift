import OctaPassResources
import OctaPassVault
import SwiftUI

/// A Wi-Fi item (the web vault's `WifiFields`): the network with a Connected mark, its password,
/// security and the Enterprise sign-in, Connect and its QR code. `past`: an old version of the
/// item, which shows the fields and nothing that acts on the network.
struct WifiFields: View {
    let item: Item
    let wifi: WifiDetails
    let onShowQr: () -> Void
    var onGuestLink: (() -> Void)?
    var past = false
    @State private var radar = WifiRadar.shared

    var body: some View {
        // About the iPhone's location permission; the Mac reads Wi-Fi in plan 19 phase 2.
        #if os(iOS)
        if !past, radar.permission != "granted" {
            Section { WifiPermissionNote() }
        }
        #endif
        Section {
            HStack {
                FieldRow(label: L10n.wifi.ssid, value: wifi.ssid)
                if !past, radar.connected == wifi.ssid { ConnectedMark() }
            }
            if wifi.security == "open" {
                FieldRow(label: L10n.fields.password, value: L10n.wifi.noPassword, copyable: false)
            } else if let password = wifi.password, !password.isEmpty {
                SecretFieldRow(label: L10n.fields.password, value: password)
            }
            FieldRow(label: L10n.wifi.security, value: WifiNames.security(wifi.security), copyable: false)
            if wifi.hidden { FieldRow(label: L10n.wifi.hidden, value: L10n.wifi.yes, copyable: false) }
        }
        .task { if !past { await radar.refresh() } }
        if !past, let network = item.wifi {
            Section { WifiActions(network: network, details: wifi, onShowQr: onShowQr, onGuestLink: onGuestLink) }
        }
        if WifiNames.isEnterprise(wifi.security) {
            Section(L10n.wifi.enterprise) {
                if let method = wifi.eapMethod { FieldRow(label: L10n.wifi.eapMethod, value: WifiNames.eapMethod(method), copyable: false) }
                if let phase2 = wifi.phase2 { FieldRow(label: L10n.wifi.phase2, value: WifiNames.phase2(phase2), copyable: false) }
                if let username = wifi.username, !username.isEmpty { FieldRow(label: L10n.fields.username, value: username) }
                if let identity = wifi.identity, !identity.isEmpty { FieldRow(label: L10n.wifi.identity, value: identity) }
                if let domain = wifi.serverDomain, !domain.isEmpty { FieldRow(label: L10n.wifi.serverDomain, value: domain, ltr: true) }
                if let ca = wifi.caCertificate, !ca.isEmpty { FieldRow(label: L10n.wifi.caCertificate, value: ca, ltr: true, mono: true) }
            }
        }
        if wifi.captivePortal || wifi.managed || wifi.hotspot {
            Section(L10n.wifi.about) {
                if wifi.captivePortal { FieldRow(label: L10n.wifi.captivePortal, value: L10n.wifi.yes, copyable: false) }
                if wifi.managed { FieldRow(label: L10n.wifi.managed, value: L10n.wifi.yes, copyable: false) }
                if wifi.hotspot { FieldRow(label: L10n.wifi.hotspot, value: L10n.wifi.yes, copyable: false) }
            }
        }
        CustomFieldsSection(fields: wifi.customFields)
        if let notes = wifi.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
        PasswordHistorySection(history: wifi.passwordHistory)
    }
}

/// Connect, Show as QR code (full screen, for another phone's camera), and Share for a day where
/// the item can be shared.
struct WifiActions: View {
    @Environment(AppModel.self) private var model
    let network: WifiNetwork
    let details: WifiDetails?
    let onShowQr: () -> Void
    var onGuestLink: (() -> Void)?
    @State private var joining = false

    var body: some View {
        if WifiConnect.canJoin(network, details: details) {
            Button {
                Task { await join() }
            } label: {
                HStack {
                    Label(joining ? L10n.phone.connecting : L10n.phone.connect, systemImage: "wifi")
                    if joining { Spacer(); ProgressView() }
                }
            }
            .disabled(joining)
            .accessibilityIdentifier("wifi-connect")
        }
        Button(action: onShowQr) {
            Label(L10n.phone.showQr, systemImage: "qrcode")
        }
        .accessibilityIdentifier("show-qr")
        if let onGuestLink {
            Button(action: onGuestLink) {
                Label(L10n.wifi.guestAction, systemImage: "link")
            }
            .accessibilityIdentifier("wifi-guest-link")
        }
    }

    private func join() async {
        joining = true
        defer { joining = false }
        do {
            try await WifiConnect.join(network, details: details)
            model.confirm(L10n.phone.connected(ssid: network.ssid))
            await WifiRadar.shared.refresh()
        } catch WifiConnect.Failure.cancelled {
            return
        } catch WifiConnect.Failure.unsupported {
            model.toast = Toast(message: L10n.phone.connectUnsupported, tone: .danger)
        } catch {
            model.toast = Toast(message: L10n.phone.connectFailed, tone: .danger)
            Haptics.error()
        }
    }
}

/// A one-time link for one guest for a day (the web vault's `GuestLink`): the QR code holds the
/// link, not the network, and the item stays yours. Hidden when the vault locks.
struct WifiGuestSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let item: Item
    @State private var link: CreatedShareLink?
    @State private var error: String?
    @State private var savedBrightness: CGFloat?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let link {
                    QRCodeImage(text: link.url)
                        .frame(maxWidth: 320, maxHeight: 320)
                        .accessibilityLabel(L10n.wifi.guestQrLabel)
                        .accessibilityIdentifier("wifi-guest-qr")
                    Text(L10n.wifi.guestHelp).font(.footnote).foregroundStyle(Color.mist)
                    SecondaryButton(title: L10n.shareLink.copyLink, systemImage: "doc.on.doc") {
                        model.copy(link.url, what: L10n.shareLink.linkWhat)
                    }
                    .accessibilityIdentifier("wifi-guest-copy")
                } else if let error {
                    Notice(text: error)
                } else {
                    ProgressView()
                }
                Spacer(minLength: 0)
            }
            .padding(20)
            .navigationTitle(L10n.wifi.guestAction)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.phone.close) { dismiss() }
                }
            }
        }
        .task {
            guard link == nil else { return }
            do {
                link = try await model.vault.createShareLink(itemId: item.id, options: ShareLinkOptions(expiresInHours: 24, maxViews: 1, passphrase: nil))
            } catch {
                self.error = error.message
            }
        }
        .onChange(of: model.session.status) { _, status in if status != .unlocked { dismiss() } }
        .onAppear {
            savedBrightness = ScreenBrightness.value
            ScreenBrightness.value = 1
        }
        .onDisappear {
            if let savedBrightness { ScreenBrightness.value = savedBrightness }
        }
    }
}

struct ConnectedMark: View {
    var body: some View {
        Label(L10n.wifi.connected, systemImage: "checkmark.circle.fill")
            .font(.caption.weight(.semibold))
            .foregroundStyle(Color.freeText)
            .labelStyle(.titleAndIcon)
    }
}

/// Why the network the phone is on isn't marked, and a way to allow it.
struct WifiPermissionNote: View {
    @State private var radar = WifiRadar.shared
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.wifi.permissionTitle).font(.subheadline.weight(.semibold))
            Text(radar.permission == "denied" ? L10n.wifi.permissionDenied : L10n.wifi.permissionBodyCurrent)
                .font(.footnote).foregroundStyle(Color.mist)
            Button(L10n.wifi.permissionAllow) {
                if radar.permission == "denied" {
                    #if os(iOS)
                    if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                    #endif
                } else {
                    Task { await radar.refresh() }
                }
            }
            .font(.subheadline.weight(.medium))
        }
    }
}

/// The catalog's names for Wi-Fi settings.
enum WifiNames {
    static func isEnterprise(_ security: String) -> Bool {
        security == "wpa2Enterprise" || security == "wpa3Enterprise"
    }

    static func security(_ value: String) -> String { L10n.text(forKey: "wifi.securities.\(value)") ?? value }
    static func eapMethod(_ value: String) -> String { L10n.text(forKey: "wifi.eapMethods.\(value)") ?? value }
    static func phase2(_ value: String) -> String { L10n.text(forKey: "wifi.phase2s.\(value)") ?? value }
}
