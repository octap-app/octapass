import CoreLocation
import OctaPassResources
import OctaPassVault
import SwiftUI

// Nearby (the web vault's `screens/vault/Nearby.tsx`): places saved in the vault, the items at
// each, the place the device is at first. Which place that is, is worked out by the core on the
// device (`OctaPassVault.nearby`): the Wi-Fi network it's on and one location reading taken while
// the app is open go in, and nothing leaves the device.

// MARK: - Where the device is

/// One reading of the device's location, foreground only: asked for when Nearby appears and when
/// the app comes back, never watched, never kept. When-in-use permission only.
@MainActor @Observable
final class NearbyLocation: NSObject, CLLocationManagerDelegate {
    static let shared = NearbyLocation()

    enum State: Equatable { case notAsked, reading, ok, denied, unavailable }

    private let manager = CLLocationManager()
    private(set) var state: State = .notAsked
    private(set) var reading: CLLocation?
    private var waiting: [CheckedContinuation<CLLocation?, Never>] = []

    override private init() {
        super.init()
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
        if Self.refused(manager.authorizationStatus) { state = .denied }
    }

    var allowed: Bool { Self.allowed(manager.authorizationStatus) && CLLocationManager.locationServicesEnabled() }

    private static func allowed(_ status: CLAuthorizationStatus) -> Bool {
        status != .notDetermined && !refused(status)
    }

    private static func refused(_ status: CLAuthorizationStatus) -> Bool {
        status == .denied || status == .restricted
    }

    /// A fresh reading. `ask`: show the system's prompt if it hasn't been answered; otherwise a
    /// device that hasn't allowed location gets nil without being asked.
    func read(ask: Bool) async -> CLLocation? {
        let status = manager.authorizationStatus
        if Self.refused(status) || !CLLocationManager.locationServicesEnabled() {
            state = .denied
            reading = nil
            return nil
        }
        if status == .notDetermined {
            guard ask else { return nil }
            state = .reading
            manager.requestWhenInUseAuthorization()
            // The answer comes to `locationManagerDidChangeAuthorization`, which reads then.
        } else {
            state = .reading
            manager.requestLocation()
        }
        let location = await withCheckedContinuation { waiting.append($0) }
        return location
    }

    private func finish(_ location: CLLocation?, _ next: State) {
        reading = location
        state = next
        let continuations = waiting
        waiting = []
        continuations.forEach { $0.resume(returning: location) }
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        Task { @MainActor in
            guard !self.waiting.isEmpty, status != .notDetermined else { return }
            if Self.refused(status) {
                self.finish(nil, .denied)
            } else {
                self.manager.requestLocation()
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let last = locations.last
        Task { @MainActor in self.finish(last, last == nil ? .unavailable : .ok) }
    }

    nonisolated func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        let denied = (error as? CLError)?.code == .denied
        Task { @MainActor in self.finish(nil, denied ? .denied : .unavailable) }
    }
}

extension Here {
    /// What the device knows now: the Wi-Fi network it's on (iPhone, with location access) and a
    /// location reading, if there is one.
    @MainActor static func now(network: String?, location: CLLocation?) -> Here {
        Here(
            networks: network.map { [$0] } ?? [],
            latitude: location?.coordinate.latitude,
            longitude: location?.coordinate.longitude,
            accuracy: location.map { $0.horizontalAccuracy >= 0 ? $0.horizontalAccuracy : 0 })
    }

    var knowsWhere: Bool { !networks.isEmpty || latitude != nil }
}

// MARK: - Formatting

enum PlaceDistance {
    /// A rough distance for a list, as the web vault's `formatDistance`: metres to the nearest 10
    /// under a kilometre, then kilometres with one decimal under 10 km, whole kilometres beyond.
    static func text(_ metres: Double) -> String {
        let formatter = MeasurementFormatter()
        formatter.unitOptions = .providedUnit
        formatter.unitStyle = .medium
        formatter.locale = L10n.formatLocale
        // Tens of metres first, so 996 m reads "1 km", not "1,000 m".
        let rounded = max(10, (metres / 10).rounded() * 10)
        if rounded < 1000 {
            formatter.numberFormatter.maximumFractionDigits = 0
            return formatter.string(from: Measurement(value: rounded, unit: UnitLength.meters))
        }
        let km = metres / 1000
        formatter.numberFormatter.maximumFractionDigits = km < 10 ? 1 : 0
        return formatter.string(from: Measurement(value: km, unit: UnitLength.kilometers))
    }

    static func summary(_ place: Place) -> String {
        var parts: [String] = []
        if place.latitude != nil { parts.append(L10n.nearby.summaryPoint(radius: text(place.radius))) }
        if !place.networks.isEmpty { parts.append(L10n.nearby.summaryNetworks(count: place.networks.count)) }
        return parts.isEmpty ? L10n.nearby.summaryNothing : parts.joined(separator: " · ")
    }
}

// MARK: - The list

/// Nearby: "Now nearby: Office" with its items by type, then the other places, nearest first.
struct NearbyView: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.detailEditor) private var detailEditor
    @State private var location = NearbyLocation.shared
    @State private var radar = WifiRadar.shared
    @State private var list: [NearbyPlace]?
    @State private var failed = false
    @State private var checking = true
    @State private var here = Here(networks: [], latitude: nil, longitude: nil, accuracy: nil)
    @State private var editing: PlaceEditing?
    @State private var managing = false
    @State private var newItem: IdentifiedDraft?

    var body: some View {
        content
            .navigationTitle(L10n.scopes.nearby)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button { managing = true } label: { Label(L10n.nearby.places, systemImage: "list.bullet") }
                        .accessibilityIdentifier("nearby-places")
                    Button { editing = .new } label: { Label(L10n.nearby.newPlace, systemImage: "plus") }
                        .accessibilityIdentifier("nearby-new-place")
                }
            }
            // Where the device is: read when Nearby appears and each time the app comes back.
            .task(id: scenePhase) {
                guard scenePhase == .active else { return }
                await locate()
            }
            .task(id: Key(version: model.itemsVersion, here: here)) { await load() }
            .sheet(item: $editing) { PlaceEditorSheet(editing: $0, network: radar.connected) }
            .sheet(isPresented: $managing) { PlacesSheet { editing = $0 } }
            .sheet(item: $newItem) { ItemEditorSheet(draft: $0.draft) }
    }

    private struct Key: Equatable {
        let version: Int
        let here: Here
    }

    private func locate() async {
        checking = true
        await radar.refresh()
        let reading = await location.read(ask: true)
        here = .now(network: radar.connected, location: reading)
        checking = false
    }

    private func load() async {
        do {
            list = try await model.vault.nearby(here: here)
            failed = false
        } catch {
            failed = true
        }
    }

    @ViewBuilder private var content: some View {
        if failed {
            EmptyStateView(icon: "exclamationmark.triangle", title: L10n.list.loadFailed) {
                Button(L10n.common.tryAgain) { Task { await load() } }
            }
        } else if let list {
            if list.isEmpty {
                EmptyStateView(icon: "mappin.and.ellipse", title: L10n.nearby.emptyTitle, message: L10n.nearby.emptyBody) {
                    Button { editing = .new } label: { Label(L10n.nearby.newPlace, systemImage: "plus") }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("nearby-first-place")
                }
            } else {
                places(list)
            }
        } else {
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func places(_ list: [NearbyPlace]) -> some View {
        let anyHere = list.contains { $0.here != nil }
        let firstOther = list.firstIndex { $0.here == nil }
        return List {
            if checking {
                Text(L10n.nearby.checking).font(.footnote).foregroundStyle(Color.mist)
            } else if !anyHere {
                Text(reason).font(.footnote).foregroundStyle(Color.mist)
                    .accessibilityIdentifier("nearby-reason")
            }
            ForEach(Array(list.enumerated()), id: \.element.place.id) { index, entry in
                if anyHere, index == firstOther {
                    Text(L10n.nearby.otherPlaces)
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(Color.mist)
                        .listRowBackground(Color.clear)
                        .accessibilityAddTraits(.isHeader)
                }
                placeHeader(entry)
                if entry.sections.allSatisfy(\.items.isEmpty) {
                    Text(L10n.nearby.noItems).font(.subheadline).foregroundStyle(Color.mist)
                } else {
                    ForEach(entry.sections, id: \.itemType.name) { section in
                        Section {
                            ForEach(section.items, id: \.id) { item in
                                DetailLink(route: .item(item.id)) {
                                    ItemRow(item: item, vault: directory.vault(item.vaultId), scope: .all)
                                }
                                .accessibilityIdentifier("item-\(item.title)")
                            }
                        } header: {
                            Text(section.itemType.categoryName)
                                .accessibilityAddTraits(.isHeader)
                        }
                    }
                }
            }
        }
        .listStyle(.plain)
    }

    private func placeHeader(_ entry: NearbyPlace) -> some View {
        let place = entry.place
        let vault = directory.vault(place.vaultId)
        let how: String? = switch entry.here {
        case .some(.wifi): L10n.nearby.byWifi
        case .some(.location): L10n.nearby.byLocation
        case .none: entry.distance.map { L10n.nearby.away(distance: PlaceDistance.text($0)) }
        }
        return HStack(spacing: 10) {
            Image(systemName: entry.here == nil ? "mappin" : "location.fill")
                .foregroundStyle(entry.here == nil ? Color.mist : Color.trust)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.here == nil ? place.name : L10n.nearby.nowNearby(place: place.name))
                    .font(.headline)
                    .foregroundStyle(Color.ink)
                    .accessibilityIdentifier("place-\(place.name)")
                if let how {
                    Text(how).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            Spacer()
            if vault?.canWrite ?? true {
                Menu {
                    Button { add(to: place) } label: { Label(L10n.nearby.addItemHere, systemImage: "plus") }
                        .accessibilityIdentifier("place-add-\(place.name)")
                    Button { editing = .edit(place) } label: { Label(L10n.nearby.editPlace, systemImage: "pencil") }
                        .accessibilityIdentifier("place-edit-\(place.name)")
                } label: {
                    Image(systemName: "ellipsis.circle").accessibilityLabel(L10n.nearby.editPlace)
                }
                .accessibilityIdentifier("place-menu-\(place.name)")
            }
        }
        .padding(.top, 8)
        .listRowSeparator(.hidden)
    }

    /// Why no place is marked as nearby.
    private var reason: String {
        if here.knowsWhere { return L10n.nearby.reasonNoMatch }
        switch location.state {
        case .denied: return L10n.nearby.reasonLocationDenied
        case .unavailable: return L10n.nearby.reasonLocationUnavailable
        default: return L10n.nearby.reasonLocationOff
        }
    }

    /// A new item that starts at this place, in the place's vault if it can be written.
    private func add(to place: Place) {
        let vaultId = directory.vault(place.vaultId)?.canWrite == true ? place.vaultId : directory.personal?.id ?? place.vaultId
        var draft = newItemDraft(itemType: .login, vaultId: vaultId)
        draft.places = [place.id]
        if let detailEditor { detailEditor.open(draft) } else { newItem = draft.identified }
    }
}

// MARK: - Places manager and editor

enum PlaceEditing: Identifiable {
    case new
    case edit(Place)

    var id: String {
        switch self {
        case .new: "new"
        case let .edit(place): place.id
        }
    }
}

/// Every place, to edit, and New place.
struct PlacesSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.dismiss) private var dismiss
    let onEdit: (PlaceEditing) -> Void
    @State private var places: [Place]?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(places ?? [], id: \.id) { place in
                        let vault = directory.vault(place.vaultId)
                        Button {
                            dismiss()
                            onEdit(.edit(place))
                        } label: {
                            HStack(spacing: 10) {
                                Image(systemName: "mappin").foregroundStyle(Color.mist)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(place.name).foregroundStyle(Color.ink)
                                    Text(PlaceDistance.summary(place)).font(.footnote).foregroundStyle(Color.mist)
                                }
                                Spacer()
                                if let vault, vault.vaultType != .personal {
                                    Text(vault.name).font(.caption2.weight(.semibold))
                                        .padding(.horizontal, 6).padding(.vertical, 1)
                                        .background(Color.tile, in: Capsule())
                                }
                            }
                        }
                        .disabled(!(vault?.canWrite ?? true))
                        .accessibilityIdentifier("manage-place-\(place.name)")
                    }
                } footer: {
                    Text(L10n.nearby.managerBody)
                }
            }
            .navigationTitle(L10n.nearby.managerTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.close) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        dismiss()
                        onEdit(.new)
                    } label: { Label(L10n.nearby.newPlace, systemImage: "plus") }
                }
            }
            .task(id: model.itemsVersion) { places = try? await model.vault.places() }
        }
    }
}

/// New place or Edit place: name, vault, Wi-Fi networks, a point and radius, a note.
struct PlaceEditorSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @Environment(\.dismiss) private var dismiss
    let editing: PlaceEditing
    /// The network the device is on, to add in one tap.
    let network: String?
    @State private var name = ""
    @State private var vaultId = ""
    @State private var networks: [String] = []
    @State private var newNetwork = ""
    @State private var latitude = ""
    @State private var longitude = ""
    @State private var radius = "150"
    @State private var notes = ""
    @State private var nameError: String?
    @State private var pointError: String?
    @State private var locating = false
    @State private var locateFailed = false
    @State private var busy = false
    @State private var confirmDelete = false
    @State private var loaded = false

    private var original: Place? {
        if case let .edit(place) = editing { return place }
        return nil
    }
    private var writable: [Vault] { directory.vaults.filter(\.canWrite) }
    private var hasPoint: Bool {
        !latitude.trimmingCharacters(in: .whitespaces).isEmpty || !longitude.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(L10n.nearby.name, text: $name, prompt: Text(L10n.nearby.namePlaceholder))
                        .accessibilityIdentifier("place-name")
                    if let nameError { Text(nameError).font(.footnote).foregroundStyle(Color.dangerText) }
                    if original == nil, writable.count > 1 {
                        Picker(L10n.nearby.vault, selection: $vaultId) {
                            ForEach(writable, id: \.id) { Text($0.name).tag($0.id) }
                        }
                    }
                }
                Section {
                    ForEach(networks, id: \.self) { ssid in
                        HStack {
                            Label(ssid, systemImage: "wifi").environment(\.layoutDirection, .leftToRight)
                            Spacer()
                            Button { networks.removeAll { $0 == ssid } } label: {
                                Image(systemName: "minus.circle.fill").foregroundStyle(Color.mist)
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.nearby.removeNetwork(network: ssid))
                        }
                    }
                    HStack {
                        TextField(L10n.nearby.networkPlaceholder, text: $newNetwork)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .onSubmit(addNetwork)
                            .accessibilityIdentifier("place-network")
                        Button(L10n.nearby.addNetwork, action: addNetwork)
                            .buttonStyle(.borderless)
                            .disabled(newNetwork.trimmingCharacters(in: .whitespaces).isEmpty)
                            .accessibilityIdentifier("place-add-network")
                    }
                    if let network, !networks.contains(network) {
                        Button { networks.append(network) } label: {
                            Label(L10n.nearby.addConnected(network: network), systemImage: "wifi")
                        }
                        .accessibilityIdentifier("place-add-connected")
                    }
                } header: {
                    Text(L10n.nearby.networks)
                } footer: {
                    Text(L10n.nearby.networksHint)
                }
                Section {
                    TextField(L10n.nearby.latitude, text: $latitude)
                        .keyboardType(.numbersAndPunctuation)
                        .accessibilityIdentifier("place-latitude")
                    TextField(L10n.nearby.longitude, text: $longitude)
                        .keyboardType(.numbersAndPunctuation)
                        .accessibilityIdentifier("place-longitude")
                    if let pointError { Text(pointError).font(.footnote).foregroundStyle(Color.dangerText) }
                    Button { Task { await useCurrent() } } label: {
                        Label(locating ? L10n.nearby.locating : L10n.nearby.useCurrent, systemImage: "location")
                    }
                    .disabled(locating)
                    .accessibilityIdentifier("place-use-current")
                    if locateFailed { Text(L10n.nearby.locationFailed).font(.footnote).foregroundStyle(Color.warnText) }
                    if hasPoint {
                        Button(L10n.nearby.clearLocation, role: .destructive) {
                            latitude = ""
                            longitude = ""
                        }
                    }
                    LabeledContent(L10n.nearby.radius) {
                        TextField(L10n.nearby.radius, text: $radius)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                            .accessibilityIdentifier("place-radius")
                    }
                    if hasPoint, let vault = directory.vault(vaultId), vault.vaultType != .personal {
                        Notice(text: L10n.nearby.sharedWarning(vault: vault.name), tone: .warn)
                            .accessibilityIdentifier("place-shared-warning")
                    }
                } header: {
                    Text(L10n.nearby.location)
                } footer: {
                    Text("\(L10n.nearby.locationHint) \(L10n.nearby.radiusHint)")
                }
                if !hasPoint, networks.isEmpty {
                    Section { Text(L10n.nearby.noWay).font(.footnote).foregroundStyle(Color.mist) }
                }
                Section(L10n.nearby.notes) {
                    TextField(L10n.nearby.notes, text: $notes, axis: .vertical)
                        .lineLimit(2...6)
                }
                if original != nil {
                    Section {
                        Button(L10n.nearby.deletePlace, role: .destructive) { confirmDelete = true }
                            .accessibilityIdentifier("place-delete")
                    }
                }
            }
            .navigationTitle(original == nil ? L10n.nearby.newPlace : L10n.nearby.editPlace)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.common.save) { Task { await save() } }
                        .disabled(busy)
                        .accessibilityIdentifier("place-save")
                }
            }
            .confirmationDialog(L10n.nearby.deletePlace, isPresented: $confirmDelete, titleVisibility: .visible) {
                Button(L10n.nearby.deletePlace, role: .destructive) { Task { await delete() } }
            } message: {
                Text(L10n.nearby.deleteConfirm(place: original?.name ?? ""))
            }
            .onAppear(perform: fill)
        }
    }

    private func fill() {
        guard !loaded else { return }
        loaded = true
        if let place = original {
            name = place.name
            vaultId = place.vaultId
            networks = place.networks
            latitude = place.latitude.map { String(format: "%.6f", $0) } ?? ""
            longitude = place.longitude.map { String(format: "%.6f", $0) } ?? ""
            radius = String(Int(place.radius.rounded()))
            notes = place.notes ?? ""
        } else {
            vaultId = (writable.first { $0.vaultType == .personal } ?? writable.first)?.id ?? ""
        }
    }

    private func addNetwork() {
        let ssid = newNetwork
        if !ssid.trimmingCharacters(in: .whitespaces).isEmpty, !networks.contains(ssid) { networks.append(ssid) }
        newNetwork = ""
    }

    private func useCurrent() async {
        locating = true
        locateFailed = false
        defer { locating = false }
        guard let reading = await NearbyLocation.shared.read(ask: true) else {
            locateFailed = true
            return
        }
        latitude = String(format: "%.6f", reading.coordinate.latitude)
        longitude = String(format: "%.6f", reading.coordinate.longitude)
        pointError = nil
    }

    /// The typed coordinates: both or neither, on Earth. `valid` is false when they aren't.
    private func point() -> (valid: Bool, value: (Double, Double)?) {
        let lat = latitude.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ",", with: ".")
        let lon = longitude.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ",", with: ".")
        if lat.isEmpty, lon.isEmpty { return (true, nil) }
        guard let la = Double(lat), let lo = Double(lon), abs(la) <= 90, abs(lo) <= 180 else { return (false, nil) }
        return (true, (la, lo))
    }

    private func save() async {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        nameError = trimmed.isEmpty ? L10n.nearby.nameRequired : nil
        let checked = point()
        pointError = checked.valid ? nil : L10n.nearby.invalidPoint
        guard !trimmed.isEmpty, checked.valid else { return Haptics.error() }
        let coordinates = checked.value
        busy = true
        defer { busy = false }
        let draft = PlaceDraft(
            id: original?.id, vaultId: vaultId, revision: original?.revision, name: trimmed,
            latitude: coordinates?.0, longitude: coordinates?.1,
            radius: Double(radius.trimmingCharacters(in: .whitespaces)), networks: networks,
            notes: notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : notes)
        do {
            let saved = try await model.vault.savePlace(draft: draft)
            model.confirm(L10n.nearby.saved(place: saved.name))
            dismiss()
        } catch {
            model.show(error)
        }
    }

    private func delete() async {
        guard let place = original else { return }
        do {
            try await model.vault.deletePlace(id: place.id)
            model.confirm(L10n.nearby.deleted(place: place.name))
            dismiss()
        } catch {
            model.show(error)
        }
    }
}

// MARK: - An item's places

/// The item's places on its page, with Add to a place and a way to take it off one.
struct ItemPlacesSection: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let editable: Bool
    @State private var places: [Place] = []

    var body: some View {
        let linked = places.filter { item.places.contains($0.id) }
        let others = places.filter { !item.places.contains($0.id) }
        Group {
            if !linked.isEmpty || (editable && !places.isEmpty) {
                Section(L10n.nearby.itemPlaces) {
                    ForEach(linked, id: \.id) { place in
                        HStack {
                            Label(place.name, systemImage: "mappin")
                            Spacer()
                            if editable {
                                Button { change(place, linked: false) } label: {
                                    Image(systemName: "minus.circle.fill").foregroundStyle(Color.mist)
                                }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(L10n.nearby.removeFromPlace(place: place.name))
                                .accessibilityIdentifier("item-remove-place-\(place.name)")
                            }
                        }
                    }
                    if editable, !others.isEmpty {
                        Menu {
                            ForEach(others, id: \.id) { place in
                                Button(place.name) { change(place, linked: true) }
                            }
                        } label: {
                            Label(L10n.nearby.addToPlace, systemImage: "plus")
                        }
                        .accessibilityIdentifier("item-add-to-place")
                    }
                }
            }
        }
        .task(id: model.itemsVersion) { places = (try? await model.vault.places()) ?? [] }
    }

    private func change(_ place: Place, linked: Bool) {
        Task {
            do {
                _ = try await model.vault.setItemPlace(itemId: item.id, placeId: place.id, linked: linked)
                model.confirm(linked ? L10n.nearby.addedTo(place: place.name) : L10n.nearby.removedFrom(place: place.name))
            } catch { model.show(error) }
        }
    }
}

// MARK: - Suggest a place when saving

/// "You're at Office. Add this item to it?" after a new item is saved at one of the user's places
/// (`OctaPassVault.suggestedPlace`). Asked once per item, never asks for location itself, and
/// Settings → Nearby turns it off. This device's own choice, never synced.
@MainActor @Observable
final class PlaceOffer {
    static let shared = PlaceOffer()

    struct Offer: Identifiable {
        let itemId: String
        let place: Place
        var id: String { itemId }
    }

    private(set) var offer: Offer?

    private static let enabledKey = "octapass.nearbySuggest"
    private static let askedKey = "octapass.nearbyAsked"

    static var enabled: Bool {
        get { UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    private init() {}

    /// After the editor saved a new item.
    func consider(_ itemId: String, vault: OctaPassVault) async {
        guard Self.enabled else { return }
        var asked = UserDefaults.standard.stringArray(forKey: Self.askedKey) ?? []
        guard !asked.contains(itemId) else { return }
        let radar = WifiRadar.shared
        await radar.refresh()
        let location = NearbyLocation.shared
        var reading: CLLocation?
        if location.allowed { reading = await location.read(ask: false) }
        let here = Here.now(network: radar.connected, location: reading)
        guard here.knowsWhere, let place = try? await vault.suggestedPlace(itemId: itemId, here: here) else { return }
        asked = Array((asked + [itemId]).suffix(200))
        UserDefaults.standard.set(asked, forKey: Self.askedKey)
        offer = Offer(itemId: itemId, place: place)
    }

    func answer(add: Bool, vault: OctaPassVault, model: AppModel) {
        guard let offer else { return }
        self.offer = nil
        guard add else { return }
        Task {
            do {
                _ = try await vault.setItemPlace(itemId: offer.itemId, placeId: offer.place.id, linked: true)
                model.confirm(L10n.nearby.addedTo(place: offer.place.name))
            } catch { model.show(error) }
        }
    }
}

/// Shows the place offer wherever the vault's shells are.
struct PlaceSaveOffer: ViewModifier {
    @Environment(AppModel.self) private var model
    @State private var offers = PlaceOffer.shared

    func body(content: Content) -> some View {
        content
            .alert(offers.offer.map { L10n.nearby.suggest(place: $0.place.name) } ?? "",
                   isPresented: Binding(get: { offers.offer != nil }, set: { if !$0 { offers.answer(add: false, vault: model.vault, model: model) } })) {
                Button(L10n.nearby.suggestAdd) { offers.answer(add: true, vault: model.vault, model: model) }
                    .accessibilityIdentifier("place-offer-add")
                Button(L10n.nearby.suggestNotNow, role: .cancel) { offers.answer(add: false, vault: model.vault, model: model) }
            }
    }
}

/// Settings → Nearby: the place suggestion. Location itself is the system's choice.
struct NearbySettingsSection: View {
    @State private var suggest = PlaceOffer.enabled

    var body: some View {
        Section(L10n.nearby.settingsTitle) {
            Toggle(isOn: Binding(get: { suggest }, set: { suggest = $0; PlaceOffer.enabled = $0 })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.nearby.suggestSetting)
                    Text(L10n.nearby.suggestSettingHint).font(.footnote).foregroundStyle(Color.mist)
                }
            }
            .accessibilityIdentifier("settings-nearby-suggest")
        }
    }
}
