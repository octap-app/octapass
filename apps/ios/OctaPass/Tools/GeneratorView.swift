import OctaPassResources
import OctaPassVault
import SwiftUI

/// The password generator (the web vault's `GeneratorPanel`): a random password or a passphrase,
/// made on the phone by the vault, with its strength and bits. The options are remembered on this
/// phone. `site`: the website the password is for, so it follows that site's known password rules.
struct GeneratorPanel: View {
    @Environment(AppModel.self) private var model
    @AppStorage("octapass.generator") private var stored = GeneratorPrefs().encoded
    @Binding var value: String
    var site: String?

    private var prefs: GeneratorPrefs { GeneratorPrefs(stored) }

    /// Digits and symbols in colours of their own, so a password is easier to read out or type.
    static func highlighted(_ value: String) -> AttributedString {
        var text = AttributedString()
        for character in value {
            var part = AttributedString(String(character))
            part.foregroundColor = character.isNumber ? Color.trustText
                : (character.isLetter || character.isWhitespace) ? Color.ink : Color.freeText
            text.append(part)
        }
        return text
    }

    var body: some View {
        let estimate = model.vault.estimateStrength(password: value)
        let bits = Int(generatorEntropyBits(options: prefs.options).rounded())
        Section {
            VStack(alignment: .leading, spacing: 10) {
                Text(Self.highlighted(value))
                    .font(.secret(.title3))
                    .textSelection(.enabled)
                    .environment(\.layoutDirection, .leftToRight)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityLabel(L10n.generator.generated)
                    .accessibilityValue(value)
                    .accessibilityIdentifier("generated-password")
                HStack {
                    Circle().fill(StrengthMeter.color(estimate.score)).frame(width: 8, height: 8)
                    Text("\(StrengthMeter.label(estimate.score)) · \(L10n.generator.bits(bits: bits))")
                        .font(.footnote)
                        .foregroundStyle(Color.mist)
                    Spacer()
                    Button { generate() } label: { Image(systemName: "arrow.clockwise") }
                        .accessibilityLabel(L10n.generator.regenerate)
                        .accessibilityIdentifier("regenerate")
                    Button { model.copy(value, what: L10n.fields.password) } label: { Image(systemName: "doc.on.doc") }
                        .accessibilityLabel(L10n.copy.action(what: L10n.fields.password))
                }
                .buttonStyle(.borderless)
            }
            .padding(.vertical, 6)
        }
        Section {
            Picker(L10n.generator.kind, selection: binding(\.passphrase)) {
                Text(L10n.generator.password).tag(false)
                Text(L10n.generator.passphrase).tag(true)
            }
            .pickerStyle(.segmented)
            if prefs.passphrase {
                Stepper(L10n.generator.wordsValue(count: prefs.words), value: binding(\.words), in: 3...10)
                Picker(L10n.generator.separator, selection: binding(\.separator)) {
                    ForEach(["-", ".", "_", " ", ","], id: \.self) { separator in
                        Text(separator == " " ? L10n.generator.space : separator).tag(separator)
                    }
                }
                Toggle(L10n.generator.capitalize, isOn: binding(\.capitalize))
                Toggle(L10n.generator.includeNumber, isOn: binding(\.includeNumber))
            } else {
                VStack(alignment: .leading) {
                    Text(L10n.generator.lengthValue(count: prefs.length))
                    Slider(value: Binding(get: { Double(prefs.length) }, set: { length in update { $0.length = Int(length) } }), in: 8...64, step: 1)
                        .accessibilityLabel(L10n.generator.length)
                        .accessibilityValue(L10n.generator.lengthValue(count: prefs.length))
                }
                Toggle(L10n.generator.uppercase, isOn: binding(\.uppercase))
                Toggle(L10n.generator.lowercase, isOn: binding(\.lowercase))
                Toggle(L10n.generator.digits, isOn: binding(\.digits))
                Toggle(L10n.generator.symbols, isOn: binding(\.symbols))
                Toggle(isOn: binding(\.avoidAmbiguous)) {
                    VStack(alignment: .leading) {
                        Text(L10n.generator.avoidAmbiguous)
                        Text(L10n.generator.avoidAmbiguousHint).font(.footnote).foregroundStyle(Color.mist)
                    }
                }
            }
        } footer: {
            Text(L10n.generator.localNote)
        }
        .onAppear { if value.isEmpty { generate() } }
        .onChange(of: stored) { generate() }
    }

    private func binding<T>(_ path: WritableKeyPath<GeneratorPrefs, T>) -> Binding<T> {
        Binding(get: { prefs[keyPath: path] }, set: { value in update { $0[keyPath: path] = value } })
    }

    private func update(_ change: (inout GeneratorPrefs) -> Void) {
        var next = prefs
        change(&next)
        // At least one set: the generator refuses none.
        if !next.passphrase, !(next.uppercase || next.lowercase || next.digits || next.symbols) { next.lowercase = true }
        stored = next.encoded
    }

    private func generate() {
        var made: String?
        if let site, !prefs.passphrase { made = try? generatePasswordForSite(url: site, options: prefs.options) }
        value = made ?? (try? generatePassword(options: prefs.options)) ?? ""
    }
}

/// The generator's options as this phone remembers them.
struct GeneratorPrefs: Codable, Equatable {
    var passphrase = false
    var length = 20
    var uppercase = true
    var lowercase = true
    var digits = true
    var symbols = true
    var avoidAmbiguous = false
    var words = 5
    var separator = "-"
    var capitalize = false
    var includeNumber = false

    init() {}

    init(_ json: String) {
        self = (try? JSONDecoder().decode(GeneratorPrefs.self, from: Data(json.utf8))) ?? GeneratorPrefs()
    }

    var encoded: String {
        (try? String(data: JSONEncoder().encode(self), encoding: .utf8)) ?? "{}"
    }

    var options: GeneratorOptions {
        passphrase
            ? .passphrase(words: UInt32(words), separator: separator, capitalize: capitalize, includeNumber: includeNumber)
            : .password(length: UInt32(length), uppercase: uppercase, lowercase: lowercase, digits: digits, symbols: symbols, avoidAmbiguous: avoidAmbiguous)
    }
}

/// The Generator tab.
struct GeneratorView: View {
    @Environment(AppModel.self) private var model
    @State private var value = ""
    @State private var masked = false

    var body: some View {
        List {
            GeneratorPanel(value: $value)
            Section { Text(L10n.generator.localNote).font(.footnote).foregroundStyle(Color.mist) }
            if masked {
                Section {
                    NavigationLink(value: Route.maskedEmail) { Label(L10n.maskedEmail.make, systemImage: "envelope.badge.shield.half.filled") }
                }
            }
        }
        .navigationTitle(L10n.generator.title)
        .task(id: model.itemsVersion) { masked = !((try? await model.vault.maskedEmailConnections()) ?? []).isEmpty }
    }
}

/// The editor's Generate a password: the same panel, and Use this password.
struct GeneratorSheet: View {
    @Environment(\.dismiss) private var dismiss
    var site: String?
    let onUse: (String) -> Void
    @State private var value = ""

    var body: some View {
        NavigationStack {
            List {
                GeneratorPanel(value: $value, site: site)
                Section {
                    Button(L10n.editor.usePassword) {
                        onUse(value)
                        dismiss()
                    }
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("use-password")
                }
            }
            .navigationTitle(L10n.editor.generateTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L10n.common.cancel) { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

extension StrengthMeter {
    static func color(_ score: UInt8) -> Color {
        switch score {
        case 0, 1: .danger
        case 2: .warn
        default: .free
        }
    }
}
