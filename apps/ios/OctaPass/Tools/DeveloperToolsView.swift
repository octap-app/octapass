import OctaPassResources
import OctaPassVault
import SwiftUI

/// The developer toolkit on the phone (plan 16 §5): inspectors, and generators whose private parts
/// go straight to the vault. Every tool is the Rust core's `toolkit::run`, as on every other client.
/// Private keys are never shown here: reading one out of the vault goes through the item.
struct DeveloperToolsView: View {
    enum Panel: String, CaseIterable, Identifiable {
        case jwt, certificates, hash, encoding, random, keys
        var id: String { rawValue }
        var title: String {
            switch self {
            case .jwt: L10n.tools.panels.jwt
            case .certificates: L10n.tools.panels.certificates
            case .hash: L10n.tools.panels.hash
            case .encoding: L10n.tools.panels.encoding
            case .random: L10n.tools.panels.random
            case .keys: L10n.tools.panels.keys
            }
        }
    }

    @Environment(AppModel.self) private var model
    @Environment(VaultDirectory.self) private var directory
    @State private var panel = Panel.jwt
    @State private var input = ""
    @State private var format = "base64"
    @State private var keyKind = "ed25519"
    @State private var output: [(label: String, value: String)] = []
    @State private var notes: [String] = []
    @State private var error: String?
    @State private var busy = false
    @State private var draft: String?
    @State private var saved = false

    private static let formats = ["base64", "base64url", "base32", "hex", "url", "html", "unicode"]
    private static let keyKinds = ["ed25519", "p256", "p384", "rsa3072", "rsa4096"]

    var body: some View {
        Form {
            Section { Text(L10n.tools.subtitle).font(.subheadline).foregroundStyle(Color.mist) }
            Section {
                Picker(L10n.tools.choose, selection: $panel) {
                    ForEach(Panel.allCases) { Text($0.title).tag($0) }
                }
                if panel == .encoding {
                    Picker(L10n.tools.encoding.format, selection: $format) {
                        ForEach(Self.formats, id: \.self) { Text($0).tag($0) }
                    }
                }
                if panel == .keys {
                    Picker(L10n.tools.keys.type, selection: $keyKind) {
                        ForEach(Self.keyKinds, id: \.self) { Text($0).tag($0) }
                    }
                }
                if panel != .random && panel != .keys {
                    TextEditor(text: $input)
                        .font(.secret(.footnote))
                        .frame(minHeight: 120)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .environment(\.layoutDirection, .leftToRight)
                        .accessibilityLabel(panel.title)
                        .accessibilityIdentifier("tools-input")
                }
            }
            Section { actions }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
            if !notes.isEmpty {
                Section { ForEach(notes, id: \.self) { Text($0) } }
            }
            ForEach(Array(output.enumerated()), id: \.offset) { _, row in
                Section(row.label) {
                    Text(row.value)
                        .font(.secret(.footnote))
                        .textSelection(.enabled)
                        .environment(\.layoutDirection, .leftToRight)
                    Button(L10n.copy.action(what: row.label)) { model.copy(row.value, what: row.label, secret: false) }
                }
            }
            if draft != nil {
                Section {
                    Button(saved ? L10n.tools.savedShort : L10n.tools.save) { Task { await save() } }
                        .disabled(saved)
                }
            }
            Section { Text(L10n.tools.localNote).font(.footnote).foregroundStyle(Color.mist) }
        }
        .navigationTitle(L10n.tools.title)
        .onChange(of: panel) { reset() }
    }

    @ViewBuilder private var actions: some View {
        switch panel {
        case .jwt: runButton(L10n.tools.jwt.read) { try await readToken() }
        case .certificates: runButton(L10n.tools.certs.readAction) { try await readCertificate() }
        case .hash: runButton(L10n.tools.hash.run) { try await hash() }
        case .encoding:
            runButton(L10n.tools.encoding.encode) { try await encode("encoding.encode") }
            runButton(L10n.tools.encoding.decode) { try await encode("encoding.decode") }
        case .random: runButton(L10n.tools.random.make) { try await random() }
        case .keys: runButton(L10n.tools.keys.generateAction) { try await generateKey() }
        }
    }

    private func runButton(_ title: String, action: @escaping () async throws -> Void) -> some View {
        Button(title) {
            Task {
                reset()
                busy = true
                defer { busy = false }
                do {
                    try await action()
                } catch {
                    self.error = Self.message(error)
                }
            }
        }
        .disabled(busy)
    }

    private func reset() {
        output = []
        notes = []
        error = nil
        draft = nil
        saved = false
    }

    /// The core's error codes come back in the message.
    private static func message(_ error: Error) -> String {
        let text = String(describing: error)
        if text.contains("invalid_token") { return L10n.tools.errors.invalid_token }
        if text.contains("invalid_certificate") { return L10n.tools.errors.invalid_certificate }
        if text.contains("invalid_encoding") { return L10n.tools.errors.invalid_encoding }
        return L10n.tools.errors.unknown
    }

    /// Off the main actor: RSA keys take seconds.
    private func run(_ op: String, _ input: [String: Any]) async throws -> [String: Any] {
        let text = String(decoding: try JSONSerialization.data(withJSONObject: input), as: UTF8.self)
        let reply = try await Task.detached { try toolkitRun(op: op, input: text) }.value
        return try JSONSerialization.jsonObject(with: Data(reply.utf8)) as? [String: Any] ?? [:]
    }

    private func pretty(_ value: Any?) -> String? {
        guard let value, JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    private func readToken() async throws {
        let decoded = try await run("jwt.decode", ["token": input])
        for warning in decoded["warnings"] as? [String] ?? [] {
            switch warning {
            case "algNone": notes.append(L10n.tools.jwt.warnings.algNone)
            case "expired": notes.append(L10n.tools.jwt.warnings.expired)
            case "notYetValid": notes.append(L10n.tools.jwt.warnings.notYetValid)
            case "noExpiry": notes.append(L10n.tools.jwt.warnings.noExpiry)
            default: break
            }
        }
        notes.append(L10n.tools.jwt.unverified)
        if let header = pretty(decoded["header"]) { output.append((L10n.tools.jwt.header, header)) }
        if let payload = pretty(decoded["payload"]) { output.append((L10n.tools.jwt.payload, payload)) }
    }

    private func readCertificate() async throws {
        let report = try await run("cert.read", ["text": input])
        for certificate in report["certificates"] as? [[String: Any]] ?? [] {
            output.append((L10n.tools.certs.subject, certificate["subject"] as? String ?? ""))
            output.append((L10n.tools.certs.issuer, certificate["issuer"] as? String ?? ""))
            let names = (certificate["sans"] as? [[String: Any]] ?? []).compactMap { $0["value"] as? String }
            output.append((L10n.tools.certs.names, names.joined(separator: ", ")))
            let days = certificate["daysLeft"] as? Int ?? 0
            output.append((L10n.tools.certs.expires, L10n.tools.certs.daysLeft(count: days)))
            output.append(("SHA-256", certificate["sha256"] as? String ?? ""))
        }
    }

    private func hash() async throws {
        let result = try await run("hash.digest", ["text": input])
        for hash in result["hashes"] as? [[String: Any]] ?? [] {
            output.append((hash["algorithm"] as? String ?? "", hash["hex"] as? String ?? ""))
        }
    }

    private func encode(_ op: String) async throws {
        let body: [String: Any] = op == "encoding.encode" ? ["format": format, "text": input] : ["format": format, "value": input]
        let result = try await run(op, body)
        let value = result["value"] as? String ?? result["text"] as? String ?? result["hex"] as? String ?? ""
        output.append((L10n.tools.encoding.result, value))
    }

    private func random() async throws {
        let token = try await run("random.token", ["shape": "base62"])
        output.append((L10n.tools.random.result, token["value"] as? String ?? ""))
        let uuid = try await run("random.uuid", ["version": 7])
        output.append(("UUID v7", (uuid["values"] as? [String])?.first ?? ""))
    }

    private func generateKey() async throws {
        let key = try await run("key.generate", ["type": keyKind])
        output.append((L10n.tools.keys.publicKey, key["publicOpenssh"] as? String ?? ""))
        let item = try await run("item.key", [
            "title": L10n.tools.keys.titleFor(name: keyKind),
            "kind": "asymmetric",
            "algorithm": keyKind,
            "privateKey": key["privateKey"] as? String ?? "",
            "publicKey": key["publicPem"] as? String ?? "",
        ])
        draft = String(decoding: try JSONSerialization.data(withJSONObject: item), as: UTF8.self)
    }

    private func save() async {
        guard let draft, let vault = directory.personal else { return }
        do {
            _ = try await model.vault.saveToolItem(vaultId: vault.id, draftJson: draft)
            saved = true
        } catch {
            self.error = Self.message(error)
        }
    }
}
