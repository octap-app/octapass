import OctaPassResources
import OctaPassVault
import SwiftUI

/// Bank accounts, API credentials, software licences, ID documents, crypto wallets, databases,
/// custom items and custom templates. The vault's `fieldSpecs` says what each holds, so one editor
/// and one detail view cover all of them (the web vault's `TypedItems`).
enum StructuredNames {
    static func label(_ key: String) -> String {
        L10n.text(forKey: "itemFields.\(key)") ?? key
    }

    /// A choice's words, or what another app wrote when it's not one of ours.
    static func choice(_ key: String, _ value: String) -> String {
        L10n.text(forKey: "itemChoices.\(key).\(value)") ?? value
    }

    static func shown(_ spec: FieldSpec, _ value: String) -> String {
        switch spec.style {
        case .choice: choice(spec.key, value)
        case .date: DateText.long(value)
        default: value
        }
    }
}

extension StructuredDetails {
    static var empty: StructuredDetails {
        StructuredDetails(values: [], addresses: [], fields: [], templateId: nil, templateName: nil, notes: nil, customFields: [], passwordHistory: [])
    }

    func value(_ key: String) -> String {
        values.first { $0.key == key }?.value ?? ""
    }

    mutating func set(_ key: String, _ value: String) {
        values.removeAll { $0.key == key }
        if !value.isEmpty { values.append(FieldValue(key: key, value: value)) }
    }
}

// MARK: Editing

struct StructuredEditor: View {
    @Environment(AppModel.self) private var model
    let type: ItemType
    let vaultId: String
    let title: String
    let isNew: Bool
    @Binding var details: StructuredDetails
    let errors: [String: String]
    @State private var templates: [ItemSummary] = []

    private func binding(_ key: String) -> Binding<String> {
        Binding(get: { details.value(key) }, set: { details.set(key, $0) })
    }

    var body: some View {
        let specs = fieldSpecs(itemType: type)
        if !specs.isEmpty {
            Section(type.typeName) {
                ForEach(specs, id: \.key) { spec in
                    StructuredInput(spec: spec, text: binding(spec.key), error: errors[spec.key])
                }
            }
        }
        if type == .cryptoWallet { AddressesEditor(addresses: $details.addresses, errors: errors) }
        if type == .custom {
            if isNew, !templates.isEmpty { templatePicker }
            TypedFieldsEditor(fields: $details.fields, withValues: true)
            if !details.fields.isEmpty {
                Section { Button(L10n.typedItems.saveAsTemplate) { Task { await saveAsTemplate() } } }
            }
        }
        if type == .customTemplate {
            Section { Text(L10n.typedItems.templateHelp).font(.footnote).foregroundStyle(Color.mist) }
            TypedFieldsEditor(fields: $details.fields, withValues: false)
        } else {
            if type != .custom { CustomFieldsEditor(fields: $details.customFields) }
            Section(L10n.fields.notes) {
                TextEditor(text: $details.notes.text).frame(minHeight: 100).accessibilityLabel(L10n.fields.notes)
            }
        }
    }

    private var templatePicker: some View {
        Section(L10n.typedItems.template) {
            Picker(L10n.typedItems.useTemplate, selection: Binding(get: { details.templateId ?? "" }, set: { choose($0) })) {
                Text(L10n.typedItems.noTemplate).tag("")
                ForEach(templates, id: \.id) { Text($0.title).tag($0.id) }
            }
        }
        .task(id: isNew) { await loadTemplates() }
    }

    private func loadTemplates() async {
        templates = (try? await model.vault.listItems(filter: ItemFilter(vaultId: nil, itemType: .customTemplate, query: nil, trash: false, favorites: false, passkeys: false, totp: false))) ?? []
    }

    private func choose(_ id: String) {
        guard !id.isEmpty else {
            details.templateId = nil
            details.templateName = nil
            return
        }
        Task {
            guard let template = try? await model.vault.getItem(id: id), case let .structured(_, fields) = template.details else { return }
            details.templateId = id
            details.templateName = template.title
            details.fields = fieldsFromTemplate(template: fields)
        }
    }

    private func saveAsTemplate() async {
        let name = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            model.toast = Toast(message: L10n.typedItems.templateNeedsName, tone: .danger)
            return
        }
        var draft = newItemDraft(itemType: .customTemplate, vaultId: vaultId)
        draft.title = name
        draft.details = .structured(itemType: .customTemplate, structured: templateFromItem(item: details))
        do {
            _ = try await model.vault.saveItem(draft: draft)
            model.confirm(L10n.typedItems.templateSaved(name: name))
        } catch {
            model.toast = Toast(message: error.message, tone: .danger)
        }
    }
}

private struct StructuredInput: View {
    let spec: FieldSpec
    @Binding var text: String
    let error: String?

    private var label: String { StructuredNames.label(spec.key) }

    var body: some View {
        switch spec.style {
        case .choice:
            Picker(label, selection: $text) {
                Text("").tag("")
                ForEach(spec.choices, id: \.self) { Text(StructuredNames.choice(spec.key, $0)).tag($0) }
                if !text.isEmpty, !spec.choices.contains(text) { Text(text).tag(text) }
            }
        case .secret:
            VStack(alignment: .leading, spacing: 4) {
                SecureField(label, text: $text).font(.secret()).accessibilityIdentifier("field-\(spec.key)")
                if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
            }
        case .secretLong:
            LongSecretEditor(label: label, text: $text, error: error)
        case .code:
            EditorField(label: label, text: $text, error: error, keyboard: .asciiCapable, mono: true, ltr: true)
        case .date:
            EditorField(label: label, text: $text, error: error, placeholder: "YYYY-MM-DD", keyboard: .numbersAndPunctuation, ltr: true)
        case .email:
            EditorField(label: label, text: $text, error: error, keyboard: .emailAddress, ltr: true)
        case .port:
            EditorField(label: label, text: $text, error: error, keyboard: .numberPad, ltr: true)
        case .text:
            EditorField(label: label, text: $text, error: error)
        }
    }
}

/// A long secret stays hidden in the editor too, until asked for.
private struct LongSecretEditor: View {
    let label: String
    @Binding var text: String
    let error: String?
    @State private var shown = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(label).font(.caption.weight(.medium)).foregroundStyle(Color.mist)
                Spacer()
                if !text.isEmpty {
                    Button { shown.toggle() } label: { Image(systemName: shown ? "eye.slash" : "eye") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(shown ? L10n.typedItems.secretHide(what: label) : L10n.typedItems.secretShow(what: label))
                }
            }
            if shown || text.isEmpty {
                TextEditor(text: $text)
                    .font(.secret())
                    .frame(minHeight: 80)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .environment(\.layoutDirection, .leftToRight)
                    .accessibilityLabel(label)
            } else {
                Text(String(repeating: "•", count: 16)).font(.secret()).accessibilityLabel(L10n.phone.native.hidden)
            }
            if let error { Text(error).font(.footnote).foregroundStyle(Color.dangerText) }
        }
        .onDisappear { shown = false }
    }
}

private struct AddressesEditor: View {
    @Binding var addresses: [WalletAddress]
    let errors: [String: String]

    var body: some View {
        Section(L10n.typedItems.addresses) {
            ForEach(addresses.indices, id: \.self) { index in
                VStack(alignment: .leading) {
                    HStack {
                        EditorField(label: L10n.typedItems.network, text: $addresses[index].network, hint: L10n.typedItems.networkHint, keyboard: .asciiCapable, ltr: true)
                        Button(role: .destructive) { addresses.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.typedItems.removeAddress(n: index + 1))
                    }
                    EditorField(label: L10n.typedItems.address, text: $addresses[index].address, error: errors["addresses.\(index)"], keyboard: .asciiCapable, mono: true, ltr: true)
                    EditorField(label: L10n.typedItems.addressLabel, text: $addresses[index].label.text)
                }
            }
            Button { addresses.append(WalletAddress(network: "bitcoin", address: "", label: nil)) } label: { Label(L10n.typedItems.addAddress, systemImage: "plus") }
        }
    }
}

private struct TypedFieldsEditor: View {
    @Binding var fields: [TypedField]
    let withValues: Bool

    var body: some View {
        Section(L10n.typedItems.fields) {
            ForEach(fields.indices, id: \.self) { index in
                VStack(alignment: .leading) {
                    HStack {
                        TextField(L10n.editor.fieldLabel, text: $fields[index].label)
                        Button(role: .destructive) { fields.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel(L10n.editor.removeField(label: fields[index].label.isEmpty ? L10n.editor.fieldN(n: index + 1) : fields[index].label))
                    }
                    if withValues {
                        if customKindIsPlain(kind: fields[index].kind) || fields[index].kind == "multiline" {
                            TextField(L10n.editor.fieldValue, text: $fields[index].value, axis: fields[index].kind == "multiline" ? .vertical : .horizontal)
                        } else {
                            SecureField(L10n.editor.fieldValue, text: $fields[index].value)
                        }
                    }
                    Picker(L10n.typedItems.fieldKind, selection: $fields[index].kind) {
                        ForEach(customFieldKinds(), id: \.self) { Text(StructuredNames.choice("customKind", $0)).tag($0) }
                        if !customFieldKinds().contains(fields[index].kind) { Text(fields[index].kind).tag(fields[index].kind) }
                    }
                    .font(.footnote)
                }
            }
            Button { fields.append(TypedField(label: "", value: "", kind: "text")) } label: { Label(L10n.editor.addField, systemImage: "plus") }
        }
    }
}

// MARK: Showing

struct StructuredFields: View {
    let item: Item
    let type: ItemType
    let details: StructuredDetails

    var body: some View {
        let specs = fieldSpecs(itemType: type).filter { !details.value($0.key).isEmpty }
        if !specs.isEmpty {
            Section {
                ForEach(specs, id: \.key) { spec in
                    let value = details.value(spec.key)
                    switch spec.style {
                    case .secret:
                        SecretFieldRow(label: StructuredNames.label(spec.key), value: value)
                    case .secretLong:
                        SecretFieldRow(label: StructuredNames.label(spec.key), value: value, multiline: true)
                    default:
                        FieldRow(label: StructuredNames.label(spec.key), value: StructuredNames.shown(spec, value), copyable: spec.style != .choice, ltr: spec.style == .code || spec.style == .port || spec.style == .email, mono: spec.style == .code)
                    }
                }
            }
        }
        if !details.addresses.isEmpty {
            Section(L10n.typedItems.addresses) {
                ForEach(details.addresses.indices, id: \.self) { index in
                    let entry = details.addresses[index]
                    FieldRow(label: entry.label ?? entry.network, value: entry.address, what: L10n.typedItems.address, ltr: true, mono: true)
                }
            }
        }
        if type == .custom { customFields }
        if type == .customTemplate, !details.fields.isEmpty {
            Section(L10n.typedItems.fields) {
                ForEach(details.fields.indices, id: \.self) { index in
                    let field = details.fields[index]
                    FieldRow(label: field.label, value: StructuredNames.choice("customKind", field.kind), copyable: false)
                }
            }
        }
        CustomFieldsSection(fields: details.customFields)
        if let notes = details.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
        PasswordHistorySection(history: details.passwordHistory)
    }

    @ViewBuilder private var customFields: some View {
        Section {
            if let name = details.templateName, !name.isEmpty {
                FieldRow(label: L10n.typedItems.template, value: name, copyable: false)
            }
            ForEach(details.fields.indices, id: \.self) { index in
                let field = details.fields[index]
                if !field.value.isEmpty {
                    if field.kind == "totp" {
                        LiveCode(secret: field.value)
                    } else if field.kind == "multiline" {
                        SecretFieldRow(label: field.label, value: field.value, multiline: true)
                    } else if customKindIsPlain(kind: field.kind) {
                        FieldRow(label: field.label, value: field.kind == "date" ? DateText.long(field.value) : field.value, ltr: field.kind != "text")
                    } else {
                        SecretFieldRow(label: field.label, value: field.value)
                    }
                }
            }
        }
    }
}
