import OctaPassResources
import OctaPassVault
import SwiftUI

extension EnvironmentDetails {
    static let empty = EnvironmentDetails(project: nil, projectName: nil, stage: nil, variables: [], notes: nil)
}

enum StageNames {
    /// A stage in the reader's language; a custom one as typed; none is the project's shared set.
    static func label(_ stage: String?) -> String {
        guard let stage, !stage.isEmpty else { return L10n.env.sharedSet }
        if let known = knownEnvironmentStage(stage: stage) {
            return L10n.text(forKey: "env.stages.\(known)") ?? stage
        }
        return stage
    }

    static func color(_ stage: String) -> Color {
        isProductionStage(stage: stage) ? .danger : .trust
    }
}

/// An environment's fields in the editor (the web vault's `EnvironmentSection`): project and stage,
/// the variables with their order, and a `.env` file pasted or chosen.
struct EnvironmentEditor: View {
    @Environment(AppModel.self) private var model
    @Binding var environment: EnvironmentDetails
    let errors: [String: String]
    @State private var pasting = false
    @State private var paste = ""
    @State private var picking = false

    var body: some View {
        Section {
            EditorField(label: L10n.env.project, text: $environment.project.text, error: errors["project"], hint: L10n.env.projectHint,
                        placeholder: L10n.env.projectPlaceholder, keyboard: .asciiCapable, ltr: true)
                .accessibilityIdentifier("env-project")
            EditorField(label: L10n.env.stage, text: $environment.stage.text, error: errors["stage"], hint: L10n.env.stageHint,
                        placeholder: L10n.env.stagePlaceholder, keyboard: .asciiCapable, ltr: true)
                .accessibilityIdentifier("env-stage")
        } header: {
            Text(L10n.env.projectAndStage)
        } footer: {
            Text(L10n.env.mergeHint)
        }
        Section(L10n.env.variables) {
            if environment.variables.isEmpty {
                Text(L10n.env.noVariables).foregroundStyle(Color.mist)
            }
            ForEach(environment.variables.indices, id: \.self) { index in
                variableRow(index)
            }
            Button {
                environment.variables.append(newEnvironmentVariable())
            } label: { Label(L10n.env.addVariable, systemImage: "plus") }
                .accessibilityIdentifier("env-add")
            Button {
                pasting.toggle()
            } label: { Label(L10n.env.paste, systemImage: "doc.on.clipboard") }
                .accessibilityIdentifier("env-paste")
            Button {
                picking = true
            } label: { Label(L10n.env.importFile, systemImage: "square.and.arrow.down") }
                .accessibilityIdentifier("env-import-file")
                .filePicker(isPresented: $picking) { urls in
                    if let url = urls.first { readFile(url) }
                }
            if pasting {
                VStack(alignment: .leading, spacing: 4) {
                    TextEditor(text: $paste)
                        .font(.secret(.footnote))
                        .frame(minHeight: 110)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .environment(\.layoutDirection, .leftToRight)
                        .accessibilityLabel(L10n.env.paste)
                        .accessibilityIdentifier("env-paste-text")
                    Text(L10n.env.pasteHint).font(.footnote).foregroundStyle(Color.mist)
                }
                Button(L10n.env.addPasted, action: addPasted)
                    .accessibilityIdentifier("env-add-pasted")
            }
        }
        Section(L10n.fields.notes) {
            TextEditor(text: $environment.notes.text).frame(minHeight: 80).accessibilityLabel(L10n.fields.notes)
        }
    }

    private func variableRow(_ index: Int) -> some View {
        let variable = $environment.variables[index]
        return VStack(alignment: .leading, spacing: 8) {
            TextField(L10n.env.key, text: variable.key, prompt: Text(verbatim: "DATABASE_URL"))
                .font(.secret())
                .keyboardType(.asciiCapable)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .environment(\.layoutDirection, .leftToRight)
                .accessibilityLabel(L10n.env.key)
                .accessibilityIdentifier("env-key-\(index)")
            if let error = errors["variables.\(index).key"] {
                Text(error).font(.footnote).foregroundStyle(Color.dangerText)
            }
            Group {
                if variable.wrappedValue.concealed {
                    MaskedField(label: L10n.env.value, text: variable.value)
                } else {
                    TextField(L10n.env.value, text: variable.value)
                        .font(.secret())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
            }
            .environment(\.layoutDirection, .leftToRight)
            .accessibilityIdentifier("env-value-\(index)")
            TextField(L10n.env.note, text: variable.note.text, prompt: Text(L10n.env.notePlaceholder))
                .font(.footnote)
            Toggle(L10n.env.concealed, isOn: variable.concealed).font(.footnote)
            HStack(spacing: 20) {
                Button { move(index, by: -1) } label: { Image(systemName: "arrow.up") }
                    .disabled(index == 0)
                    .accessibilityLabel(L10n.env.moveUp)
                Button { move(index, by: 1) } label: { Image(systemName: "arrow.down") }
                    .disabled(index == environment.variables.count - 1)
                    .accessibilityLabel(L10n.env.moveDown)
                Spacer()
                Button(role: .destructive) { environment.variables.remove(at: index) } label: { Image(systemName: "minus.circle.fill") }
                    .accessibilityLabel(L10n.env.removeVariable)
            }
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 4)
    }

    private func move(_ index: Int, by offset: Int) {
        let target = index + offset
        guard environment.variables.indices.contains(target) else { return }
        environment.variables.swapAt(index, target)
    }

    private func addPasted() {
        do {
            let merged = try mergeDotenv(variables: environment.variables, text: paste)
            environment.variables = merged.variables
            paste = ""
            pasting = false
            model.confirm(L10n.env.imported(count: Int(merged.count)))
        } catch {
            model.toast = Toast(message: L10n.env.importFailed(reason: error.reason), tone: .danger)
        }
    }

    private func readFile(_ url: URL) {
        guard let file = try? PickedFiles.copy(url) else { return }
        defer { PickedFiles.discard(file) }
        paste = (try? String(contentsOf: file.url, encoding: .utf8)) ?? ""
        pasting = true
    }
}

/// An environment's project, stage and variables, with copy and save as `.env`. Names shown here
/// aren't secret; concealed values and the whole file ask first.
struct EnvironmentFields: View {
    @Environment(AppModel.self) private var model
    let item: Item
    let environment: EnvironmentDetails
    @State private var missing: [String] = []

    var body: some View {
        if environment.project != nil || environment.stage != nil {
            Section(L10n.env.projectAndStage) {
                if let project = environment.project {
                    FieldRow(label: L10n.env.project, value: project, ltr: true)
                }
                FieldRow(label: L10n.env.stage, value: StageNames.label(environment.stage), copyable: false)
            }
        }
        Section(L10n.env.variables) {
            if environment.variables.isEmpty {
                Text(L10n.env.noVariables).foregroundStyle(Color.mist)
            }
            ForEach(environment.variables, id: \.key) { variable in
                if variable.concealed {
                    SecretFieldRow(label: variable.key, value: variable.value, what: variable.note ?? L10n.env.value)
                } else {
                    FieldRow(label: variable.key, value: variable.value, ltr: true, mono: true)
                }
            }
        }
        .task(id: model.itemsVersion) { await loadMissing() }
        Section {
            Button { Task { await copyDotenv() } } label: { Label(L10n.env.copyDotenv, systemImage: "doc.on.doc") }
                .accessibilityIdentifier("env-copy-dotenv")
            Button { Task { await saveDotenv() } } label: { Label(L10n.env.downloadDotenv, systemImage: "square.and.arrow.up") }
                .accessibilityIdentifier("env-save-dotenv")
        }
        if !missing.isEmpty {
            Notice(text: L10n.env.missingInStage(keys: missing.joined(separator: ", ")), tone: .info)
                .listRowBackground(Color.clear)
                .accessibilityIdentifier("env-missing")
        }
        if isProductionStage(stage: environment.stage) {
            Notice(text: L10n.env.productionWarning, tone: .warn).listRowBackground(Color.clear)
                .accessibilityIdentifier("env-production")
        }
        if let notes = environment.notes, !notes.isEmpty {
            Section(L10n.fields.notes) { SecretFieldRow(label: L10n.fields.notes, value: notes, multiline: true) }
        }
    }

    private func loadMissing() async {
        var filter = ListScope.type(.environment).filter
        filter.project = environment.project
        guard environment.project != nil, let items = try? await model.vault.listItems(filter: filter) else { return }
        missing = missingEnvironmentKeys(itemId: item.id, details: environment, items: items)
    }

    private func copyDotenv() async {
        guard await model.confirmReveal() else { return }
        do {
            model.copy(try environmentDotenv(details: environment), what: L10n.env.copyDotenvWhat, item: item.id)
        } catch {
            model.show(error)
        }
    }

    private func saveDotenv() async {
        // A file of secrets leaving the app: an export, asked every time.
        guard await model.confirmIdentity() else { return }
        do {
            let name = environmentFileName(title: item.title)
            await ShareFile.write(model: model, name: name, text: try environmentDotenv(details: environment), done: L10n.env.downloaded(name: name))
        } catch {
            model.show(error)
        }
    }
}

/// The filters above an environment list, for the projects and stages it holds.
struct EnvironmentFilters: View {
    let choices: EnvironmentChoices
    @Binding var project: String?
    @Binding var stage: String?

    var body: some View {
        HStack(spacing: 12) {
            if !choices.projects.isEmpty {
                Picker(L10n.env.filterProject, selection: $project) {
                    Text(L10n.env.allProjects).tag(String?.none)
                    ForEach(choices.projects, id: \.self) { Text($0).tag(String?.some($0)) }
                }
                .accessibilityIdentifier("env-filter-project")
            }
            if !choices.stages.isEmpty {
                Picker(L10n.env.filterStage, selection: $stage) {
                    Text(L10n.env.allStages).tag(String?.none)
                    ForEach(choices.stages, id: \.self) { Text(StageNames.label($0)).tag(String?.some($0)) }
                }
                .accessibilityIdentifier("env-filter-stage")
            }
        }
        .pickerStyle(.menu)
    }
}
