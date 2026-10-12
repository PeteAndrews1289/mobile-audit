import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct ContentView: View {
    @EnvironmentObject private var model: AuditModel
    @State private var path: [String] = []
    @State private var showingImporter = false
    @State private var showingAppPicker = false
    @State private var showingManualTarget = false
    @State private var manualName = ""
    @State private var manualBundleID = ""

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    Button {
                        showingImporter = true
                    } label: {
                        Label("Import App Privacy Report", systemImage: "square.and.arrow.down")
                    }
                    .disabled(model.isBusy)
                    Button {
                        showingManualTarget = true
                    } label: {
                        Label("Start a private research case", systemImage: "plus.rectangle.on.folder")
                    }
                    Button {
                        guard let url = Bundle.main.url(forResource: "sample", withExtension: "ndjson") else {
                            model.errorMessage = "The sample report is missing from this build."
                            return
                        }
                        Task { @MainActor in
                            await model.prepareImport(url)
                            showingAppPicker = !model.pendingApps.isEmpty
                        }
                    } label: {
                        Label("Try a sample report", systemImage: "doc.text.magnifyingglass")
                    }
                    .disabled(model.isBusy)
                } footer: {
                    Text("On your iPhone: Settings → Privacy & Security → App Privacy Report → Share. Save the export to Files, then import it here. The sample contains invented activity.")
                }

                if let message = model.statusMessage {
                    Section { Text(message).foregroundStyle(.secondary) }
                }

                Section("Saved apps") {
                    if model.savedBundleIDs.isEmpty {
                        Text("No app snapshots yet.").foregroundStyle(.secondary)
                    }
                    ForEach(model.savedBundleIDs, id: \.self) { bundleID in
                        NavigationLink(value: bundleID) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(bundleID).font(.headline)
                                Text("\(model.snapshots(for: bundleID).count) saved export(s)")
                                    .font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Section("Private research cases") {
                    if model.manualAssessments.isEmpty {
                        Text("No independent cases yet. You can start one for any app, even without a privacy report.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.manualAssessments) { assessment in
                        NavigationLink {
                            ResearchAssessmentView(assessmentID: assessment.id)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(assessment.displayName).font(.headline)
                                Text(assessment.appVersion.isEmpty ? "Version not recorded" : "Version \(assessment.appVersion)")
                                    .font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                    }
                }

                Section("How reports work") {
                    Text("Choose one app after import. Mobile Audit saves only that app's activity and a hash of the original export.")
                    Text("Domain contacts and resource access are observations. They do not show request contents or prove a vulnerability.")
                    Text("A guided assessment on a physical iPhone can record potential attack vectors and produce a provisional security grade after enough documented checks.")
                }
            }
            .navigationTitle("Mobile Audit")
            .navigationDestination(for: String.self) { bundleID in
                AppDetailView(bundleID: bundleID)
            }
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [.json, .plainText, .data]
            ) { result in
                switch result {
                case .success(let url):
                    Task { @MainActor in
                        await model.prepareImport(url)
                        showingAppPicker = !model.pendingApps.isEmpty
                    }
                case .failure(let error):
                    model.errorMessage = error.localizedDescription
                }
            }
            .sheet(isPresented: $showingAppPicker, onDismiss: model.cancelPendingImport) {
                NavigationStack {
                    List(model.pendingApps) { app in
                        Button {
                            Task { @MainActor in
                                let imported = await model.importSelectedApp(app.bundleID)
                                if imported {
                                    showingAppPicker = false
                                    path = [app.bundleID]
                                }
                            }
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(app.bundleID).font(.headline)
                                Text("\(app.networkEntries) network entries · \(app.accessEvents) resource events")
                                    .font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                        .disabled(model.isBusy)
                    }
                    .navigationTitle("Choose an app")
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showingAppPicker = false }
                        }
                    }
                }
            }
            .sheet(isPresented: $showingManualTarget) {
                NavigationStack {
                    Form {
                        Section("App to examine") {
                            TextField("App name", text: $manualName)
                            TextField("Bundle identifier, if known", text: $manualBundleID)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            Text("A bundle identifier helps identify the affected product later, but you can start with the app name.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                        Section {
                            Text("This creates a private case on your device. It does not inspect, launch, or contact the other app.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                    .navigationTitle("New research case")
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showingManualTarget = false }
                        }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Create") {
                                if model.startManualAssessment(name: manualName, bundleID: manualBundleID,
                                                               iOSVersion: UIDevice.current.systemVersion) != nil {
                                    manualName = ""
                                    manualBundleID = ""
                                    showingManualTarget = false
                                }
                            }
                            .disabled(manualName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }
                    }
                }
            }
            .overlay {
                if model.isBusy {
                    ProgressView("Reading report…")
                        .padding(20)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
                }
            }
            .alert("Mobile Audit", isPresented: Binding(
                get: { model.errorMessage != nil },
                set: { if !$0 { model.errorMessage = nil } }
            )) {
                Button("OK") { model.errorMessage = nil }
            } message: {
                Text(model.errorMessage ?? "Unknown error")
            }
        }
    }
}
