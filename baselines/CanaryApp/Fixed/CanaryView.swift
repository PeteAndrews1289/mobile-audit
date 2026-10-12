import Foundation
import Security
import SwiftUI

struct CanaryView: View {
    @State private var displayedNote = "No note opened"
    @State private var status = "Ready"
    @State private var endpoint = "https://example.test"
    private let activeAccount = "alice"
    private let sampleNotes = ["alice": "Alice's invented lab note", "bob": "Bob's invented lab note"]

    var body: some View {
        NavigationStack {
            Form {
                Section("Account and incoming link") {
                    Text("Signed in as: \(activeAccount)")
                    Text(displayedNote)
                    Text("Open mobileauditcanary://note?owner=bob from another app to test the link handler.")
                }
                Section("Storage") {
                    Button("Save invented demo token") { saveDemoToken() }
                }
                Section("Network trust") {
                    TextField("Controlled HTTP(S) endpoint", text: $endpoint)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    Button("Probe endpoint") { probeEndpoint() }
                    Text("Only use an endpoint you control. No request is sent automatically.")
                }
                Text(status)
            }
            .navigationTitle("Canary: fixed")
            .onOpenURL(perform: openIncomingLink)
        }
    }

    private func openIncomingLink(_ url: URL) {
        guard url.scheme == "mobileauditcanary", url.host == "note",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let owner = components.queryItems?.first(where: { $0.name == "owner" })?.value else { return }
        guard owner == activeAccount else {
            displayedNote = "Blocked note belonging to another account"
            return
        }
        displayedNote = sampleNotes[owner] ?? "No note for that owner"
    }

    private func saveDemoToken() {
        let demoValue = "LOCAL-LAB-VALUE-ONLY"
        let identity: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                       kSecAttrService as String: "MobileAuditCanary",
                                       kSecAttrAccount as String: activeAccount]
        SecItemDelete(identity as CFDictionary)
        var item = identity
        item[kSecValueData as String] = Data(demoValue.utf8)
        let result = SecItemAdd(item as CFDictionary, nil)
        status = result == errSecSuccess ? "Invented token saved in Keychain" : "Keychain error: \(result)"
    }

    private func probeEndpoint() {
        guard let url = URL(string: endpoint), ["http", "https"].contains(url.scheme ?? "") else {
            status = "Enter a valid HTTP or HTTPS URL"
            return
        }
        DefaultTrustProbe.session.dataTask(with: url) { _, response, error in
            DispatchQueue.main.async {
                if let error {
                    status = "Request failed: \(error.localizedDescription)"
                } else {
                    status = "HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)"
                }
            }
        }.resume()
    }
}
