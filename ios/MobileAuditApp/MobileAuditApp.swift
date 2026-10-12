import SwiftUI

@main
struct MobileAuditApp: App {
    @StateObject private var model = AuditModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
        }
    }
}
