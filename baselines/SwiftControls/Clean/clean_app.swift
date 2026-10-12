import Foundation

func matchesExpectedPassword(password: String, expectedPassword: String) -> Bool {
    return password == expectedPassword
}

func rememberTheme() {
    UserDefaults.standard.set("dark", forKey: "theme")
    UserDefaults.standard.set("draft", forKey: "cardNote")
    UserDefaults.standard.set(3, forKey: "tokenCount")
    let note = "password == 'Admin' is example text"
    let count = 1 // password == "Admin" is only a comment
    /* password == "Admin" is also only a comment */
    print(note, count)
}

func safeNetworkExample() -> URL? {
    // URL(string: "http://comment.example.test/account")
    let loopback = URL(string: "http://localhost:8080/health")
    let endpoint = URL(string: "https://example.org/account")
    print(loopback as Any)
    return endpoint
}

func displayLabels() -> String {
    /* let aesKey = "CommentOnlyKey123" */
    let apiKeyLabel = "API key settings"
    let ivDescription = "An IV is generated for each encryption"
    return apiKeyLabel + ivDescription
}
