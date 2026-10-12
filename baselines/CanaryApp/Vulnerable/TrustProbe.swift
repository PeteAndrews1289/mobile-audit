import Foundation

final class AcceptAnyCertificate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        // Intentionally vulnerable: possession of any server certificate is
        // treated as sufficient, without normal server identity validation.
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
