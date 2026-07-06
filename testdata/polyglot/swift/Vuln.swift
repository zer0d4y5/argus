// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Never compiled; exists only to be scanned by semgrep.
//
// Swift DID NOT LAND this session: p/swift (a thin registry pack) plus
// p/default caught NONE of the plants below. Per the earn-your-slot bar the
// language is not claimed as supported — .swift stays "unsupported source"
// in skip accounting, and every plant here is an honest PLANT-GAP. Documented
// in docs/coverage.md and the PR, not silently dropped.

import Foundation
import CommonCrypto

func takeInput() -> String {
    return CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
}

// PLANT-GAP (swift-sqli, CWE-89): SQL built by string interpolation
func sqli(userInput: String, db: OpaquePointer?) {
    let query = "SELECT * FROM users WHERE name = '\(userInput)'"
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(db, query, -1, &stmt, nil)
}

// PLANT-GAP (swift-weak-hash, CWE-328): MD5 over sensitive input
func weakHash(userInput: String) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    let data = Array(userInput.utf8)
    CC_MD5(data, CC_LONG(data.count), &digest)
    return digest
}

// PLANT-GAP (swift-tls-verify, CWE-295): TLS certificate validation disabled
final class TrustAll: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let cred = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, cred)
    }
}

// PLANT-GAP (swift-cmdi, CWE-78): Process invoking a shell with concatenated input
func runShell(userInput: String) {
    let task = Process()
    task.launchPath = "/bin/sh"
    task.arguments = ["-c", "echo " + userInput]
    try? task.run()
}

// PLANT-GAP (swift-hardcoded-secret, CWE-798): hardcoded credential
let apiKey = "AKIAIOSFODNN7EXAMPLE"

func main() {
    let input = takeInput()
    sqli(userInput: input, db: nil)
    _ = weakHash(userInput: input)
    runShell(userInput: input)
    _ = apiKey
}
