// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.
import Foundation

func store(_ token: String) {
    // PLANT(swift-userdefaults-secret, min-profile=standard, CWE-312): secret written to UserDefaults (argus/curated)
    UserDefaults.standard.set(token, forKey: "authToken")
}

func weakToken() -> Double {
    // PLANT(swift-weak-random, min-profile=standard, CWE-338): weak PRNG for a security value (argus/curated)
    return drand48()
}
