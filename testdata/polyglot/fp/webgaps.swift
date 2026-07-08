// Safe-code plants for the FP measurement eval.
import Foundation

// PLANT-FP(swift-safe-userdefaults, CWE-312): a non-secret preference key.
func store() { UserDefaults.standard.set("dark", forKey: "themeName") }

// PLANT-FP(swift-safe-random, CWE-338): a cryptographically secure source.
func token() -> UInt32 { return arc4random_uniform(100) }
