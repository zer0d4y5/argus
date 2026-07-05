// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import java.util.Random
import javax.crypto.Cipher

fun weakEcbCipher(): Cipher {
    // PLANT(kt-ecb-cipher, min-profile=max, CWE-327): AES in ECB mode
    return Cipher.getInstance("AES/ECB/PKCS5Padding")
}

fun token(): String {
    // PLANT-GAP: predictable PRNG for a security token (CWE-330) — caught by no profile
    return Random().nextInt().toString()
}
