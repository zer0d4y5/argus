// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import java.util.Random;
import javax.crypto.Cipher;

public class Insecure {
    static String token() {
        // PLANT(java-weak-random, min-profile=max, CWE-330): predictable PRNG for a security token
        Random r = new Random();
        return Long.toString(r.nextLong());
    }

    static Cipher weakCipher() throws Exception {
        // PLANT(java-weak-cipher, min-profile=fast, CWE-326): DES in ECB mode (semgrep emits CWE-326)
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
