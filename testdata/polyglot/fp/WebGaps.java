// Safe-code plants for the FP measurement eval.
import java.net.URL;
import java.net.URLConnection;

public class WebGaps {
    // PLANT-FP(java-safe-ssrf, CWE-918): constant, hard-coded URL.
    public URLConnection safeFetch() throws Exception {
        return new URL("https://api.example.com/status").openConnection();
    }
}
