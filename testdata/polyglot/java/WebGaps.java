// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap class caught by an argus/curated rule the registry packs miss.
import java.net.URL;
import java.net.URLConnection;

public class WebGaps {
    public URLConnection ssrf(String userInput) throws Exception {
        // PLANT(java-ssrf-web, min-profile=standard, CWE-918): URL from user input opened (argus/curated)
        URL url = new URL(userInput);
        return url.openConnection();
    }
}
