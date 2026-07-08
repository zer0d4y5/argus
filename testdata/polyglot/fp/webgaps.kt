// Safe-code plants for the FP measurement eval.
import java.net.URL
import java.io.File
import android.webkit.WebView

// PLANT-FP(kotlin-safe-ssrf, CWE-918): constant URL.
fun fetch() = URL("https://api.example.com/health").openConnection()

// PLANT-FP(kotlin-safe-path, CWE-22): constant path.
fun readConfig() = File("/etc/myapp/config.yaml").readText()

// PLANT-FP(kotlin-safe-webview, CWE-749): JavaScript left disabled.
fun web(webView: WebView) { webView.settings.javaScriptEnabled = false }
