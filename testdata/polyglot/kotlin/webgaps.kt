// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.
import java.net.URL
import java.io.File
import android.webkit.WebView

fun ssrf(userUrl: String) =
    // PLANT(kotlin-ssrf-url, min-profile=standard, CWE-918): URL from user input opened (argus/curated)
    URL(userUrl).openConnection()

fun read(userPath: String) =
    // PLANT(kotlin-path-file, min-profile=standard, CWE-22): file read from unsanitized path (argus/curated)
    File(userPath).readText()

fun web(webView: WebView) {
    // PLANT(kotlin-webview-js, min-profile=standard, CWE-749): JavaScript enabled on a WebView (argus/curated)
    webView.settings.javaScriptEnabled = true
}
