// Safe-code plants for the FP measurement eval.
using System.Net;
using System.Xml;

class WebGapsSafe {
    // PLANT-FP(csharp-safe-ssrf, CWE-918): constant, trusted URL.
    string Fetch() { return new WebClient().DownloadString("https://api.example.com/health"); }

    // PLANT-FP(csharp-safe-xxe, CWE-611): XmlResolver disabled before load.
    void Parse(string x) { var doc = new XmlDocument(); doc.XmlResolver = null; doc.LoadXml(x); }
}
