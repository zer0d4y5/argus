// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.
using System.Net;
using System.Xml;

class WebGaps {
    string Ssrf(string userUrl) {
        // PLANT(csharp-ssrf-web, min-profile=standard, CWE-918): request to a user-controlled URL (argus/curated)
        return new WebClient().DownloadString(userUrl);
    }

    void Xxe(string untrusted) {
        // PLANT(csharp-xxe, min-profile=standard, CWE-611): XmlDocument load without XmlResolver=null (argus/curated)
        var doc = new XmlDocument();
        doc.LoadXml(untrusted);
    }
}
