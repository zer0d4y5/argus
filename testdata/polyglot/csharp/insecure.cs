// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
using System;
using System.Security.Cryptography;
using System.Xml;

public class Insecure {
    public static ICryptoTransform Weak() {
        // PLANT(cs-weak-cipher, min-profile=standard, CWE-327): DES weak cipher
        var des = DES.Create();
        return des.CreateEncryptor();
    }

    public static void Xxe(string xml) {
        // PLANT-GAP: XXE via explicit resolver (CWE-611) — caught by no profile
        var doc = new XmlDocument();
        doc.XmlResolver = new XmlUrlResolver();
        doc.LoadXml(xml);
    }

    public static string Token() {
        // PLANT(cs-weak-random, min-profile=max, CWE-338): predictable PRNG for a security token
        var r = new Random();
        return r.Next().ToString();
    }
}
