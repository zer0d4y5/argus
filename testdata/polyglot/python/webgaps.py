# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
# Web-gap classes caught by argus/curated rules the registry packs miss.
import requests
import yaml
from lxml import etree


def ssrf(user_url):
    # PLANT(py-ssrf-web, min-profile=standard, CWE-918): request to a user-controlled URL (argus/curated)
    return requests.get(user_url, timeout=5).text


def xxe(untrusted_bytes):
    # PLANT(py-xxe-web, min-profile=standard, CWE-611): lxml parse without disabling entity resolution (argus/curated)
    return etree.fromstring(untrusted_bytes)


def unsafe_yaml(text):
    # PLANT(py-deser-yaml, min-profile=standard, CWE-502): yaml.load without SafeLoader (argus/curated)
    return yaml.load(text)
