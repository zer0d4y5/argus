# Safe-code plants for the FP measurement eval (see fp/safe.py header).
# The correct form of each web-gap class; flagging one is a measured FP.
import requests
import yaml
from lxml import etree


def safe_fetch():
    # PLANT-FP(py-safe-ssrf, CWE-918): constant, trusted URL.
    return requests.get("https://api.example.com/status", timeout=5).text


def safe_xml(data):
    # PLANT-FP(py-safe-xxe, CWE-611): entity resolution disabled on the parser.
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(data, parser)


def safe_yaml(text):
    # PLANT-FP(py-safe-yaml, CWE-502): SafeLoader forbids arbitrary objects.
    return yaml.load(text, Loader=yaml.SafeLoader)
