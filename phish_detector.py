# Phishing Awareness & URL Checker
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = ["login", "verify", "update", "password", "bank", "free", "urgent"]

def check_url(url):
    findings = []
    parsed = urlparse(url)

    if parsed.scheme == "http":
        findings.append("Uses HTTP (not secure)")
    if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
        findings.append("IP address instead of domain")
    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            findings.append(f"Contains '{word}'")

    if findings:
        return f"⚠️ Suspicious: {', '.join(findings)}"
    else:
        return "✅ Looks safe"

if __name__ == "__main__":
    test_urls = [
        "http://secure-bank-login.com",
        "https://google.com",
        "http://198.51.100.23/login"
    ]
    for u in test_urls:
        print(u, "->", check_url(u))
