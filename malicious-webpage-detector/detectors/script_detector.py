"""
External Script Detector Module
Detects scripts loaded from external or suspicious domains
"""

from urllib.parse import urlparse
from config import MALICIOUS_DOMAINS, SUSPICIOUS_TLDS, TRUSTED_DOMAINS


class ScriptDetector:
    """Detects external and suspicious script sources."""

    def __init__(self, soup, base_domain):
        """
        Initialize the detector.

        Args:
            soup: BeautifulSoup object of the parsed HTML
            base_domain: The base domain of the analyzed page
        """
        self.soup = soup
        self.base_domain = base_domain
        self.findings = []

    def detect(self):
        """Run all external script detection checks."""
        scripts = self.soup.find_all("script", src=True)

        for script in scripts:
            src = script.get("src", "")
            if not src:
                continue

            self._check_external_script(src)

        return self.findings

    def _check_external_script(self, src):
        """Check if script is loaded from an external or suspicious domain."""
        # Skip relative URLs and data URIs
        if src.startswith("/") or src.startswith("./") or src.startswith("../"):
            return
        if src.startswith("data:"):
            return

        # Normalize URL
        if src.startswith("//"):
            src = "https:" + src
        elif not src.startswith(("http://", "https://")):
            return

        try:
            parsed = urlparse(src)
            script_domain = parsed.netloc.lower()
        except Exception:
            return

        # Skip if same domain
        if script_domain == self.base_domain:
            return

        # Check against trusted domains (whitelist)
        if any(script_domain.endswith(trusted) for trusted in TRUSTED_DOMAINS):
            return

        # Check against malicious domain blocklist
        if any(mal_domain in script_domain for mal_domain in MALICIOUS_DOMAINS):
            self.findings.append({
                "category": "external_script",
                "severity": "critical",
                "points": 30,
                "description": f"Script loaded from known malicious domain: {script_domain}",
                "evidence": f"src='{src}'",
                "recommendation": "This script is from a known malicious domain. It may contain malware or keyloggers.",
            })
            return

        # Check for suspicious TLDs (weak indicator)
        for tld in SUSPICIOUS_TLDS:
            if script_domain.endswith(tld):
                self.findings.append({
                    "category": "external_script",
                    "severity": "medium",
                    "points": 15,
                    "description": f"Script loaded from suspicious TLD: {script_domain}",
                    "evidence": f"src='{src}'",
                    "recommendation": "Scripts from free/suspicious TLDs are often used in malicious campaigns, but this is a weak indicator",
                })
                return

        # Check for mixed content (HTTP script on potentially HTTPS page)
        if src.startswith("http://"):
            self.findings.append({
                "category": "external_script",
                "severity": "medium",
                "points": 15,
                "description": f"Script loaded over insecure HTTP: {script_domain}",
                "evidence": f"src='{src}'",
                "recommendation": "Scripts over HTTP can be intercepted and modified by attackers (man-in-the-middle attack)",
            })
            return

        # General external script warning
        self.findings.append({
            "category": "external_script",
            "severity": "low",
            "points": 10,
            "description": f"Script loaded from external domain: {script_domain}",
            "evidence": f"src='{src}'",
            "recommendation": "External scripts may track user behavior or inject unwanted content",
        })
