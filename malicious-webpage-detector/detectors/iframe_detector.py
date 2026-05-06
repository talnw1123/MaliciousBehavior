"""
Iframe Detector Module
Detects hidden and suspicious iframes in webpage HTML
"""

from urllib.parse import urlparse
from config import MALICIOUS_DOMAINS, SUSPICIOUS_TLDS


class IframeDetector:
    """Detects hidden and suspicious iframes."""

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
        """Run all iframe detection checks."""
        iframes = self.soup.find_all("iframe")

        for iframe in iframes:
            self._check_hidden(iframe)
            self._check_suspicious_domain(iframe)
            self._check_sandbox_attribute(iframe)

        return self.findings

    def _check_hidden(self, iframe):
        """Check if iframe is hidden using CSS or attributes."""
        style = iframe.get("style", "").lower()
        width = iframe.get("width", "")
        height = iframe.get("height", "")

        is_hidden = False
        reason = ""

        # Check for display:none
        if "display:none" in style or "display: none" in style:
            is_hidden = True
            reason = "Hidden iframe detected with 'display:none'"

        # Check for visibility:hidden
        elif "visibility:hidden" in style or "visibility: hidden" in style:
            is_hidden = True
            reason = "Hidden iframe detected with 'visibility:hidden'"

        # Check for opacity:0
        elif "opacity:0" in style or "opacity: 0" in style:
            is_hidden = True
            reason = "Hidden iframe detected with 'opacity:0'"

        # Check for width/height = 0
        elif width == "0" or height == "0":
            is_hidden = True
            reason = "Hidden iframe detected with width=0 or height=0"

        # Check for position:absolute with negative offsets
        elif "position:absolute" in style and ("left:-" in style or "top:-" in style):
            is_hidden = True
            reason = "Hidden iframe detected with absolute positioning off-screen"

        if is_hidden:
            src = iframe.get("src", "unknown")
            self.findings.append({
                "category": "iframe",
                "severity": "high",
                "points": 25,
                "description": reason,
                "evidence": str(iframe)[:200],
                "recommendation": "Hidden iframes may redirect to phishing or malware pages without user knowledge",
            })

    def _check_suspicious_domain(self, iframe):
        """Check if iframe points to a suspicious domain."""
        src = iframe.get("src", "")
        if not src:
            return

        # Parse the iframe source URL
        if not src.startswith(("http://", "https://", "//")):
            return  # Relative URL, likely same domain

        if src.startswith("//"):
            src = "https:" + src

        try:
            parsed = urlparse(src)
            iframe_domain = parsed.netloc.lower()
        except Exception:
            return

        # Check against malicious domain blocklist
        if any(mal_domain in iframe_domain for mal_domain in MALICIOUS_DOMAINS):
            self.findings.append({
                "category": "iframe",
                "severity": "critical",
                "points": 30,
                "description": f"Iframe loads content from known malicious domain: {iframe_domain}",
                "evidence": f"src='{src}'",
                "recommendation": "This iframe loads content from a known malicious domain. Avoid this site immediately.",
            })
            return

        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if iframe_domain.endswith(tld):
                self.findings.append({
                    "category": "iframe",
                    "severity": "medium",
                    "points": 20,
                    "description": f"Iframe loads content from suspicious TLD: {iframe_domain}",
                    "evidence": f"src='{src}'",
                    "recommendation": "Iframes from free/suspicious TLDs are often used in phishing attacks",
                })
                return

        # Check if domain is different from base domain
        if self.base_domain and iframe_domain != self.base_domain:
            self.findings.append({
                "category": "iframe",
                "severity": "medium",
                "points": 15,
                "description": f"Iframe loads content from external domain: {iframe_domain}",
                "evidence": f"src='{src}'",
                "recommendation": "External iframes may load unwanted or malicious content",
            })

    def _check_sandbox_attribute(self, iframe):
        """Check for potentially misused sandbox attribute."""
        sandbox = iframe.get("sandbox", "")
        if sandbox is not None:  # Attribute exists
            # Empty sandbox or with dangerous permissions
            dangerous_permissions = ["allow-scripts", "allow-same-origin"]
            has_dangerous = any(p in sandbox for p in dangerous_permissions)

            if sandbox == "" or has_dangerous:
                src = iframe.get("src", "unknown")
                self.findings.append({
                    "category": "iframe",
                    "severity": "medium",
                    "points": 10,
                    "description": "Iframe with sandbox attribute that allows scripts or same-origin access",
                    "evidence": f"sandbox='{sandbox}' src='{src}'",
                    "recommendation": "Sandbox with script permissions can execute malicious code",
                })
