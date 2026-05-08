"""
Google Safe Browsing Detector Module
Detects malicious URLs using Google Safe Browsing API v4
"""

import requests
from config import GOOGLE_SAFE_BROWSING_API_KEY


class SafeBrowsingDetector:
    """Detects malicious URLs by querying Google Safe Browsing."""

    def __init__(self, main_url, soup):
        """
        Initialize the detector.

        Args:
            main_url: The main URL being analyzed
            soup: BeautifulSoup object of the parsed HTML
        """
        self.main_url = main_url
        self.soup = soup
        self.findings = []

    def detect(self):
        """Run the Safe Browsing check."""
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return self.findings

        # Collect URLs to check
        urls_to_check = set([self.main_url])

        # Extract iframe sources
        if self.soup:
            for iframe in self.soup.find_all("iframe"):
                src = iframe.get("src", "")
                if src and src.startswith(("http", "//")):
                    if src.startswith("//"):
                        src = "https:" + src
                    urls_to_check.add(src)

            # Extract script sources
            for script in self.soup.find_all("script", src=True):
                src = script.get("src", "")
                if src and src.startswith(("http", "//")):
                    if src.startswith("//"):
                        src = "https:" + src
                    urls_to_check.add(src)

        if not urls_to_check:
            return self.findings

        # Prepare payload for API
        threat_entries = [{"url": u} for u in urls_to_check]

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "malicious-webpage-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries
            }
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=10)
            if response.status_code == 200:
                result = response.json()
                matches = result.get("matches", [])

                if not matches:
                    return self.findings

                # Separate matches for main URL and external resources
                main_malicious = [m for m in matches if m["threat"]["url"] == self.main_url]
                other_malicious = [m for m in matches if m["threat"]["url"] != self.main_url]

                if main_malicious:
                    threat_type = main_malicious[0].get("threatType", "MALICIOUS")
                    self.findings.append({
                        "category": "safe_browsing",
                        "severity": "critical",
                        "points": 100,
                        "description": f"Google Safe Browsing flags this site as {threat_type}",
                        "evidence": f"API Match: {self.main_url}",
                        "recommendation": f"CRITICAL: Leave this site immediately. Google has flagged it as {threat_type}."
                    })

                for match in other_malicious:
                    url = match["threat"]["url"]
                    threat_type = match.get("threatType", "MALICIOUS")
                    self.findings.append({
                        "category": "safe_browsing",
                        "severity": "critical",
                        "points": 50,
                        "description": f"Page loads content from {threat_type} URL",
                        "evidence": f"API Match: {url}",
                        "recommendation": "This page loads external resources that Google has flagged as dangerous."
                    })

        except Exception as e:
            print(f"Error querying Google Safe Browsing API: {e}")

        return self.findings
