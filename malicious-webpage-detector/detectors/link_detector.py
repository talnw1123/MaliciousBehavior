"""
Dangerous Link Detector Module
Detects links to sensitive files, admin panels, and backup files
"""

import re
from urllib.parse import urlparse
from config import DANGEROUS_FILE_PATTERNS


class LinkDetector:
    """Detects links to dangerous or sensitive files."""

    def __init__(self, soup, raw_html):
        """
        Initialize the detector.

        Args:
            soup: BeautifulSoup object of the parsed HTML
            raw_html: Raw HTML string
        """
        self.soup = soup
        self.raw_html = raw_html
        self.findings = []

    def detect(self):
        """Run all dangerous link detection checks."""
        self._check_links_in_html()
        self._check_patterns_in_raw_html()
        return self.findings

    def _check_links_in_html(self):
        """Check all href attributes for dangerous patterns."""
        links = self.soup.find_all(["a", "link"], href=True)

        for link in links:
            href = link.get("href", "")
            self._check_href(href)

        # Also check form actions
        forms = self.soup.find_all("form", action=True)
        for form in forms:
            action = form.get("action", "")
            self._check_href(action)

    def _check_href(self, href):
        """Check a single href value for dangerous patterns."""
        if not href:
            return

        href_lower = href.lower()

        for pattern in DANGEROUS_FILE_PATTERNS:
            pattern_lower = pattern.lower()
            # Use word boundary or path separator matching for better accuracy
            if self._pattern_in_url(pattern_lower, href_lower):
                # Updated scoring per new specification
                if pattern in [".git", ".env"]:
                    severity = "high"
                    points = 25
                elif pattern in [".htaccess"]:
                    severity = "medium"
                    points = 10
                elif pattern in ["config.php", "config.json", "config.yml", "web.config", "database.yml", "settings.py"]:
                    severity = "high"
                    points = 20
                elif pattern in [".bak", ".backup", ".old", ".sql", ".dump"]:
                    severity = "medium"
                    points = 10
                elif pattern in ["/admin", "/wp-admin", "/phpmyadmin", "/wp-login", "/administrator", "/cpanel", "/manager"]:
                    severity = "medium"
                    points = 15
                elif pattern in ["api_key", "api_token", "access_token", "secret_key"]:
                    severity = "high"
                    points = 20
                else:
                    severity = "medium"
                    points = 10

                self.findings.append({
                    "category": "dangerous_link",
                    "severity": severity,
                    "points": points,
                    "description": f"Link to sensitive file/path detected: {pattern}",
                    "evidence": f"href='{href}'",
                    "recommendation": f"Links to '{pattern}' may expose sensitive configuration or credentials",
                })
                return  # Only report once per link

    def _pattern_in_url(self, pattern, href):
        """Check if a pattern exists in URL with proper boundary matching."""
        # For .git, .env etc., look for the pattern followed by / or end of string
        # or preceded by / or at start
        import re
        # Escape special regex characters in pattern
        escaped = re.escape(pattern)
        # Match pattern at word boundary or path separator
        regex = r'(?:^|/|\.|_)' + escaped + r'(?:/|$|\?|#|\.)'
        return bool(re.search(regex, href))

    def _check_patterns_in_raw_html(self):
        """Check raw HTML for dangerous file patterns that might not be in links."""
        # Look for patterns like .git/, .env, config.php in text or comments
        # Updated scoring per new specification
        patterns_to_check = [
            (r'\.git/', ".git directory exposure", 25, "high"),
            (r'\.env\b', ".env file exposure", 25, "high"),
            (r'\.htaccess', ".htaccess file exposure", 10, "medium"),
            (r'config\.(php|json|yml|yaml|xml)', "Configuration file exposure", 20, "high"),
            (r'\.(bak|backup|old|sql|dump)\b', "Backup file exposure", 10, "medium"),
            (r'/wp-admin', "WordPress admin panel", 15, "medium"),
            (r'/phpmyadmin', "phpMyAdmin panel", 15, "medium"),
            (r'api[_-]?key\s*[:=]', "API key exposure", 20, "high"),
            (r'secret[_-]?key\s*[:=]', "Secret key exposure", 20, "high"),
        ]

        for pattern, description, points, severity in patterns_to_check:
            matches = re.findall(pattern, self.raw_html, re.IGNORECASE)
            if matches:
                self.findings.append({
                    "category": "dangerous_link",
                    "severity": severity,
                    "points": points,
                    "description": description,
                    "evidence": f"Found {len(matches)} occurrence(s)",
                    "recommendation": f"Exposed {description.lower()} may leak sensitive information",
                })
