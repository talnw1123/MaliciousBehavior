"""
JavaScript Obfuscation Detector Module
Detects obfuscated and suspicious JavaScript patterns in webpage HTML
"""

import re


class JSDetector:
    """Detects obfuscated and suspicious JavaScript code."""

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
        self.js_content = []
        self._extract_javascript()

    def _extract_javascript(self):
        """Extract all JavaScript content from the page."""
        # Extract inline scripts
        scripts = self.soup.find_all("script")
        for script in scripts:
            if script.string:
                self.js_content.append(script.string)

        # Also check for JS in event handlers
        tags_with_handlers = self.soup.find_all(
            ["body", "div", "span", "a", "img", "input", "button", "form"]
        )
        for tag in tags_with_handlers:
            for attr, value in tag.attrs.items() if tag.attrs else []:
                if attr.startswith("on") and value:
                    self.js_content.append(str(value))

    def detect(self):
        """Run all JavaScript obfuscation detection checks."""
        for js in self.js_content:
            self._check_eval(js)
            self._check_atob_btoa(js)
            self._check_string_from_char_code(js)
            self._check_hex_encoding(js)
            self._check_unicode_escape(js)
            self._check_document_write(js)
            self._check_excessive_concatenation(js)
            self._check_cryptojacking(js)

        return self.findings

    def _check_eval(self, js):
        """Check for eval() usage which can execute arbitrary code."""
        # Match eval( with possible whitespace
        pattern = r'\beval\s*\('
        matches = re.findall(pattern, js)
        if matches:
            # Find the context around eval
            for match in matches:
                # Get surrounding context
                idx = js.find(match)
                context = js[max(0, idx - 20):idx + 50].strip()

            self.findings.append({
                "category": "javascript",
                "severity": "high",
                "points": 20,
                "description": "eval() usage detected - can execute arbitrary code",
                "evidence": self._truncate(context),
                "recommendation": "eval() is commonly used to execute obfuscated malware payloads",
            })

    def _check_atob_btoa(self, js):
        """Check for Base64 encoding/decoding functions."""
        atob_pattern = r'\batob\s*\('
        btoa_pattern = r'\bbtoa\s*\('

        atob_matches = re.findall(atob_pattern, js)
        btoa_matches = re.findall(btoa_pattern, js)

        if atob_matches or btoa_matches:
            # Find context
            all_matches = atob_matches + btoa_matches
            if atob_matches:
                idx = js.find("atob(")
            else:
                idx = js.find("btoa(")
            context = js[max(0, idx - 20):idx + 50].strip()

            self.findings.append({
                "category": "javascript",
                "severity": "medium",
                "points": 10,
                "description": "Base64 encoding/decoding detected (atob/btoa) - may hide malicious payloads",
                "evidence": self._truncate(context),
                "recommendation": "Base64 encoding is often used to obfuscate malicious scripts, but is also found in legitimate websites",
            })

    def _check_string_from_char_code(self, js):
        """Check for String.fromCharCode() usage."""
        pattern = r'\bString\s*\.\s*fromCharCode\s*\('
        matches = re.findall(pattern, js)
        if matches:
            idx = js.find("String")
            context = js[max(0, idx - 10):idx + 80].strip()

            self.findings.append({
                "category": "javascript",
                "severity": "high",
                "points": 15,
                "description": "String.fromCharCode() detected - commonly used to obfuscate strings",
                "evidence": self._truncate(context),
                "recommendation": "This function is often used to hide malicious strings from detection",
            })

    def _check_hex_encoding(self, js):
        """Check for hex-encoded strings (\\x41\\x42...)."""
        # Look for sequences of hex escapes
        pattern = r'(?:\\x[0-9a-fA-F]{2}){4,}'
        matches = re.findall(pattern, js)
        if matches:
            self.findings.append({
                "category": "javascript",
                "severity": "medium",
                "points": 10,
                "description": "Hex-encoded strings detected - possible obfuscation technique",
                "evidence": self._truncate(matches[0]),
                "recommendation": "Hex encoding is used to hide malicious code from analysis",
            })

    def _check_unicode_escape(self, js):
        """Check for Unicode escape sequences (\\u0041\\u0042...)."""
        pattern = r'(?:\\u[0-9a-fA-F]{4}){4,}'
        matches = re.findall(pattern, js)
        if matches:
            self.findings.append({
                "category": "javascript",
                "severity": "medium",
                "points": 10,
                "description": "Unicode escape sequences detected - possible obfuscation technique",
                "evidence": self._truncate(matches[0]),
                "recommendation": "Unicode escapes can be used to obfuscate malicious strings",
            })

    def _check_document_write(self, js):
        """Check for document.write() with potentially encoded content."""
        pattern = r'\bdocument\s*\.\s*write\s*\('
        matches = re.findall(pattern, js)
        if matches:
            # Check if document.write is used with encoded content
            has_encoded = any(
                p in js for p in [
                    "atob(", "fromCharCode", "\\x", "\\u", "eval(",
                    "unescape(", "decodeURIComponent("
                ]
            )
            if has_encoded:
                idx = js.find("document")
                context = js[max(0, idx - 10):idx + 80].strip()

                self.findings.append({
                    "category": "javascript",
                    "severity": "high",
                    "points": 20,
                    "description": "document.write() with encoded content - may inject malicious HTML",
                    "evidence": self._truncate(context),
                    "recommendation": "document.write() with encoded data can inject hidden malicious elements",
                })

    def _check_excessive_concatenation(self, js):
        """Check for excessive string concatenation patterns."""
        # Pattern: multiple string concatenations like "a"+"b"+"c"+...
        pattern = r'(?:"[^"]*"\s*\+\s*){5,}'
        matches = re.findall(pattern, js)
        if matches:
            self.findings.append({
                "category": "javascript",
                "severity": "low",
                "points": 5,
                "description": "Excessive string concatenation detected - possible obfuscation",
                "evidence": self._truncate(matches[0]),
                "recommendation": "String concatenation is used to build malicious URLs or code dynamically, but is also common in legitimate code",
            })

    def _check_cryptojacking(self, js):
        """Check for cryptocurrency mining scripts."""
        # Known mining libraries (direct evidence) - 30 points
        mining_libraries = [
            r'\bCoinHive\b',
            r'\bcoinhive\b',
            r'\bCoinImp\b',
            r'\bCryptoLoot\b',
            r'\bWebMiner\b',
            r'\bJSECoin\b',
            r'\bMinerGate\b',
            r'\bCoinMiner\b',
            r'\bCryptoMiner\b',
            r'\bCoinHive\.Anonymous\b',
        ]

        # Mining functions (specific to mining) - 20 points
        mining_functions = [
            r'\bhashrate\b',
            r'\bstartMining\b',
            r'\bstopMining\b',
            r'\bgetMiningStats\b',
            r'\bminer\.start\b',
        ]

        # Cryptocurrency keywords (weaker indicator) - 20 points
        crypto_keywords = [
            r'\bmonero\b',
            r'\bXMR\b',
        ]

        # Mining domain URLs (direct evidence) - 30 points
        mining_domains = [
            r'\bcoinhive\.com\b',
            r'\bcryptoloot\.pro\b',
            r'\bwebmine\.pro\b',
            r'\bminergate\.com\b',
            r'\bjsecoin\.com\b',
            r'\bcoinimp\.com\b',
        ]

        # Check mining libraries first (highest priority)
        for pattern in mining_libraries:
            if re.search(pattern, js, re.IGNORECASE):
                self.findings.append({
                    "category": "cryptojacking",
                    "severity": "critical",
                    "points": 30,
                    "description": "Known cryptocurrency mining library detected - your device may be used for mining",
                    "evidence": self._truncate(f"Pattern: {pattern}"),
                    "recommendation": "This site is using your device's CPU to mine cryptocurrency. Leave immediately!",
                })
                return

        # Check mining domain URLs
        for pattern in mining_domains:
            if re.search(pattern, js, re.IGNORECASE):
                self.findings.append({
                    "category": "cryptojacking",
                    "severity": "critical",
                    "points": 30,
                    "description": "Connection to known mining pool/domain detected - your device may be used for mining",
                    "evidence": self._truncate(f"Pattern: {pattern}"),
                    "recommendation": "This site is using your device's CPU to mine cryptocurrency. Leave immediately!",
                })
                return

        # Check mining functions
        for pattern in mining_functions:
            if re.search(pattern, js, re.IGNORECASE):
                self.findings.append({
                    "category": "cryptojacking",
                    "severity": "high",
                    "points": 20,
                    "description": "Cryptocurrency mining function detected - your device may be used for mining",
                    "evidence": self._truncate(f"Pattern: {pattern}"),
                    "recommendation": "This site may be using your device's CPU to mine cryptocurrency.",
                })
                return

        # Check crypto keywords
        for pattern in crypto_keywords:
            if re.search(pattern, js, re.IGNORECASE):
                self.findings.append({
                    "category": "cryptojacking",
                    "severity": "high",
                    "points": 20,
                    "description": "Cryptocurrency keyword detected - possible mining activity",
                    "evidence": self._truncate(f"Pattern: {pattern}"),
                    "recommendation": "This site may be related to cryptocurrency mining.",
                })
                return

    def _truncate(self, text, max_length=150):
        """Truncate text for display."""
        if len(text) > max_length:
            return text[:max_length] + "..."
        return text
