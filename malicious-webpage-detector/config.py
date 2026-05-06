"""
Configuration settings for the Malicious Webpage Behavior Detection System
"""

# Request settings
REQUEST_TIMEOUT = 10  # seconds
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

# Known malicious domains (blocklist)
MALICIOUS_DOMAINS = [
    "evil.com",
    "malware.com",
    "phishing.com",
    "hack.com",
    "exploit.com",
]

# Suspicious TLDs often used in malicious sites
SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".club",
    ".work",
]

# Dangerous file patterns
DANGEROUS_FILE_PATTERNS = [
    ".git",
    ".env",
    ".htaccess",
    "config.php",
    "config.json",
    "config.yml",
    "web.config",
    "database.yml",
    "settings.py",
    ".bak",
    ".backup",
    ".old",
    ".sql",
    ".dump",
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/wp-login",
    "/administrator",
    "/cpanel",
    "/manager",
    "api_key",
    "api_token",
    "access_token",
    "secret_key",
]

# Risk score thresholds
RISK_THRESHOLDS = {
    "LOW": (0, 25),
    "MEDIUM": (26, 50),
    "HIGH": (51, 75),
    "CRITICAL": (76, 100),
}

# Flask settings
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = True
