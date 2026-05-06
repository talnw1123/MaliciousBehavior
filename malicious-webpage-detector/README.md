# Malicious Webpage Behavior Detection System

A web-based system that analyzes webpages for suspicious and malicious behavior patterns including hidden iframes, obfuscated JavaScript, external scripts from unknown domains, and dangerous file links.

## Features

- **Hidden Iframe Detection**: Identifies iframes hidden with CSS or zero dimensions that may redirect to phishing pages
- **JavaScript Obfuscation Detection**: Finds `eval()`, `atob()`, `String.fromCharCode()`, hex/unicode encoded strings
- **External Script Analysis**: Detects scripts loaded from unknown or known malicious domains
- **Dangerous Link Detection**: Finds links to sensitive files (`.git`, `.env`, config files, backups, admin panels)
- **Cryptojacking Detection**: Detects cryptocurrency mining scripts (CoinHive, CryptoLoot, etc.)
- **Risk Scoring**: Calculates an overall risk level (LOW/MEDIUM/HIGH/CRITICAL) with detailed explanations
- **Scan History**: Stores scan results in SQLite database for future reference
- **Export Results**: Export scan results as JSON or print as PDF

## Tech Stack

- **Backend**: Python 3.8+ with Flask
- **Frontend**: HTML, CSS, JavaScript (vanilla)
- **Web Scraping**: requests + BeautifulSoup4

## Installation

1. **Clone or download** this project
2. **Install Python 3.8+** if not already installed
3. **Create a virtual environment** (recommended):
   ```bash
   cd malicious-webpage-detector
   python -m venv venv
   ```
4. **Activate the virtual environment**:
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source venv/bin/activate
     ```
5. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Start the server**:
   ```bash
   python app.py
   ```
2. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```
3. **Enter a URL** to analyze and click "Analyze"
4. **Review the results** including risk level, findings, and recommendations

## Project Structure

```
malicious-webpage-detector/
├── app.py                    # Flask application entry point
├── requirements.txt          # Python dependencies
├── config.py                 # Configuration settings
├── scraper.py                # Web scraping and HTML fetching
├── detectors/                # Detection modules
│   ├── __init__.py
│   ├── iframe_detector.py    # Hidden/suspicious iframe detection
│   ├── js_detector.py        # JavaScript obfuscation detection
│   ├── script_detector.py    # External script detection
│   ├── link_detector.py      # Dangerous file/link detection
│   └── risk_scorer.py        # Risk scoring engine
├── static/                   # Static assets
│   ├── css/
│   │   └── style.css         # Frontend styling
│   └── js/
│       └── main.js           # Frontend JavaScript
└── templates/
    └── index.html            # Main frontend page
```

## API Endpoint

### POST `/analyze`

Analyze a URL for malicious behavior.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "risk_level": "HIGH",
  "risk_score": 75,
  "findings": [
    {
      "category": "iframe",
      "severity": "high",
      "points": 25,
      "description": "Hidden iframe detected with 'display:none'",
      "evidence": "<iframe src='https://evil.com' style='display:none'>",
      "recommendation": "Hidden iframes may redirect to phishing or malware pages"
    }
  ],
  "recommendations": [
    "Hidden iframes detected - this page may redirect you to phishing or malware sites"
  ]
}
```

## Risk Levels

| Level    | Score Range | Description                                      |
|----------|-------------|--------------------------------------------------|
| LOW      | 0-25        | No significant threats detected                  |
| MEDIUM   | 26-50       | Some suspicious behavior, exercise caution       |
| HIGH     | 51-75       | Multiple threats detected, avoid entering data   |
| CRITICAL | 76-100      | Severe threats, avoid this site completely       |

## New Features

### Scan History
- All scan results are automatically saved to SQLite database (`scan_history.db`)
- View scan history on the main page
- Click any history item to view details
- Delete individual scans or clear all history

### Export Results
- **Export JSON**: Download scan results as a JSON file
- **Export PDF**: Print results as PDF using browser's print function

### Cryptojacking Detection
- Detects known mining scripts: CoinHive, CryptoLoot, WebMiner, JSECoin, MinerGate, etc.
- Detects mining-related patterns: `startMining()`, `hashrate`, `monero`, `XMR`
- Critical severity - immediately warns user to leave the site

## Detection Categories

### Iframe Detection
- Hidden iframes (display:none, visibility:hidden, opacity:0, width/height=0)
- Iframes from known malicious domains
- Iframes from suspicious TLDs (.tk, .ml, .ga, etc.)
- Iframes with misused sandbox attributes

### JavaScript Detection
- `eval()` usage
- `atob()`/`btoa()` Base64 encoding
- `String.fromCharCode()` obfuscation
- Hex-encoded strings (`\x41\x42...`)
- Unicode escape sequences (`\u0041\u0042...`)
- `document.write()` with encoded content
- Excessive string concatenation

### External Script Detection
- Scripts from known malicious domains
- Scripts from suspicious TLDs
- Scripts loaded over insecure HTTP
- Scripts from unknown external domains

### Dangerous Link Detection
- `.git/` directory exposure
- `.env` file exposure
- `.htaccess` file exposure
- Configuration files (config.php, config.json, etc.)
- Backup files (.bak, .backup, .old, .sql)
- Admin panels (/admin, /wp-admin, /phpmyadmin)
- API key/secret key exposure

## Configuration

Edit [`config.py`](config.py) to customize:

- `MALICIOUS_DOMAINS`: List of known malicious domains to blocklist
- `SUSPICIOUS_TLDS`: List of suspicious top-level domains
- `DANGEROUS_FILE_PATTERNS`: Patterns to detect dangerous file links
- `RISK_THRESHOLDS`: Score ranges for risk levels
- `REQUEST_TIMEOUT`: Timeout for fetching webpages
- `FLASK_PORT`: Port to run the server on

## Disclaimer

This tool is for educational and research purposes only. It is not a substitute for professional security analysis. Always practice safe browsing habits and use multiple layers of security protection.

## License

MIT License
