# Presentation Slides - Malicious Webpage Behavior Detection System

---

## Slide 1: Title Slide

**ระบบตรวจจับพฤติกรรมที่น่าสงสัยบนหน้าเว็บไซต์**
Malicious Webpage Behavior Detection System

- ชื่อผู้จัดทำ: [ชื่อคุณ]
- วันที่: [วันที่ present]

---

## Slide 2: Problem Statement - ทำไมต้องทำ?

**ปัญหา:**
- เว็บไซต์อันตรายมีมากขึ้นทุกวัน
- ผู้ใช้ทั่วไปไม่สามารถตรวจสอบได้ว่าเว็บปลอดภัยไหม
- Malicious iframes, obfuscated JavaScript, cryptojacking แฝงตัวในเว็บปกติ

**ผลกระทบ:**
- Phishing attacks - ขโมยข้อมูลส่วนตัว
- Malware distribution - ติดไวรัส/ ransomware
- Cryptojacking - ใช้ CPU เราขุดเงินโดยไม่บอก

---

## Slide 3: Solution - ระบบของเราทำอะไร?

**รับ URL → วิเคราะห์ → บอกผล**

ระบบจะ:
1. ดาวน์โหลด HTML ของหน้าเว็บ
2. วิเคราะห์ 5 ด้าน
3. คำนวณคะแนนความเสี่ยง
4. แสดงผลพร้อมคำแนะนำ

**Output:**
- Risk Level: LOW / MEDIUM / HIGH / CRITICAL
- Risk Score: 0-100
- Findings: รายการสิ่งที่พบ
- Recommendations: คำแนะนำ

---

## Slide 4: 5 Detection Modules

| # | Module | ตรวจจับอะไร |
|---|--------|-------------|
| 1 | Iframe Detector | Hidden iframes, malicious domains |
| 2 | JavaScript Detector | eval(), atob(), hex encoding |
| 3 | External Script Detector | Scripts จาก unknown domains |
| 4 | Dangerous Link Detector | .git, .env, config files |
| 5 | Cryptojacking Detector | Mining scripts (CoinHive, etc.) |

---

## Slide 5: Iframe Detection

**ตรวจจับ:**
- Hidden iframes: `display:none`, `width=0`, `opacity:0`
- Iframes จาก malicious domains (blocklist)
- Iframes จาก suspicious TLDs (.tk, .ml, .xyz)

**ตัวอย่าง:**
```html
<iframe src="https://evil.com/phishing" style="display:none"></iframe>
```

**ความเสี่ยง:** อาจ redirect ไป phishing page โดยผู้ใช้ไม่รู้ตัว

---

## Slide 6: JavaScript Obfuscation Detection

**ตรวจจับ patterns:**
- `eval()` - execute arbitrary code
- `atob()`/`btoa()` - Base64 encoding
- `String.fromCharCode()` - obfuscate strings
- Hex encoding: `\x41\x42\x43...`
- Unicode escape: `\u0041\u0042...`

**ตัวอย่าง:**
```javascript
eval(atob("ZG9jdW1lbnQud3JpdGUoJzxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4nKQ=="))
```

---

## Slide 7: Cryptojacking Detection

**ตรวจจับ mining scripts:**
- CoinHive, CryptoLoot, WebMiner, JSECoin, MinerGate
- Patterns: `startMining()`, `hashrate`, `monero`, `XMR`

**ตัวอย่าง:**
```javascript
var miner = new CoinHive.Anonymous('KEY');
miner.start();  // ใช้ CPU เราขุดเงิน!
```

**ผลกระทบ:** CPU ทำงานหนัก, เครื่องร้อน, เปลืองไฟ

---

## Slide 8: Risk Scoring System

| Level | Score | Color | Meaning |
|-------|-------|-------|---------|
| LOW | 0-25 | 🟢 | ปลอดภัย |
| MEDIUM | 26-50 | 🟡 | ควรระวัง |
| HIGH | 51-75 |  | อย่ากรอกข้อมูล |
| CRITICAL | 76-100 | 🔴 | หลีกเลี่ยงทันที |

**Category Caps:**
- external_script: max 30 points
- dangerous_link: max 30 points
- iframe: max 50 points
- javascript: max 50 points
- cryptojacking: max 50 points

---

## Slide 9: Tech Stack

**Backend:**
- Python 3.8+
- Flask (Web Framework)
- requests + BeautifulSoup4 (Web Scraping)
- SQLite (Scan History)

**Frontend:**
- HTML5 + CSS3 (Dark Theme)
- Vanilla JavaScript
- Responsive Design

**Architecture:**
```
User → Flask API → Scraper → Detectors → Risk Scorer → JSON Response
```

---

## Slide 10: Project Structure

```
malicious-webpage-detector/
├── app.py                    # Flask application
├── config.py                 # Configuration
├── scraper.py                # Web scraping
├── database.py               # SQLite history
├── detectors/
│   ├── iframe_detector.py
│   ├── js_detector.py
│   ├── script_detector.py
│   ├── link_detector.py
│   └── risk_scorer.py
├── static/                   # CSS, JS
└── templates/                # HTML
```

---

## Slide 11: Demo - ผลการทดสอบ

| เว็บไซต์ | Risk | Score | เหตุผล |
|----------|------|-------|--------|
| example.com | 🟢 LOW | 0 | ปลอดภัย |
| theuselessweb.com | 🟢 LOW | 20 | External scripts น้อย |
| github.com |  MEDIUM | 30 | External scripts เยอะ |
| w3schools.com | 🟠 HIGH | 70 | Scripts + ads เยอะ |

---

## Slide 12: Features

**Core Features:**
- 5 Detection Modules
- Risk Scoring (0-100)
- Detailed Findings + Evidence

**Additional Features:**
- Scan History (SQLite)
- Export Results (JSON/PDF)
- Cryptojacking Detection
- Dark Theme UI

---

## Slide 13: How to Use

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run server
python app.py

# 3. Open browser
http://localhost:5000

# 4. Enter URL → Analyze → View Results
```

---

## Slide 14: Limitations & Future Work

**ข้อจำกัด:**
- Signature-based detection (ไม่ตรวจจับ zero-day)
- ไม่มี threat intelligence feed
- False positives จาก safe domains (Google, etc.)

**สิ่งที่อยากทำเพิ่ม:**
- Google Safe Browsing API integration
- Machine Learning-based detection
- Real-time monitoring mode
- Browser extension

---

## Slide 15: Q&A

**ขอบคุณครับ!**

คำถาม?

---

## Slide 16: References

- OWASP Web Security Testing Guide
- Google Safe Browsing API
- CoinHive Documentation
- Flask Documentation
- BeautifulSoup4 Documentation
