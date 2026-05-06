# Detailed Documentation

## 5 Detection Modules - รายละเอียดเชิงลึก

---

### Module 1: Iframe Detector

**ไฟล์:** `detectors/iframe_detector.py`

#### ตรวจจับอะไร?

1. **Hidden Iframes** - iframe ที่ซ่อนจากผู้ใช้
   - `display:none` - ซ่อนด้วย CSS
   - `visibility:hidden` - ซ่อนแต่ยังกินพื้นที่
   - `opacity:0` - โปร่งใส 100%
   - `width=0` หรือ `height=0` - ขนาดเป็น 0
   - `position:absolute` + `left:-9999px` - ย้ายออกนอกจอ

2. **Malicious Domain Iframes** - iframe จาก domain อันตราย
   - ตรวจสอบกับ blocklist ใน config
   - ใช้ substring matching

3. **Suspicious TLD Iframes** - iframe จาก TLD น่าสงสัย
   - `.tk`, `.ml`, `.ga`, `.cf`, `.gq` (ฟรี TLD)
   - `.xyz`, `.top`, `.club`, `.work`

4. **Sandbox Misuse** - iframe ที่ใช้ sandbox ผิดวิธี
   - `sandbox` attribute แต่มี `allow-scripts`
   - อนุญาตให้รัน JavaScript ได้

#### ตัวอย่างที่ตรวจจับได้

```html
<!-- Hidden iframe -->
<iframe src="https://evil.com/phishing" style="display:none"></iframe>

<!-- Zero size iframe -->
<iframe src="https://bad.tk/malware" width="0" height="0"></iframe>

<!-- Off-screen iframe -->
<iframe src="https://hack.com/exploit" style="position:absolute;left:-9999px"></iframe>
```

#### ความเสี่ยง

- **Phishing** - redirect ไปหน้า login ปลอม
- **Malware distribution** - โหลด malware โดยไม่รู้ตัว
- **Clickjacking** - ซ่อนปุ่มให้ผู้ใช้คลิกโดยไม่ตั้งใจ

---

### Module 2: JavaScript Obfuscation Detector

**ไฟล์:** `detectors/js_detector.py`

#### ตรวจจับอะไร?

1. **eval()** - execute arbitrary code
   ```javascript
   eval("alert('hello')")  // รัน code อะไรก็ได้
   ```

2. **atob()/btoa()** - Base64 encoding/decoding
   ```javascript
   eval(atob("ZG9jdW1lbnQud3JpdGUoJzxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4nKQ=="))
   ```

3. **String.fromCharCode()** - สร้าง string จาก char codes
   ```javascript
   String.fromCharCode(100, 111, 99, 117, 109, 101, 110, 116)
   // = "document"
   ```

4. **Hex Encoding** - ตัวอักษร hex escape
   ```javascript
   "\x64\x6f\x63\x75\x6d\x65\x6e\x74"  // = "document"
   ```

5. **Unicode Escape** - ตัวอักษร unicode escape
   ```javascript
   "\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074"  // = "document"
   ```

6. **document.write() + encoded content** - inject HTML
   ```javascript
   document.write(atob("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="))
   ```

7. **Excessive String Concatenation** - ต่อ string ยาวๆ
   ```javascript
   var x = "d"+"o"+"c"+"u"+"m"+"e"+"n"+"t"
   ```

#### เทคนิค Obfuscation ที่พบบ่อย

| เทคนิค | ตัวอย่าง | จุดประสงค์ |
|--------|---------|-----------|
| Base64 + eval | `eval(atob("..."))` | ซ่อน malicious code |
| String.fromCharCode | `String.fromCharCode(97,108,101,114,116)` | หลบ signature detection |
| Hex encoding | `"\x61\x6c\x65\x72\x74"` | หลบ keyword detection |
| Unicode escape | `"\u0061\u006c\u0065\u0072\u0074"` | หลบ keyword detection |
| String concat | `"a"+"l"+"e"+"r"+"t"` | หลบ static analysis |

#### ความเสี่ยง

- **Malware execution** - รัน malware โดยผู้ใช้ไม่รู้
- **Keylogging** - ขโมยข้อมูลที่พิมพ์
- **Data exfiltration** - ส่งข้อมูลออกนอก

---

### Module 3: External Script Detector

**ไฟล์:** `detectors/script_detector.py`

#### ตรวจจับอะไร?

1. **External Scripts** - scripts จาก domain อื่น
   ```html
   <script src="https://other-domain.com/script.js"></script>
   ```

2. **Malicious Domain Scripts** - scripts จาก blocklist
   ```html
   <script src="https://evil.com/malware.js"></script>
   ```

3. **Suspicious TLD Scripts** - scripts จาก TLD น่าสงสัย
   ```html
   <script src="https://bad.tk/script.js"></script>
   ```

4. **Mixed Content** - HTTP scripts บน HTTPS page
   ```html
   <!-- บน https://example.com -->
   <script src="http://insecure.com/script.js"></script>
   ```

#### การตรวจสอบ

1. ดึง `src` attribute จากทุก `<script>` tag
2. เปรียบเทียบ domain กับ base domain ของหน้าเว็บ
3. ตรวจสอบกับ blocklist และ suspicious TLD list
4. ตรวจสอบ protocol (HTTP vs HTTPS)

#### ความเสี่ยง

- **Third-party tracking** - ติดตามพฤติกรรมผู้ใช้
- **Ad injection** - inject โฆษณา
- **Malware delivery** - ส่ง malware ผ่าน CDN ที่ถูก hack

---

### Module 4: Dangerous Link Detector

**ไฟล์:** `detectors/link_detector.py`

#### ตรวจจับอะไร?

1. **Sensitive File Links** - ลิงก์ไปยังไฟล์สำคัญ
   - `.git/` - Git repository
   - `.env` - Environment variables (API keys, passwords)
   - `.htaccess` - Apache configuration

2. **Configuration Files** - ไฟล์ config
   - `config.php`, `config.json`, `config.yml`
   - `web.config`, `database.yml`
   - `settings.py`

3. **Backup Files** - ไฟล์ backup
   - `.bak`, `.backup`, `.old`
   - `.sql`, `.dump`

4. **Admin Panels** - หน้า admin
   - `/admin`, `/wp-admin`, `/phpmyadmin`
   - `/administrator`, `/cpanel`, `/manager`

5. **API Keys/Tokens** - คีย์ที่ expose
   - `api_key=`, `api_token=`, `access_token=`
   - `secret_key=`

#### การตรวจสอบ

1. ตรวจสอบ `href` attribute ในทุก `<a>` และ `<link>` tag
2. ตรวจสอบ `action` attribute ใน `<form>` tag
3. ใช้ regex ค้นหา patterns ใน raw HTML
4. ใช้ boundary matching เพื่อลด false positives

#### ตัวอย่างที่ตรวจจับได้

```html
<!-- Sensitive file -->
<a href="/.env">Download config</a>
<a href="/.git/config">Git config</a>

<!-- Backup file -->
<a href="/backup.sql">Database backup</a>

<!-- Admin panel -->
<a href="/wp-admin">Login</a>

<!-- API key exposure -->
<script>var apiKey = "sk-1234567890"</script>
```

#### ความเสี่ยง

- **Information disclosure** - เปิดเผยข้อมูลสำคัญ
- **Unauthorized access** - เข้าถึงระบบโดยไม่ได้รับอนุญาต
- **Database leak** - ข้อมูลฐานข้อมูลรั่วไหล

---

### Module 5: Cryptojacking Detector

**ไฟล์:** `detectors/js_detector.py` (method: `_check_cryptojacking`)

#### ตรวจจับอะไร?

1. **Known Mining Libraries**
   - CoinHive, CoinImp, CryptoLoot
   - WebMiner, JSECoin, MinerGate

2. **Mining Function Names**
   - `startMining()`, `stopMining()`
   - `getMiningStats()`, `miner.start()`
   - `hashrate`

3. **Cryptocurrency Keywords**
   - `monero`, `XMR` (Monero ticker)
   - `CoinMiner`, `CryptoMiner`

4. **Mining Domain URLs**
   - `coinhive.com`, `cryptoloot.pro`
   - `webmine.pro`, `minergate.com`
   - `jsecoin.com`, `coinimp.com`

#### ตัวอย่างที่ตรวจจับได้

```javascript
// CoinHive
<script src="https://coinhive.com/lib/coinhive.min.js"></script>
<script>
    var miner = new CoinHive.Anonymous('SITE_KEY');
    miner.start();
</script>

// CryptoLoot
<script src="https://cryptoloot.pro/lib/cryptoloot.min.js"></script>
<script>
    var miner = new CryptoLoot.Anonymous('KEY');
    miner.start();
</script>

// WebMine
<script src="https://webmine.pro/miner.js"></script>
```

#### วิธีทำงานของ Cryptojacking

1. เว็บโหลด mining JavaScript
2. Script เชื่อมต่อกับ mining pool
3. ใช้ CPU ของผู้ใช้ขุด cryptocurrency (มักเป็น Monero)
4. ผลลัพธ์ส่งไปยังเจ้าของเว็บ

#### ผลกระทบ

- **CPU usage สูง** - เครื่องช้า, ร้อน
- **เปลืองไฟ** - ใช้พลังงานโดยไม่จำเป็น
- **ลดอายุ hardware** - CPU ทำงานหนักตลอดเวลา

---

## Limitations & Future Work - รายละเอียดเชิงลึก

---

### ข้อจำกัดปัจจุบัน

#### 1. Signature-Based Detection

**ปัญหา:**
- ตรวจจับได้เฉพาะ patterns ที่รู้จัก
- ไม่สามารถตรวจจับ zero-day threats ได้
- Mining scripts ใหม่ที่ยังไม่อยู่ใน list จะหลุดรอด

**ตัวอย่าง:**
```javascript
// Mining script ใหม่ที่ยังไม่รู้จัก
var x = new UnknownMiner('key');
x.begin();  // ไม่ตรวจจับเพราะไม่อยู่ใน patterns
```

#### 2. No Threat Intelligence Integration

**ปัญหา:**
- ไม่มี connection กับ Google Safe Browsing
- ไม่มี VirusTotal API integration
- Blocklist เป็น manual update

**ผลกระทบ:**
- ต้องเพิ่ม malicious domains เอง
- ไม่ได้รับ update อัตโนมัติ
- อาจพลาด domains ใหม่ที่ยังไม่ได้เพิ่ม

#### 3. False Positives

**ปัญหา:**
- Safe domains (Google, Facebook) ถูกตรวจจับ
- GTM iframe ถูกนับเป็น hidden iframe
- External scripts จาก CDN ถูกนับเป็น suspicious

**ตัวอย่าง:**
```html
<!-- Google Tag Manager - ไม่อันตราย แต่ถูกตรวจจับ -->
<iframe src="https://www.googletagmanager.com/ns.html" style="display:none"></iframe>
```

#### 4. No Behavioral Analysis

**ปัญหา:**
- วิเคราะห์เฉพาะ static code
- ไม่ตรวจสอบ runtime behavior
- ไม่สามารถตรวจจับ dynamic malware ได้

**ตัวอย่าง:**
```javascript
// Malware ที่โหลดมาทีหลัง
setTimeout(function() {
    loadMaliciousScript();  // ไม่ตรวจจับเพราะรันทีหลัง
}, 5000);
```

#### 5. Limited Protocol Support

**ปัญหา:**
- ตรวจสอบเฉพาะ HTTP/HTTPS
- ไม่รองรับ WebSocket connections
- ไม่ตรวจสอบ WebRTC leaks

---

### สิ่งที่อยากทำเพิ่ม (Future Work)

#### 1. Google Safe Browsing API Integration

**ทำอะไร:**
- เชื่อมต่อกับ Google Safe Browsing API
- ตรวจสอบ URLs กับ Google's database
- ได้รับ real-time updates

**ประโยชน์:**
- ตรวจจับ phishing/malware domains ได้ดีขึ้น
- ลด false positives
- Update อัตโนมัติ

**วิธีทำ:**
```python
import requests

def check_safe_browsing(url):
    api_key = "YOUR_API_KEY"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(endpoint, json=payload)
    return response.json()
```

#### 2. Machine Learning-Based Detection

**ทำอะไร:**
- Train model เพื่อ classify malicious vs benign scripts
- ใช้ features เช่น entropy, string patterns, API calls
- Predict risk score ด้วย ML

**Features ที่ใช้:**
- String entropy (ความสุ่มของ string)
- จำนวน function calls
- จำนวน DOM manipulations
- จำนวน network requests
- ความยาวของ script

**วิธีทำ:**
```python
from sklearn.ensemble import RandomForestClassifier

# Features: [entropy, func_calls, dom_ops, net_requests, length]
X = [[3.2, 5, 10, 2, 500], [7.8, 50, 100, 20, 5000]]
y = [0, 1]  # 0 = benign, 1 = malicious

model = RandomForestClassifier()
model.fit(X, y)

# Predict
risk = model.predict([[5.5, 25, 50, 10, 2500]])
```

#### 3. Real-Time Monitoring Mode

**ทำอะไร:**
- Monitor web traffic แบบ real-time
- ตรวจสอบทุก request/response
- Alert ทันทีเมื่อพบ threat

**วิธีทำ:**
- Browser extension (Chrome/Firefox)
- Proxy server (mitmproxy)
- Network packet inspection

#### 4. Browser Extension

**ทำอะไร:**
- Extension สำหรับ Chrome/Firefox
- ตรวจสอบทุกหน้าที่ผู้ใช้เข้า
- แสดง risk badge บน address bar

**Features:**
- Real-time scanning
- Block malicious sites
- History sync กับ main app

#### 5. Community Blocklist

**ทำอะไร:**
- ระบบรายงาน malicious domains
- Users สามารถ report domains ได้
- Blocklist update จาก community

**วิธีทำ:**
- Web interface สำหรับ report
- Voting system สำหรับ verify reports
- Auto-update blocklist

#### 6. Screenshot Capture

**ทำอะไร:**
- จับ screenshot ของหน้าที่ scan
- เปรียบเทียบกับ known phishing pages
- ใช้ image recognition ตรวจจับ fake login forms

#### 7. API Rate Limiting & Authentication

**ทำอะไร:**
- เพิ่ม rate limiting ป้องกัน abuse
- เพิ่ม API key authentication
- เพิ่ม user accounts

#### 8. Docker Containerization

**ทำอะไร:**
- สร้าง Docker image
- Deploy ง่ายบน server
- Scale ได้ง่าย

---

### สรุป

| ข้อจำกัด | วิธีแก้ |
|----------|---------|
| Signature-based | เพิ่ม ML-based detection |
| No threat intel | เชื่อมต่อ Google Safe Browsing |
| False positives | เพิ่ม whitelist + noscript check |
| No behavioral analysis | เพิ่ม runtime monitoring |
| Limited protocols | เพิ่ม WebSocket/WebRTC support |
