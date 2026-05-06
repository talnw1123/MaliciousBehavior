# สรุป 5 Detection Modules & Limitations - สำหรับ Present

---

## 5 Detection Modules - อธิบายแบบเข้าใจง่าย

---

### Module 1: Iframe Detector (ตรวจจับ iframe ซ่อนเร้น)

#### iframe คืออะไร?
- หน้าเว็บเล็กๆ ที่ฝังอยู่ในหน้าเว็บใหญ่
- เหมือน "หน้าต่าง" ที่เปิดเว็บอื่นซ้อนอยู่

#### เราตรวจจับอะไร?

**1. iframe ที่ซ่อนจากผู้ใช้**
```html
<!-- ซ่อนด้วย CSS -->
<iframe src="https://evil.com" style="display:none"></iframe>

<!-- ขนาดเป็น 0 -->
<iframe src="https://bad.com" width="0" height="0"></iframe>
```
→ **ทำไมต้องซ่อน?** เพราะไม่อยากให้ผู้ใช้เห็น!

**2. iframe จาก domain อันตราย**
```html
<iframe src="https://evil.com/phishing"></iframe>
```
→ เรามี "blacklist" domain ที่รู้ว่าอันตราย

**3. iframe จาก TLD น่าสงสัย**
```html
<iframe src="https://bad.tk/malware"></iframe>
<iframe src="https://hack.xyz/exploit"></iframe>
```
→ `.tk`, `.xyz`, `.top` มักใช้ทำเว็บไม่ดี

#### ความเสี่ยง?
- **Phishing** - ขโมย username/password
- **Malware** - ติดไวรัสโดยไม่รู้ตัว
- **Clickjacking** - หลอกให้คลิกปุ่มโดยไม่รู้ตัว

---

### Module 2: JavaScript Obfuscation Detector (ตรวจจับ JS ที่พยายามซ่อน)

#### Obfuscation คืออะไร?
- การทำให้โค้ดอ่านไม่ออก
- เหมือนเขียนรหัสลับ

#### เราตรวจจับอะไร?

**1. eval() - รันโค้ดอะไรก็ได้**
```javascript
// ปกติ
alert("hello")

// Obfuscated
eval("alert('hello')")  // ทำเหมือนกัน แต่ซ่อนใน eval()
```

**2. atob() - ถอดรหัส Base64**
```javascript
// ข้อความปกติ: "document.write('<script>malware</script>')"
// หลัง encode: "ZG9jdW1lbnQud3JpdGUoJzxzY3JpcHQ+bWFsd2FyZTwvc2NyaXB0Picp"

eval(atob("ZG9jdW1lbnQud3JpdGUoJzxzY3JpcHQ+bWFsd2FyZTwvc2NyaXB0Picp"))
// → รัน malware โดยผู้ใช้ไม่เห็นโค้ดจริง!
```

**3. String.fromCharCode() - สร้างตัวอักษรจากตัวเลข**
```javascript
// "alert" เขียนเป็นตัวเลข
String.fromCharCode(97, 108, 101, 114, 116)
// → ได้คำว่า "alert" แต่อ่านไม่ออกทันที
```

**4. Hex/Unicode Encoding**
```javascript
// "document" เขียนแบบ hex
"\x64\x6f\x63\x75\x6d\x65\x6e\x74"

// "document" เขียนแบบ unicode
"\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074"
```

#### ทำไมต้อง obfuscate?
- **ซ่อน malware** - ไม่ให้ antivirus ตรวจจับได้
- **ซ่อน keylogger** - ขโมยข้อมูลที่พิมพ์
- **ซ่อน phishing** - ขโมยข้อมูล login

---

### Module 3: External Script Detector (ตรวจจับ script จากภายนอก)

#### External Script คืออะไร?
- JavaScript ที่โหลดจากเว็บอื่น
```html
<!-- Script จากเว็บตัวเอง -->
<script src="/js/mycode.js"></script>

<!-- Script จากเว็บอื่น (external) -->
<script src="https://other-site.com/script.js"></script>
```

#### เราตรวจจับอะไร?

**1. Script จาก domain อื่น**
```html
<script src="https://unknown-site.com/tracker.js"></script>
```
→ อาจเป็น tracking script ที่เก็บข้อมูลเรา

**2. Script จาก domain อันตราย**
```html
<script src="https://evil.com/malware.js"></script>
```
→ malware ชัดเจน!

**3. Script ที่โหลดแบบไม่ปลอดภัย (HTTP)**
```html
<!-- บนเว็บ HTTPS -->
<script src="http://insecure.com/script.js"></script>
```
→ คนกลางสามารถดักจับและแก้ไขโค้ดได้

#### ความเสี่ยง?
- **Tracking** - เก็บข้อมูลการใช้งานเรา
- **Ads** - inject โฆษณา
- **Malware** - ส่งไวรัสผ่าน script

---

### Module 4: Dangerous Link Detector (ตรวจจับลิงก์อันตราย)

#### เราตรวจจับอะไร?

**1. ลิงก์ไปยังไฟล์สำคัญ**
```html
<a href="/.env">Config</a>        ← มี API keys, passwords
<a href="/.git/config">Git</a>    ← source code ทั้งหมด
<a href="/.htaccess">Apache</a>   ← server config
```

**2. ลิงก์ไปยังไฟล์ backup**
```html
<a href="/backup.sql">Database</a>    ← ข้อมูลฐานข้อมูล
<a href="/config.php.bak">Config</a>  ← ไฟล์ config เก่า
```

**3. ลิงก์ไปยังหน้า admin**
```html
<a href="/wp-admin">Login</a>         ← WordPress admin
<a href="/phpmyadmin">Database</a>    ← จัดการฐานข้อมูล
```

**4. API Keys ที่ expose**
```html
<script>var apiKey = "sk-1234567890"</script>
```

#### ความเสี่ยง?
- **ข้อมูลรั่ว** - passwords, API keys
- **Unauthorized access** - เข้าระบบโดยไม่ได้รับอนุญาต
- **Database leak** - ข้อมูลลูกค้ารั่วไหล

---

### Module 5: Cryptojacking Detector (ตรวจจับการขุดเงิน)

#### Cryptojacking คืออะไร?
- การใช้ CPU ของผู้ใช้ขุด cryptocurrency โดยไม่บอก
- เหมือนให้เครื่องเราทำงานให้เขาฟรีๆ

#### เราตรวจจับอะไร?

**1. Mining Libraries ที่รู้จัก**
```javascript
// CoinHive
var miner = new CoinHive.Anonymous('KEY');
miner.start();

// CryptoLoot
var miner = new CryptoLoot.Anonymous('KEY');
miner.start();
```

**2. Mining Functions**
```javascript
startMining()     // เริ่มขุด
stopMining()      // หยุดขุด
getMiningStats()  // ดูสถิติการขุด
```

**3. Cryptocurrency Keywords**
```javascript
monero    // ชื่อ cryptocurrency
XMR       // ตัวย่อ Monero
hashrate  // ความเร็วในการขุด
```

#### ผลกระทบ?
- **CPU ทำงานหนัก** - เครื่องช้า, ร้อน
- **เปลืองไฟ** - ใช้พลังงานโดยไม่จำเป็น
- **ลดอายุ hardware** - CPU เสื่อมเร็ว

---

## Limitations - ข้อจำกัดปัจจุบัน

### 1. ตรวจจับได้เฉพาะสิ่งที่รู้จัก (Signature-Based)

**ปัญหา:**
- เหมือนมี "รูปคนร้าย" แล้วคอยเทียบ
- ถ้าคนร้ายเปลี่ยนหน้า → ตรวจจับไม่ได้

**ตัวอย่าง:**
```javascript
// เรารู้จัก CoinHive → ตรวจจับได้
var miner = new CoinHive.Anonymous('KEY');

// แต่ถ้ามินิงตัวใหม่ที่เราไม่รู้จัก → หลุดรอด
var x = new UnknownMiner('KEY');
```

### 2. ไม่เห็นโค้ดที่รันทีหลัง (No Behavioral Analysis)

**ปัญหา:**
- เราอ่านแค่ source code
- ไม่เห็นสิ่งที่เกิดขึ้นตอนรันจริง

**ตัวอย่าง:**
```javascript
// รอ 10 วินาทีค่อยโหลด malware
setTimeout(function() {
    loadMalware();  // เราไม่เห็น!
}, 10000);
```

### 3. False Positives (แจ้งเตือนผิด)

**ปัญหา:**
- บางครั้งแจ้งเตือนสิ่งที่ปลอดภัย

**ตัวอย่าง:**
```html
<!-- Google Tag Manager - ปลอดภัย แต่เราแจ้งเตือน -->
<iframe src="https://googletagmanager.com" style="display:none"></iframe>
```

### 4. ไม่ดึงข้อมูลแบบ Real Browser

**ปัญหา:**
- เราดึงแค่ HTML text
- ไม่รัน JavaScript → ไม่เห็น DOM หลัง render

**ตัวอย่าง:**
```javascript
// สร้าง iframe แบบ dynamic - เราไม่เห็น
document.write('<iframe src="https://evil.com"></iframe>');
```

---

## Future Work - สิ่งที่อยากทำเพิ่ม

### 1. เชื่อมต่อ Google Safe Browsing API

**ทำอะไร:**
- ใช้ database ของ Google ที่รู้จักเว็บอันตรายล้านๆ เว็บ
- ได้ update อัตโนมัติทุกวัน

**ประโยชน์:**
- ตรวจจับ phishing/malware ได้ดีขึ้น
- ไม่ต้องเพิ่ม blacklist เอง

### 2. ใช้ Machine Learning

**ทำอะไร:**
- ฝึก AI ให้รู้จัก patterns ใหม่
- ตรวจจับ zero-day threats ได้

**ประโยชน์:**
- ตรวจจับ malware ใหม่ที่ยังไม่เคยเห็น
- ลด false positives

### 3. ใช้ Headless Browser (Playwright/Puppeteer)

**ทำอะไร:**
- รันเว็บจริงใน browser ที่ไม่มีหน้าจอ
- เห็น DOM หลัง render แล้ว
- เห็น network requests ทั้งหมด

**ประโยชน์:**
- ตรวจจับ malware ที่โหลดทีหลังได้
- เห็น dynamic content

### 4. ทำ Browser Extension

**ทำอะไร:**
- Extension สำหรับ Chrome/Firefox
- ตรวจสอบทุกหน้าที่ผู้ใช้เข้าแบบ real-time

**ประโยชน์:**
- ป้องกันผู้ใช้ทันที
- ไม่ต้อง copy URL มา scan

### 5. Community Blocklist

**ทำอะไร:**
- ให้ผู้ใช้รายงานเว็บอันตรายได้
- Blocklist update จากชุมชน

**ประโยชน์:**
- ได้ข้อมูลใหม่ๆ เร็วขึ้น
- ช่วยกันป้องกัน

---

## สรุปสั้นๆ

| Module | ตรวจจับอะไร | ความเสี่ยง |
|--------|-------------|-----------|
| Iframe | หน้าเว็บซ้อนที่ซ่อน | Phishing, malware |
| JavaScript | โค้ดที่พยายามซ่อน | Keylogger, malware |
| External Script | Script จากเว็บอื่น | Tracking, ads |
| Dangerous Link | ลิงก์ไฟล์สำคัญ | ข้อมูลรั่ว |
| Cryptojacking | การขุดเงินแอบแฝง | CPU ทำงานหนัก |

| ข้อจำกัด | วิธีแก้ในอนาคต |
|----------|---------------|
| ตรวจจับได้เฉพาะสิ่งที่รู้จัก | Machine Learning |
| ไม่เห็นโค้ดที่รันทีหลัง | Headless Browser |
| False positives | Google Safe Browsing |
| ไม่ดึงข้อมูลแบบ real browser | Playwright/Puppeteer |
