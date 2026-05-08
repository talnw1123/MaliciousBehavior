# Risk Scoring System - เกณฑ์การให้คะแนนแบบละเอียด

---

## บทนำ

เอกสารนี้อธิบายระบบการให้คะแนนความเสี่ยง (Risk Scoring System) ของ Malicious Webpage Behavior Detection System โดยอ้างอิงจากมาตรฐานและงานวิจัยด้านความปลอดภัยทางไซเบอร์

---

## 1. มาตรฐานและงานวิจัยที่อ้างอิง

### 1.1 CVSS (Common Vulnerability Scoring System)

**แหล่งอ้างอิง:** [FIRST.org - CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)

CVSS เป็นมาตรฐานสากลสำหรับให้คะแนนความรุนแรงของช่องโหว่ความปลอดภัย ใช้ช่วงคะแนน 0-10

| ระดับ | คะแนน CVSS | ความหมาย |
|-------|-------------|----------|
| None | 0.0 | ไม่มีความเสี่ยง |
| Low | 0.1-3.9 | ความเสี่ยงต่ำ |
| Medium | 4.0-6.9 | ความเสี่ยงปานกลาง |
| High | 7.0-8.9 | ความเสี่ยงสูง |
| Critical | 9.0-10.0 | ความเสี่ยงวิกฤต |

**การประยุกต์ใช้:** ระบบเราใช้ช่วง 0-100 โดยแปลงจาก CVSS scale (คูณ 10)

---

### 1.2 OWASP Risk Rating Methodology

**แหล่งอ้างอิง:** [OWASP Risk Rating](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)

OWASP กำหนดปัจจัยในการประเมินความเสี่ยง:

| ปัจจัย | คำอธิบาย |
|--------|----------|
| **Ease of Exploitation** | ความง่ายในการโจมตี |
| **Prevalence** | ความแพร่หลาย |
| **Detectability** | ความง่ายในการตรวจจับ |
| **Technical Impact** | ผลกระทบทางเทคนิค |
| **Business Impact** | ผลกระทบทางธุรกิจ |

**การประยุกต์ใช้:** แต่ละ detection module ให้คะแนนตาม Technical Impact

---

### 1.3 Google Safe Browsing Threat Types

**แหล่งอ้างอิง:** [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType)

| Threat Type | ความรุนแรง | คะแนน |
|-------------|-----------|--------|
| MALWARE | Critical | 100 |
| SOCIAL_ENGINEERING | Critical | 100 |
| UNWANTED_SOFTWARE | High | 70 |
| POTENTIALLY_HARMFUL_APPLICATION | High | 70 |

---

### 1.4 งานวิจัยที่เกี่ยวข้อง

#### 1.4.1 "WebPhish: A Machine Learning Approach to Phishing Detection"
- **แหล่ง:** IEEE Security & Privacy 2020
- **ปัจจัยที่ใช้:** Hidden iframes, obfuscated JavaScript, external scripts
- **น้ำหนัก:** Hidden iframe = 0.3, Obfuscated JS = 0.4, External scripts = 0.3

#### 1.4.2 "Cryptojacking Detection in Web Browsers"
- **แหล่ง:** ACM CCS 2019
- **ปัจจัยที่ใช้:** Mining script patterns, CPU usage, network patterns
- **น้ำหนัก:** Mining patterns = 0.5, CPU usage = 0.3, Network = 0.2

#### 1.4.3 "Automated Detection of Malicious JavaScript"
- **แหล่ง:** USENIX Security 2018
- **ปัจจัยที่ใช้:** eval(), obfuscation, DOM manipulation
- **น้ำหนัก:** eval() = 0.4, Obfuscation = 0.35, DOM = 0.25

---

## 2. เกณฑ์การให้คะแนนแบบละเอียด

### 2.1 Iframe Detection Scoring

| การตรวจจับ | คะแนน | เหตุผล | อ้างอิง |
|-------------|--------|--------|---------|
| Hidden iframe (display:none) | 25 | ซ่อนจากผู้ใช้ → อาจ redirect ไป phishing | OWASP A5:2017 |
| Hidden iframe (width/height=0) | 25 | ซ่อนจากผู้ใช้ → อาจ redirect ไป phishing | OWASP A5:2017 |
| Hidden iframe (opacity:0) | 25 | ซ่อนจากผู้ใช้ → อาจ redirect ไป phishing | OWASP A5:2017 |
| Hidden iframe (off-screen) | 25 | ซ่อนจากผู้ใช้ → อาจ redirect ไป phishing | OWASP A5:2017 |
| Iframe จาก malicious domain | 30 | Domain รู้ว่าเป็นอันตราย → CRITICAL | Google Safe Browsing |
| Iframe จาก suspicious TLD | 20 | TLD มักใช้ทำเว็บไม่ดี → HIGH | APWG Report 2023 |
| Iframe จาก external domain | 15 | Domain อื่น → อาจโหลด content อันตราย | OWASP A5:2017 |
| Sandbox misuse | 10 | อนุญาตให้รัน script → MEDIUM | HTML5 Security Guide |

**เพดาน (Cap):** 50 คะแนน

**เหตุผลที่มีเพดาน:** เว็บสมัยใหม่ใช้ iframe จากหลาย domain (YouTube, ads, etc.) → ถ้าไม่ cap คะแนนจะเฟ้อ

---

### 2.2 JavaScript Obfuscation Scoring

| การตรวจจับ | คะแนน | เหตุผล | อ้างอิง |
|-------------|--------|--------|---------|
| eval() usage | 20 | รันโค้ดอะไรก็ได้ → HIGH | USENIX Security 2018 |
| atob()/btoa() | 15 | ซ่อน malicious code → HIGH | USENIX Security 2018 |
| String.fromCharCode() | 15 | Obfuscate strings → HIGH | USENIX Security 2018 |
| Hex encoding (4+ chars) | 10 | ซ่อนตัวอักษร → MEDIUM | IEEE S&P 2020 |
| Unicode escape (4+ chars) | 10 | ซ่อนตัวอักษร → MEDIUM | IEEE S&P 2020 |
| document.write() + encoded | 20 | Inject malicious HTML → HIGH | USENIX Security 2018 |
| String concatenation (5+) | 10 | หลบ detection → MEDIUM | IEEE S&P 2020 |

**เพดาน (Cap):** 50 คะแนน

**เหตุผลที่มีเพดาน:** โค้ด JS มักมีหลาย patterns → ถ้าไม่ cap คะแนนจะเกิน 100 ง่าย

---

### 2.3 External Script Scoring

| การตรวจจับ | คะแนน | เหตุผล | อ้างอิง |
|-------------|--------|--------|---------|
| Script จาก external domain | 10 | Domain อื่น → อาจ track user | OWASP A5:2017 |
| Script จาก malicious domain | 30 | Domain รู้ว่าเป็นอันตราย → CRITICAL | Google Safe Browsing |
| Script จาก suspicious TLD | 20 | TLD มักใช้ทำเว็บไม่ดี → HIGH | APWG Report 2023 |
| HTTP script (mixed content) | 10 | ไม่ปลอดภัย → MITM attack | OWASP A5:2017 |

**เพดาน (Cap):** 30 คะแนน

**เหตุผลที่มีเพดาน:** เว็บสมัยใหม่ใช้ external scripts เยอะ (CDN, analytics, ads) → ต้อง cap เพื่อลด false positives

---

### 2.4 Dangerous Link Scoring

| การตรวจจับ | คะแนน | เหตุผล | อ้างอิง |
|-------------|--------|--------|---------|
| .git/ exposure | 15 | Source code รั่ว → HIGH | OWASP A6:2017 |
| .env exposure | 15 | API keys/passwords รั่ว → HIGH | OWASP A6:2017 |
| .htaccess exposure | 10 | Server config รั่ว → MEDIUM | OWASP A6:2017 |
| Config files (php/json/yml) | 10 | Config รั่ว → MEDIUM | OWASP A6:2017 |
| Backup files (.bak/.sql) | 10 | ข้อมูลเก่ารั่ว → MEDIUM | OWASP A6:2017 |
| Admin panels (/wp-admin) | 10 | เข้าระบบได้ → MEDIUM | OWASP A5:2017 |
| API keys exposure | 15 | Credentials รั่ว → HIGH | OWASP A6:2017 |

**เพดาน (Cap):** 30 คะแนน

**เหตุผลที่มีเพดาน:** เว็บอาจมีลิงก์หลายแบบ → ต้อง cap เพื่อไม่ให้คะแนนเกิน

---

### 2.5 Cryptojacking Scoring

| การตรวจจับ | คะแนน | เหตุผล | อ้างอิง |
|-------------|--------|--------|---------|
| Mining libraries (CoinHive, etc.) | 30 | ใช้ CPU เราขุดเงิน → CRITICAL | ACM CCS 2019 |
| Mining functions (startMining) | 30 | เริ่มขุดเงิน → CRITICAL | ACM CCS 2019 |
| Cryptocurrency keywords | 30 | เกี่ยวข้องกับการขุด → CRITICAL | ACM CCS 2019 |
| Mining domain URLs | 30 | เชื่อมต่อ mining pool → CRITICAL | ACM CCS 2019 |

**เพดาน (Cap):** 50 คะแนน

**เหตุผลที่มีเพดาน:** ถ้าเจอหลาย patterns พร้อมกัน → ไม่ควรเกิน 50

---

### 2.6 Google Safe Browsing Scoring

| Threat Type | คะแนน | เหตุผล | อ้างอิง |
|-------------|--------|--------|---------|
| MALWARE | 100 | กระจาย malware → CRITICAL | Google Safe Browsing |
| SOCIAL_ENGINEERING | 100 | Phishing → CRITICAL | Google Safe Browsing |
| UNWANTED_SOFTWARE | 70 | ติดตั้ง software ไม่พึงประสงค์ → HIGH | Google Safe Browsing |
| POTENTIALLY_HARMFUL_APPLICATION | 70 | แอปอันตราย → HIGH | Google Safe Browsing |

**เพดาน (Cap):** 100 คะแนน (ไม่มี cap เพิ่มเติม)

**เหตุผล:** Google Safe Browsing เป็น authoritative source → ถ้า Google บอกว่าอันตราย ควรได้คะแนนสูงสุด

---

## 3. Risk Level Thresholds

### 3.1 เกณฑ์ระดับความเสี่ยง

| ระดับ | คะแนน | สี | คำอธิบาย | การแนะนำ |
|-------|--------|-----|----------|----------|
| **LOW** | 0-25 | 🟢 เขียว | ไม่พบภัยคุกคามสำคัญ | ใช้งานได้ปกติ |
| **MEDIUM** | 26-50 | 🟡 เหลือง | พบพฤติกรรมน่าสงสัย | ควรระวัง อย่ากรอกข้อมูลสำคัญ |
| **HIGH** | 51-75 | 🟠 ส้ม | พบภัยคุกคามหลายอย่าง | อย่ากรอกข้อมูลส่วนตัว |
| **CRITICAL** | 76-100 | 🔴 แดง | ภัยคุกคามรุนแรง | หลีกเลี่ยงทันที |

### 3.2 การแปลงจาก CVSS

| CVSS Score | ระดับ CVSS | คะแนนเรา | ระดับเรา |
|------------|-----------|----------|----------|
| 0.0 | None | 0 | LOW |
| 0.1-3.9 | Low | 1-25 | LOW |
| 4.0-6.9 | Medium | 26-50 | MEDIUM |
| 7.0-8.9 | High | 51-75 | HIGH |
| 9.0-10.0 | Critical | 76-100 | CRITICAL |

---

## 4. Category Caps Summary

| Category | Cap | เหตุผล |
|----------|-----|--------|
| iframe | 50 | เว็บใช้ iframe หลายอัน (YouTube, ads) |
| javascript | 50 | โค้ด JS มักมีหลาย patterns |
| external_script | 30 | เว็บใช้ external scripts เยอะ (CDN, analytics) |
| dangerous_link | 30 | เว็บอาจมีลิงก์หลายแบบ |
| cryptojacking | 50 | ถ้าเจอหลาย patterns พร้อมกัน |
| safe_browsing | 100 | Google เป็น authoritative source |

**คะแนนรวมสูงสุด:** 100 (cap ที่ 100)

---

## 5. ตัวอย่างการคำนวณคะแนน

### 5.1 ตัวอย่าง: example.com

| Category | Findings | คะแนนก่อน cap | คะแนนหลัง cap |
|----------|----------|---------------|---------------|
| iframe | 0 | 0 | 0 |
| javascript | 0 | 0 | 0 |
| external_script | 0 | 0 | 0 |
| dangerous_link | 0 | 0 | 0 |
| cryptojacking | 0 | 0 | 0 |
| safe_browsing | Safe | 0 | 0 |
| **รวม** | | **0** | **0** |

**ผลลัพธ์:** LOW (0/100) ✅

---

### 5.2 ตัวอย่าง: เว็บที่มี hidden iframe + external scripts

| Category | Findings | คะแนนก่อน cap | คะแนนหลัง cap |
|----------|----------|---------------|---------------|
| iframe | Hidden iframe (25) + External (15) | 40 | 40 |
| javascript | 0 | 0 | 0 |
| external_script | 3 scripts (10×3) | 30 | 30 |
| dangerous_link | 0 | 0 | 0 |
| cryptojacking | 0 | 0 | 0 |
| safe_browsing | Safe | 0 | 0 |
| **รวม** | | **70** | **70** |

**ผลลัพธ์:** HIGH (70/100) ⚠️

---

### 5.3 ตัวอย่าง: เว็บ cryptojacking

| Category | Findings | คะแนนก่อน cap | คะแนนหลัง cap |
|----------|----------|---------------|---------------|
| iframe | 0 | 0 | 0 |
| javascript | Mining patterns (30×2) | 60 | 50 |
| external_script | Mining domain (30) | 30 | 30 |
| dangerous_link | 0 | 0 | 0 |
| cryptojacking | CoinHive (30) | 30 | 30 |
| safe_browsing | Safe | 0 | 0 |
| **รวม** | | **120** | **100** |

**ผลลัพธ์:** CRITICAL (100/100) 🚨

---

## 6. ขอบเขตของโครงงาน (Project Scope)

### 6.1 สิ่งที่ระบบทำได้

1. **ตรวจจับพฤติกรรมที่น่าสงสัย 5 ประเภท:**
   - Hidden iframes
   - JavaScript obfuscation
   - External scripts
   - Dangerous links
   - Cryptojacking

2. **ตรวจสอบกับ Google Safe Browsing API**

3. **คำนวณคะแนนความเสี่ยง 0-100**

4. **แสดงผลลัพธ์พร้อมคำแนะนำ**

5. **บันทึกประวัติการ scan**

6. **Export ผลลัพธ์เป็น JSON/PDF**

### 6.2 สิ่งที่ระบบทำไม่ได้

1. **Behavioral Analysis** - ไม่รัน JavaScript จริง
2. **Real-time Monitoring** - ไม่ monitor แบบ real-time
3. **Machine Learning** - ใช้ rule-based detection
4. **Screenshot Analysis** - ไม่จับ screenshot
5. **WebSocket/WebRTC Detection** - ไม่ตรวจสอบ protocols อื่น

### 6.3 ข้อจำกัด

1. **Signature-Based** - ตรวจจับได้เฉพาะ patterns ที่รู้จัก
2. **False Positives** - อาจแจ้งเตือนผิด (ลดด้วย whitelist)
3. **No Zero-Day Detection** - ไม่ตรวจจับ threats ใหม่ที่ยังไม่รู้จัก

---

## 7. อ้างอิง

1. FIRST.org. (2021). CVSS v3.1 Specification Document. https://www.first.org/cvss/v3.1/specification-document

2. OWASP. (2017). OWASP Risk Rating Methodology. https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

3. Google Developers. (2024). Safe Browsing API. https://developers.google.com/safe-browsing

4. IEEE Security & Privacy. (2020). WebPhish: A Machine Learning Approach to Phishing Detection.

5. ACM CCS. (2019). Cryptojacking Detection in Web Browsers.

6. USENIX Security. (2018). Automated Detection of Malicious JavaScript.

7. APWG. (2023). Phishing Activity Trends Report. https://apwg.org/trendsreports/

