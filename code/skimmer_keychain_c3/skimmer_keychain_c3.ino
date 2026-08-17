/*
  Same behavior as the ESP32 (WROOM) version, ported to the Seeed XIAO
  ESP32-C3 and updated for the current toolchain.

  WHAT CHANGED FROM THE ESP32 (WROOM) VERSION
    1. Pins remapped to the XIAO: button D0 (GPIO2), buzzer D1 (GPIO3),
       motor D2 (GPIO4).
    2. Deep-sleep wake: ESP32-C3 has no ext0. Uses GPIO wakeup instead
       (esp_deep_sleep_enable_gpio_wakeup). Wake GPIO must be 0-5 on the C3;
       D0 = GPIO2 satisfies this.
    3. LEDC (PWM) updated to ESP32 core 3.x API: ledcAttach(pin,freq,res) and
       ledcWrite(pin,duty) - no manual channel numbers.
    4. Buzzer now driven with LEDC (ledcWriteTone) instead of tone(), which is
       the reliable ESP32-native way to make tones.
    5. BLE scan updated to NimBLE-Arduino 2.x: getResults(ms) instead of the
       old blocking start(seconds); device iteration uses const pointers.

  REQUIRED VERSIONS (install these, or the API calls below won't match)
    - ESP32 Arduino core 3.x (Boards Manager: "esp32" by Espressif)
    - NimBLE-Arduino 2.x (Library Manager)
    Board selection: Tools -> Board -> "XIAO_ESP32C3".
    Also set Tools -> "USB CDC On Boot: Enabled" so Serial works.

  MODES / BUTTON MAP
    - Single press wakes from deep sleep -> SCAN mode.
    - SCAN: locks onto the strongest suspicious BLE device; motor + buzzer
      intensify as you move closer (parking-sensor style).
    - Double press -> SYNC mode: starts a WiFi hotspot + web page for the log.
    - Long press (~2s) -> deep sleep.
    - Auto-sleep after IDLE_TIMEOUT_MS with nothing suspicious.

  SCOPE NOTE (unchanged): detects BLE-transmitting skimmers only. A quiet
  device is NOT proof a terminal is clean - still do the physical wiggle test.
*/

#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <esp_sleep.h>


// ---- must be declared before the first function definition ----
struct Candidate {
  bool   found = false;
  int    score = 0;
  int    rssi  = -127;
  String mac;
  String name;
  String reasons;
};

volatile unsigned long lastIsrMs = 0;
volatile uint8_t pressCount = 0;

void IRAM_ATTR onButtonPress() {
  unsigned long now = millis();
  if (now - lastIsrMs > 50) {   // debounce
    pressCount++;
    lastIsrMs = now;
  }
}


// ------------------------- Pin config (XIAO ESP32-C3) -------------------------
const int BUTTON_PIN = 2;   // D0  (RTC/GPIO wake capable; must be GPIO 0-5)
const int BUZZER_PIN = 3;   // D1
const int MOTOR_PIN  = 4;   // D2  (to NPN transistor base via 1k)

// ------------------------- Scan / scoring config -------------------------
const uint32_t SCAN_BURST_MS        = 1000; // one scan burst (NimBLE 2.x = ms)
const int   RSSI_STRONG_THRESHOLD   = -55;  // "very close" cutoff for scoring
const int   SCORE_ALERT_THRESHOLD   = 3;    // score >= this = suspicious

// RSSI-to-intensity mapping range (dBm). Tune to your board's antenna.
const int   RSSI_FAR   = -90;  // barely detectable -> weakest feedback
const int   RSSI_CLOSE = -45;  // right on top of it -> strongest feedback

// Timing
const unsigned long IDLE_TIMEOUT_MS = 90UL * 1000UL;
const unsigned long LONG_PRESS_MS   = 2000;
const unsigned long DOUBLE_PRESS_WINDOW_MS = 600;

// WiFi SoftAP (sync mode)
const char* AP_SSID = "SkimmerCheck";
const char* AP_PASS = "check1234"; // >= 8 chars

// Generic BLE serial-module name patterns often repurposed in skimmers.
const char* SUSPICIOUS_NAME_PATTERNS[] = {
  "HC-05", "HC-06", "HM-10", "AT-09", "BT05", "BT_", "linvor", "JDY"
};
const int NUM_PATTERNS = sizeof(SUSPICIOUS_NAME_PATTERNS)/sizeof(SUSPICIOUS_NAME_PATTERNS[0]);

// ------------------------- PWM (LEDC) config -------------------------
const int MOTOR_PWM_FREQ = 20000; // 20 kHz, inaudible
const int MOTOR_PWM_RES  = 8;     // 8-bit duty (0-255)

// ------------------------- Persistent across deep sleep -------------------------
RTC_DATA_ATTR int bootCount = 0;

WebServer server(80);
NimBLEScan* pBLEScan;

float smoothedRssi = -100.0f;
bool  haveLock = false;
String lockedMac = "";

enum Mode { MODE_SCAN, MODE_SYNC };
Mode currentMode = MODE_SCAN;
unsigned long lastSuspiciousMs = 0;

// ------------------------- Buzzer (LEDC tone) -------------------------
bool beeping = false;
unsigned long beepStopAt = 0;

void startBeep(int freq, int durMs) {   // non-blocking beep
  ledcWriteTone(BUZZER_PIN, freq);
  beeping = true;
  beepStopAt = millis() + durMs;
}
void serviceBeep() {                     // call every loop; stops the beep
  if (beeping && (long)(millis() - beepStopAt) >= 0) {
    ledcWriteTone(BUZZER_PIN, 0);
    beeping = false;
  }
}
void blockingBeep(int freq, int durMs) { // for one-off confirmation buzzes
  ledcWriteTone(BUZZER_PIN, freq);
  delay(durMs);
  ledcWriteTone(BUZZER_PIN, 0);
}

// ------------------------- Helpers -------------------------
bool nameMatchesPattern(const std::string& name) {
  if (name.empty()) return false;
  String n = String(name.c_str()); n.toUpperCase();
  for (int i = 0; i < NUM_PATTERNS; i++) {
    String pat = String(SUSPICIOUS_NAME_PATTERNS[i]); pat.toUpperCase();
    if (n.indexOf(pat) >= 0) return true;
  }
  return false;
}

int scoreDevice(const NimBLEAdvertisedDevice* dev, String& reasonOut) {
  int score = 0; reasonOut = "";
  int rssi = dev->getRSSI();
  if (rssi >= RSSI_STRONG_THRESHOLD) { score += 2; reasonOut += "strong-signal "; }

  std::string name = dev->getName();
  if (name.empty())                 { score += 1; reasonOut += "no-name "; }
  else if (nameMatchesPattern(name)){ score += 2; reasonOut += "module-name "; }

  if (dev->haveServiceUUID()) {
    for (int i = 0; i < dev->getServiceUUIDCount(); i++) {
      std::string uuid = dev->getServiceUUID(i).toString();
      if (uuid.find("ffe0") != std::string::npos ||
          uuid.find("ffe1") != std::string::npos) {
        score += 1; reasonOut += "serial-uuid ";
      }
    }
  }
  return score;
}

// ------------------------- Logging (LittleFS) -------------------------
void logDetection(const Candidate& c) {
  File f = LittleFS.open("/log.csv", FILE_APPEND);
  if (!f) return;
  f.printf("%d,%lu,%s,%d,%d,%s,%s\n",
           bootCount, millis(), c.mac.c_str(), c.score, c.rssi,
           c.name.c_str(), c.reasons.c_str());
  f.close();
}

// ------------------------- Feedback (motor + buzzer) -------------------------
unsigned long lastBeepMs = 0;

void feedbackForRssi(float rssi) {
  float t = (rssi - RSSI_FAR) / float(RSSI_CLOSE - RSSI_FAR);
  if (t < 0) t = 0; if (t > 1) t = 1;
  int duty = int(t * 255);
  ledcWrite(MOTOR_PIN, duty);

  unsigned long interval = (unsigned long)(1200 - t * 1120); // 1200ms -> 80ms
  if (millis() - lastBeepMs > interval) {
    startBeep(2500, 40);
    lastBeepMs = millis();
  }
}

void feedbackOff() {
  ledcWrite(MOTOR_PIN, 0);
  ledcWriteTone(BUZZER_PIN, 0);
  beeping = false;
}

// ------------------------- BLE scan -> pick best candidate -------------------------
Candidate scanOnce() {
  Candidate best;
  NimBLEScanResults results = pBLEScan->getResults(SCAN_BURST_MS, false);
  int n = results.getCount();
  for (int i = 0; i < n; i++) {
    const NimBLEAdvertisedDevice* dev = results.getDevice(i);
    String reasons;
    int score = scoreDevice(dev, reasons);
    if (score >= SCORE_ALERT_THRESHOLD) {
      int rssi = dev->getRSSI();
      if (!best.found || score > best.score ||
          (score == best.score && rssi > best.rssi)) {
        best.found   = true;
        best.score   = score;
        best.rssi    = rssi;
        best.mac     = String(dev->getAddress().toString().c_str());
        best.name    = String(dev->getName().c_str());
        best.reasons = reasons;
      }
    }
  }
  pBLEScan->clearResults();
  return best;
}

// ------------------------- Web server (sync mode) -------------------------
String htmlPage() {
  String p;
  p += "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  p += "<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p += "<title>Skimmer Check Log</title><style>";
  p += "body{font-family:system-ui,sans-serif;margin:0;padding:16px;background:#111;color:#eee}";
  p += "h1{font-size:18px}table{width:100%;border-collapse:collapse;font-size:13px}";
  p += "th,td{text-align:left;padding:6px 4px;border-bottom:1px solid #333}";
  p += ".s{color:#ff5c5c;font-weight:bold}.muted{color:#888;font-size:12px}";
  p += "a.btn{display:inline-block;margin:8px 0;color:#4ea1ff}";
  p += "</style></head><body>";
  p += "<h1>Skimmer Check &mdash; detection log</h1>";
  p += "<p class='muted'>Times for the current session are computed from your phone's clock. ";
  p += "Older sessions show relative time only (add a DS3231 RTC for full timestamps).</p>";
  p += "<a class='btn' href='/download'>Download raw CSV</a> ";
  p += "<a class='btn' href='/clear' onclick=\"return confirm('Clear all logged detections?')\">Clear log</a>";
  p += "<table id='t'><thead><tr><th>When</th><th>Score</th><th>RSSI</th><th>Name</th><th>MAC</th><th>Flags</th></tr></thead><tbody></tbody></table>";
  p += "<script>";
  p += "fetch('/data').then(r=>r.json()).then(d=>{";
  p += " const now=Date.now(); const up=d.device_now_ms; const cur=d.boot;";
  p += " const tb=document.querySelector('#t tbody');";
  p += " d.entries.reverse().forEach(e=>{";
  p += "  let when;";
  p += "  if(e.boot===cur){ let ms=now-(up-e.ms); when=new Date(ms).toLocaleString(); }";
  p += "  else { when='session '+e.boot+', +'+Math.round(e.ms/1000)+'s'; }";
  p += "  const tr=document.createElement('tr');";
  p += "  tr.innerHTML=`<td>${when}</td><td class='s'>${e.score}</td><td>${e.rssi}</td>`+";
  p += "   `<td>${e.name||'(none)'}</td><td>${e.mac}</td><td class='muted'>${e.reasons}</td>`;";
  p += "  tb.appendChild(tr);";
  p += " });";
  p += " if(!d.entries.length){tb.innerHTML='<tr><td colspan=6 class=muted>No detections logged yet.</td></tr>';}";
  p += "});";
  p += "</script></body></html>";
  return p;
}

void handleRoot() { server.send(200, "text/html", htmlPage()); }

void handleData() {
  String json = "{\"device_now_ms\":" + String(millis()) +
                ",\"boot\":" + String(bootCount) + ",\"entries\":[";
  File f = LittleFS.open("/log.csv", FILE_READ);
  bool first = true;
  if (f) {
    while (f.available()) {
      String line = f.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) continue;
      int c1 = line.indexOf(','); int c2 = line.indexOf(',', c1+1);
      int c3 = line.indexOf(',', c2+1); int c4 = line.indexOf(',', c3+1);
      int c5 = line.indexOf(',', c4+1); int c6 = line.indexOf(',', c5+1);
      if (c6 < 0) continue;
      String boot=line.substring(0,c1), ms=line.substring(c1+1,c2),
             mac=line.substring(c2+1,c3), score=line.substring(c3+1,c4),
             rssi=line.substring(c4+1,c5), name=line.substring(c5+1,c6),
             reasons=line.substring(c6+1);
      if (!first) json += ",";
      first = false;
      json += "{\"boot\":"+boot+",\"ms\":"+ms+",\"mac\":\""+mac+"\",\"score\":"+score+
              ",\"rssi\":"+rssi+",\"name\":\""+name+"\",\"reasons\":\""+reasons+"\"}";
    }
    f.close();
  }
  json += "]}";
  server.send(200, "application/json", json);
}

void handleDownload() {
  File f = LittleFS.open("/log.csv", FILE_READ);
  if (!f) { server.send(200, "text/plain", "boot,ms,mac,score,rssi,name,reasons\n"); return; }
  server.streamFile(f, "text/csv");
  f.close();
}

void handleClear() {
  LittleFS.remove("/log.csv");
  server.send(200, "text/html", "<meta http-equiv='refresh' content='1;url=/'>Cleared.");
}

void startSyncMode() {
  currentMode = MODE_SYNC;
  feedbackOff();
  NimBLEDevice::deinit(true);   // free the radio for WiFi
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  server.on("/", handleRoot);
  server.on("/data", handleData);
  server.on("/download", handleDownload);
  server.on("/clear", handleClear);
  server.begin();
  for (int i=0;i<3;i++){ blockingBeep(1800,80); delay(60); } // sync-mode confirm
}

// ------------------------- Button handling -------------------------
// Returns: 0 none, 1 single, 2 double, 3 long
int readButtonEvent() {
  // Long press: button currently held — poll until release or threshold
  if (digitalRead(BUTTON_PIN) == LOW) {
    unsigned long start = millis();
    while (digitalRead(BUTTON_PIN) == LOW) {
      if (millis() - start > LONG_PRESS_MS) {
        noInterrupts(); pressCount = 0; interrupts();   // discard latched taps
        return 3;
      }
      delay(5);
    }
  }

  // Short presses latched by the ISR, resolved once the double-press
  // window has elapsed with no further presses
  noInterrupts();
  uint8_t count = pressCount;
  unsigned long last = lastIsrMs;
  interrupts();

  if (count > 0 && (millis() - last) > DOUBLE_PRESS_WINDOW_MS) {
    noInterrupts(); pressCount = 0; interrupts();
    return (count >= 2) ? 2 : 1;
  }
  return 0;
}

void goToSleep() {
  feedbackOff();
  Serial.println("Entering deep sleep. Press button to wake.");
  Serial.flush();                 // ensure the line is sent before USB dies
  blockingBeep(1600, 120);        // descending pair = going to sleep
  delay(40);
  blockingBeep(1100, 200);
  while (digitalRead(BUTTON_PIN) == LOW) delay(10);
  delay(150);
  esp_deep_sleep_enable_gpio_wakeup(1ULL << BUTTON_PIN, ESP_GPIO_WAKEUP_GPIO_LOW);
  delay(50);
  esp_deep_sleep_start();
}

// ------------------------- Setup / loop -------------------------
void setup() {
  Serial.begin(115200);
  bootCount++;

  pinMode(BUTTON_PIN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(BUTTON_PIN), onButtonPress, FALLING);

  // LEDC: attach motor (PWM duty) and buzzer (tone) pins
  ledcAttach(MOTOR_PIN, MOTOR_PWM_FREQ, MOTOR_PWM_RES);
  ledcAttach(BUZZER_PIN, 2000, 8);   // base config; ledcWriteTone sets frequency
  ledcWrite(MOTOR_PIN, 0);

  if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed");

  NimBLEDevice::init("");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  currentMode = MODE_SCAN;
  lastSuspiciousMs = millis();

  blockingBeep(2200, 120); // wake-confirm buzz
  Serial.printf("Awake. Boot #%d. SCAN mode.\n", bootCount);
}

void loop() {
  serviceBeep(); // keep non-blocking beeps timed

  int ev = readButtonEvent();
  if (ev == 3) { goToSleep(); return; }
  if (ev == 2) {
    if (currentMode == MODE_SCAN) startSyncMode();
    return;
  }

  if (currentMode == MODE_SYNC) {
    server.handleClient();
    return;
  }

  // ---- SCAN mode ----
  Candidate c = scanOnce();

  if (c.found) {
    lastSuspiciousMs = millis();
    if (!haveLock || c.mac != lockedMac) {
      lockedMac = c.mac; haveLock = true; smoothedRssi = c.rssi;
      logDetection(c);
      Serial.printf("LOCK %s score=%d rssi=%d [%s]\n",
                    c.mac.c_str(), c.score, c.rssi, c.reasons.c_str());
    } else {
      smoothedRssi = 0.6f * smoothedRssi + 0.4f * c.rssi; // EMA
    }
    feedbackForRssi(smoothedRssi);
  } else {
    haveLock = false;
    feedbackOff();
    if (millis() - lastSuspiciousMs > IDLE_TIMEOUT_MS) {
      Serial.println("Idle timeout -> sleep");
      goToSleep();
    }
  }
}

/*
  RELIABILITY NOTES
  -----------------
  * Wake pull-up: internal pull-ups may not be guaranteed during deep sleep on
    the C3. If the device ever wakes on its own or won't wake, add an external
    ~100k pull-up from D0 to 3V3 so the button pin has a defined HIGH while
    asleep and the press pulls it cleanly LOW.
  * Deep-sleep current: the XIAO's onboard charge IC and power LED add draw
    beyond the chip's ~44 uA rating. For best battery life you can remove the
    power LED (or its resistor); measure actual sleep current and size the
    LiPo accordingly.
  * BLE vs WiFi never run at once - that's why SYNC mode calls
    NimBLEDevice::deinit(true) before starting the WiFi AP.
*/
