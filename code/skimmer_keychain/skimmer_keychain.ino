/*
  ESP32 Keychain BLE Skimmer Detector  (v2 - proximity + logging + phone sync)
  ---------------------------------------------------------------------------
  A pocket/keychain device that helps a user check for BLE-exfiltrating card
  skimmers around an ATM or payment terminal.

  MODES / BUTTON MAP
    - Wakes from deep sleep on a single button press -> SCAN mode.
    - SCAN mode: continuously scans BLE, "locks onto" the strongest suspicious
      device, and drives a vibration motor + buzzer whose intensity/beep-rate
      increases as you physically move CLOSER to that device (RSSI gets
      stronger). Like a parking sensor: faster/stronger = closer.
    - Double press (while awake): -> SYNC mode. ESP32 starts a WiFi hotspot and
      a tiny web server. Connect your phone to the hotspot, open the page, and
      view/download the log of past detections. No phone app required.
    - Long press (hold ~2s): -> deep sleep (off).
    - Auto-sleep after IDLE_TIMEOUT_MS with nothing suspicious, to save battery.

  IMPORTANT SCOPE / HONESTY NOTE
    This only detects skimmers that transmit over BLE. It cannot detect
    local-storage-only skimmers, WiFi skimmers, pure magnetic shimmers, or
    hidden cameras / keypad overlays. A quiet device is NOT a guarantee the
    terminal is safe. Always still do the physical wiggle test.

  HARDWARE
    - ESP32 dev board (built-in BLE + WiFi)
    - Coin vibration motor  -> driven via NPN transistor (see wiring), PWM pin
    - Passive buzzer        -> BUZZER_PIN (tone-capable)
    - Momentary push button -> BUTTON_PIN, active LOW, wired to a
                               RTC-capable GPIO for deep-sleep wake (GPIO 33)
    - LiPo + TP4056 charger for portability

  LIBRARIES (Arduino Library Manager)
    - NimBLE-Arduino (h2zero)
    - (WiFi, WebServer, LittleFS, Preferences are part of the ESP32 core)

  NOTE: This is the original ESP32 (WROOM) version. If you are building on the
  XIAO ESP32-C3 (Option C), two changes are needed: remap the pins to D0/D1/D2
  (GPIO 2/3/4), and replace the ext0 deep-sleep wake with the C3's GPIO wake:
      esp_deep_sleep_enable_gpio_wakeup(1ULL << 2, ESP_GPIO_WAKEUP_GPIO_LOW);
  See notes below the code.
*/

#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <esp_sleep.h>

// ------------------------- Pin config -------------------------
const gpio_num_t BUTTON_PIN = GPIO_NUM_33; // RTC-capable, for ext0 wake
const int MOTOR_PIN  = 25;                 // vibration motor via transistor
const int BUZZER_PIN = 26;                 // passive buzzer

// ------------------------- Scan / scoring config -------------------------
const int   SCAN_BURST_SECONDS      = 2;    // one scan burst length
const int   RSSI_STRONG_THRESHOLD   = -55;  // "very close" cutoff for scoring
const int   SCORE_ALERT_THRESHOLD   = 3;    // score >= this = treat as suspicious

// RSSI-to-intensity mapping range (dBm). Tune to your board's antenna.
const int   RSSI_FAR   = -90;  // barely detectable -> weakest feedback
const int   RSSI_CLOSE = -45;  // right on top of it -> strongest feedback

// Timing
const unsigned long IDLE_TIMEOUT_MS = 90UL * 1000UL; // auto-sleep if idle
const unsigned long LONG_PRESS_MS   = 2000;
const unsigned long DOUBLE_PRESS_WINDOW_MS = 400;

// WiFi SoftAP (sync mode)
const char* AP_SSID = "SkimmerCheck";
const char* AP_PASS = "check1234"; // >= 8 chars required by WiFi

// Generic BLE serial-module name patterns often seen repurposed in skimmers.
// Heuristic, not a definitive blacklist.
const char* SUSPICIOUS_NAME_PATTERNS[] = {
  "HC-05", "HC-06", "HM-10", "AT-09", "BT05", "BT_", "linvor", "JDY"
};
const int NUM_PATTERNS = sizeof(SUSPICIOUS_NAME_PATTERNS)/sizeof(SUSPICIOUS_NAME_PATTERNS[0]);

// ------------------------- PWM (LEDC) for motor -------------------------
const int MOTOR_PWM_CHANNEL = 0;
const int MOTOR_PWM_FREQ    = 20000; // 20 kHz, inaudible
const int MOTOR_PWM_RES     = 8;     // 8-bit duty (0-255)

// ------------------------- Persistent state across deep sleep -------------------------
RTC_DATA_ATTR int bootCount = 0;

Preferences prefs;
WebServer server(80);
NimBLEScan* pBLEScan;

// Tracks the best (most suspicious, strongest) device seen in the current burst
struct Candidate {
  bool   found = false;
  int    score = 0;
  int    rssi  = -127;
  String mac;
  String name;
  String reasons;
};

// Smoothed RSSI for the currently locked target (exponential moving average)
float smoothedRssi = -100.0f;
bool  haveLock = false;
String lockedMac = "";

enum Mode { MODE_SCAN, MODE_SYNC };
Mode currentMode = MODE_SCAN;

unsigned long lastSuspiciousMs = 0;

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

int scoreDevice(NimBLEAdvertisedDevice* dev, String& reasonOut) {
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
// Each line: bootCount,millisAtDetection,mac,score,rssi,name,reasons
// millis resets each wake, so absolute time for CURRENT session is computed
// on the phone (see web page JS). Older sessions show relative time only,
// unless you add a DS3231 RTC.
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
  // Map rssi [RSSI_FAR..RSSI_CLOSE] -> intensity [0..255]
  float t = (rssi - RSSI_FAR) / float(RSSI_CLOSE - RSSI_FAR);
  if (t < 0) t = 0; if (t > 1) t = 1;
  int duty = int(t * 255);
  ledcWrite(MOTOR_PWM_CHANNEL, duty);

  // Parking-sensor style: beep interval shrinks as you get closer
  unsigned long interval = (unsigned long)(1200 - t * 1120); // 1200ms far -> 80ms close
  if (millis() - lastBeepMs > interval) {
    tone(BUZZER_PIN, 2500, 40);
    lastBeepMs = millis();
  }
}

void feedbackOff() {
  ledcWrite(MOTOR_PWM_CHANNEL, 0);
  noTone(BUZZER_PIN);
}

// ------------------------- BLE scan -> pick best candidate -------------------------
Candidate scanOnce() {
  Candidate best;
  NimBLEScanResults results = pBLEScan->start(SCAN_BURST_SECONDS, false);
  for (int i = 0; i < results.getCount(); i++) {
    NimBLEAdvertisedDevice dev = results.getDevice(i);
    String reasons;
    int score = scoreDevice(&dev, reasons);
    if (score >= SCORE_ALERT_THRESHOLD) {
      int rssi = dev.getRSSI();
      // Prefer higher score; tie-break on stronger signal (closer)
      if (!best.found || score > best.score ||
          (score == best.score && rssi > best.rssi)) {
        best.found   = true;
        best.score   = score;
        best.rssi    = rssi;
        best.mac     = String(dev.getAddress().toString().c_str());
        best.name    = String(dev.getName().c_str());
        best.reasons = reasons;
      }
    }
  }
  pBLEScan->clearResults();
  return best;
}

// ------------------------- Web server (sync mode) -------------------------
String htmlPage() {
  // The page fetches /data (JSON), then computes absolute timestamps for the
  // CURRENT session using the phone's clock and the device's reported uptime.
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
      // parse: boot,ms,mac,score,rssi,name,reasons  (name/reasons have no commas)
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
  // brief triple buzz to confirm we're in sync mode
  for (int i=0;i<3;i++){ tone(BUZZER_PIN,1800,80); delay(140); }
}

// ------------------------- Button handling -------------------------
// Returns: 0 none, 1 single, 2 double, 3 long
int readButtonEvent() {
  if (digitalRead(BUTTON_PIN) == HIGH) return 0; // not pressed (active LOW)
  unsigned long pressStart = millis();
  while (digitalRead(BUTTON_PIN) == LOW) {
    if (millis() - pressStart > LONG_PRESS_MS) return 3; // long press
    delay(5);
  }
  // released before long-press threshold; watch for a second press
  unsigned long releaseTime = millis();
  while (millis() - releaseTime < DOUBLE_PRESS_WINDOW_MS) {
    if (digitalRead(BUTTON_PIN) == LOW) {
      // wait for release of the second press
      while (digitalRead(BUTTON_PIN) == LOW) delay(5);
      return 2; // double
    }
    delay(5);
  }
  return 1; // single
}

void goToSleep() {
  feedbackOff();
  // wake on button press (active LOW -> wake on level 0)
  esp_sleep_enable_ext0_wakeup(BUTTON_PIN, 0);
  delay(50);
  esp_deep_sleep_start();
}

// ------------------------- Setup / loop -------------------------
void setup() {
  Serial.begin(115200);
  bootCount++;

  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(BUZZER_PIN, OUTPUT);

  ledcSetup(MOTOR_PWM_CHANNEL, MOTOR_PWM_FREQ, MOTOR_PWM_RES);
  ledcAttachPin(MOTOR_PIN, MOTOR_PWM_CHANNEL);
  ledcWrite(MOTOR_PWM_CHANNEL, 0);

  if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed");

  NimBLEDevice::init("");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  currentMode = MODE_SCAN;
  lastSuspiciousMs = millis();

  // wake-confirm buzz
  tone(BUZZER_PIN, 2200, 120);
  Serial.printf("Awake. Boot #%d. SCAN mode.\n", bootCount);
}

void loop() {
  // Handle button in both modes
  int ev = readButtonEvent();
  if (ev == 3) { goToSleep(); return; }
  if (ev == 2) {
    if (currentMode == MODE_SCAN) startSyncMode();
    // (a second double-press in sync mode just re-confirms; ignore)
    return;
  }

  if (currentMode == MODE_SYNC) {
    server.handleClient();
    return; // stay in sync mode until long-press sleeps the device
  }

  // ---- SCAN mode ----
  Candidate c = scanOnce();

  if (c.found) {
    lastSuspiciousMs = millis();
    // lock/relock onto this device and smooth its RSSI
    if (!haveLock || c.mac != lockedMac) {
      lockedMac = c.mac; haveLock = true; smoothedRssi = c.rssi;
      logDetection(c); // log first sighting of this device this session
      Serial.printf("LOCK %s score=%d rssi=%d [%s]\n",
                    c.mac.c_str(), c.score, c.rssi, c.reasons.c_str());
    } else {
      smoothedRssi = 0.6f * smoothedRssi + 0.4f * c.rssi; // EMA
    }
    feedbackForRssi(smoothedRssi);
  } else {
    // nothing suspicious this burst
    haveLock = false;
    feedbackOff();
    if (millis() - lastSuspiciousMs > IDLE_TIMEOUT_MS) {
      Serial.println("Idle timeout -> sleep");
      goToSleep();
    }
  }
}
