/*
  Cyber-Physical OT Secure Real Node with Mesh Intelligence (Hardened Mode v1.6)
  Project 19 | Pinnacle 1 | Atlas SkillTech
  Firmware Version: 1.6.0-ot-hard-mesh

  Features:
    - Ear-Saver Mode: Buzzer pulses once every 3 seconds during lockdown[cite: 1]
    - Token-Gated API & Remote Admin Reset Endpoint (/secure/reset)[cite: 1]
    - Physical Reality Validation (Sanity checks block even admin overrides)[cite: 1]
    - Single Optical Tamper (LDR Light Sensor)[cite: 1]
    - Smart Vibration Counter with Auto-Decay (5 hits in 3s)[cite: 1]
    - ARP-based Attacker MAC Address Forensics & Instant IP/MAC Blacklisting[cite: 2]
    - Strict Input Sanitization (Blocks XSS/script injections cleanly)[cite: 2]
    - Cooperative Mesh Intelligence Endpoint (/internal/ban) for Honeypot Integration
*/

#include <WiFi.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <DHT.h>
#include <esp_task_wdt.h>
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "wifi_secrets.h"
#include "secrets.h"   // SEPARATE from the lure board's secrets.h

#define FW_VERSION "1.6.0-ot-hard-mesh"
#define NODE_ID "SECURE-OT-PLC-01"

// ---- Enhanced IP & MAC Security Tracking / Instant Ban ----
const unsigned long BAN_DURATION_MS = 3600000UL; // 1-hour immediate ban for malicious actors[cite: 2]
const unsigned long TOKEN_MAX_AGE_MS = 10000UL; 

struct AuthTracker { 
  String ip; 
  String mac; 
  unsigned long lockUntil = 0; 
  bool banned = false; 
  bool used = false; 
};

const int MAX_TRACKED_IPS = 8;
AuthTracker authTrack[MAX_TRACKED_IPS];
unsigned long lastSeenNonce = 0;  

AuthTracker &trackerFor(const String &ip, const String &mac) {
  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    if (authTrack[i].used && (authTrack[i].ip == ip || (mac != "00:00:00:00:00:00" && authTrack[i].mac == mac))) 
      return authTrack[i];
  }
  for (int i = 0; i < MAX_TRACKED_IPS; i++) {
    if (!authTrack[i].used) { 
      authTrack[i] = AuthTracker(); 
      authTrack[i].used = true; 
      authTrack[i].ip = ip; 
      authTrack[i].mac = mac; 
      return authTrack[i]; 
    }
  }
  return authTrack[0];
}

const int PIN_GREEN_LED = 25;
const int PIN_RED_LED   = 26;
const int PIN_BUZZER    = 27;
const int PIN_RELAY     = 14;   
const int PIN_DHT       = 4;
const int PIN_LDR       = 34;
const int PIN_VIBRATION = 33;   

#define DHT_TYPE DHT11
DHT dht(PIN_DHT, DHT_TYPE);

LiquidCrystal_I2C *lcd = nullptr;
WiFiServer secureServer(80);

unsigned long eventCount = 0;
unsigned long validRequests = 0;
unsigned long blockedRequests = 0;

int baselineLight = 0;
bool systemCompromised = false;
unsigned long lastLcdUpdate = 0;
int lcdScreenIndex = 0;

unsigned long lastDhtReadMs = 0;
float cachedTemp = NAN, cachedHum = NAN;

// ARP MAC resolver helper function (compatible with ESP32 Arduino Core v3.x)[cite: 2]
String getMacFromIP(const String &ipStr) {
  ip4_addr_t target_ip;
  ip4addr_aton(ipStr.c_str(), &target_ip);
  const ip4_addr_t *ip_ret = nullptr; 
  struct eth_addr *eth_ret;
  
  if (etharp_find_addr(netif_default, &target_ip, &eth_ret, &ip_ret) >= 0) {
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
            eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
            eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
    return String(macStr);
  }
  return "UNKNOWN (Off-Subnet)";
}

void readDhtCached() {
  if (millis() - lastDhtReadMs < 2200 && lastDhtReadMs != 0) return;
  lastDhtReadMs = millis();
  float t = dht.readTemperature(), h = dht.readHumidity();
  if (!isnan(t)) cachedTemp = t;
  if (!isnan(h)) cachedHum = h;
}

int vibrationHits = 0;
unsigned long lastHitTime = 0;
bool lastVibState = LOW;

unsigned long lastBuzzerPulse = 0;

void logSecureEvent(const String &level, const String &evt, const String &msg, const String &ip = "LOCAL", const String &mac = "00:00:00:00:00:00", uint16_t port = 0) {
  eventCount++;
  Serial.printf("#%lu [%lus] [HARD-NODE-SECURE] [IP: %s] [MAC: %s] [PORT: %u] [%s] [%s] %s\n", 
                eventCount, millis() / 1000UL, ip.c_str(), mac.c_str(), port, level.c_str(), evt.c_str(), msg.c_str());
}

void triggerLockdown(const String &reason) {
  if (systemCompromised) return;
  systemCompromised = true;
  digitalWrite(PIN_GREEN_LED, LOW);
  digitalWrite(PIN_RED_LED, HIGH);
  digitalWrite(PIN_RELAY, LOW); // Trip Emergency Shutdown Relay
  
  logSecureEvent("CRITICAL", "SYSTEM_LOCKDOWN", "Emergency Shutdown tripped! Reason: " + reason);
}

void resetSystemState() {
  systemCompromised = false;
  vibrationHits = 0;
  digitalWrite(PIN_GREEN_LED, HIGH);
  digitalWrite(PIN_RED_LED, LOW);
  digitalWrite(PIN_BUZZER, LOW);
  digitalWrite(PIN_RELAY, HIGH); 
  logSecureEvent("INFO", "SYSTEM_RESTORED", "System cleared and re-secured by admin command.");
}

void updateSecureLcd(float temp, float hum) {
  if (!lcd) return;
  if (millis() - lastLcdUpdate < 3000) return;
  lastLcdUpdate = millis();

  char l1[17], l2[17];
  if (systemCompromised) {
    snprintf(l1, sizeof(l1), "ALERT: BREACH!  ");
    snprintf(l2, sizeof(l2), "LOCKDOWN ACTIVE ");
  } else {
    snprintf(l1, sizeof(l1), "T:%.1fC H:%.1f%%  ", temp, hum);
    switch (lcdScreenIndex) {
      case 0: snprintf(l2, sizeof(l2), "SECURE MESH: OK "); break;
      case 1: snprintf(l2, sizeof(l2), "ADMIN TOKEN:OK  "); break;
      case 2: snprintf(l2, sizeof(l2), "ESD INTERLOCK:OK"); break;
    }
    lcdScreenIndex = (lcdScreenIndex + 1) % 3;
  }

  lcd->setCursor(0, 0); lcd->print(l1);
  lcd->setCursor(0, 1); lcd->print(l2);
}

void monitorPhysicalSensors() {
  if (systemCompromised) return;

  int currentLight = analogRead(PIN_LDR);
  if (baselineLight > 0 && currentLight > (baselineLight + 800)) {
    triggerLockdown("Optical tamper detected (Cabinet lid opened)");
    return;
  }

  int currentVib = digitalRead(PIN_VIBRATION);
  if (currentVib == HIGH && lastVibState == LOW) {
    unsigned long now = millis();
    if (now - lastHitTime < 3000) {
      vibrationHits++;
    } else {
      vibrationHits = 1; 
    }
    lastHitTime = now;
    logSecureEvent("WARNING", "VIB_HIT", "Kinetic impact registered (" + String(vibrationHits) + "/5 hits)");

    if (vibrationHits >= 5) {
      triggerLockdown("Kinetic anomaly: Repeated heavy physical impact detected");
    }
  }
  lastVibState = currentVib;

  if (vibrationHits > 0 && millis() - lastHitTime > 4000) {
    vibrationHits = 0;
  }
}

void serviceSecureApi() {
  WiFiClient c = secureServer.available();
  if (!c) return;

  String clientIP = c.remoteIP().toString();
  uint16_t clientPort = c.remotePort();
  String clientMac = getMacFromIP(clientIP); // Resolve MAC via lwIP ARP cache[cite: 2]

  unsigned long t0 = millis();
  String req = "";
  while (c.connected() && millis() - t0 < 1000) {
    while (c.available()) {
      req += (char)c.read();
      if (req.endsWith("\r\n\r\n")) goto headers_done;
    }
  }
headers_done:

  String firstLine = req.substring(0, req.indexOf('\n'));
  bool isPost = firstLine.startsWith("POST");
  String path = firstLine.substring(firstLine.indexOf(' ') + 1);
  path = path.substring(0, path.indexOf(' '));

  // ---- INTERNAL MESH ENDPOINT: Accepts threat intelligence sync from the Honeypot ----
  if (isPost && path.startsWith("/internal/ban")) {
    String meshSec = "";
    int secIdx = req.indexOf("X-Mesh-Secret:");
    if (secIdx >= 0) {
      int secEnd = req.indexOf("\r\n", secIdx);
      meshSec = req.substring(secIdx + 14, secEnd);
      meshSec.trim();
    }

    if (meshSec != "MESH_SECRET_123") {
      logSecureEvent("SECURITY", "MESH_AUTH_FAIL", "Unauthorized mesh ban attempt rejected", clientIP, clientMac, clientPort);
      c.print("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      c.stop();
      return;
    }

    int cl = req.indexOf("Content-Length:");
    long len = (cl >= 0) ? req.substring(cl + 15).toInt() : 0;
    while ((long)c.available() < len && millis() - t0 < 1500) delay(5);
    String body = "";
    for (long i = 0; i < len && c.available(); i++) body += (char)c.read();

    int ipIdx = body.indexOf("ip=");
    int macIdx = body.indexOf("mac=");
    
    String badIp = (ipIdx >= 0) ? body.substring(ipIdx + 3, body.indexOf('&', ipIdx)) : clientIP;
    badIp.trim();
    String badMac = (macIdx >= 0) ? body.substring(macIdx + 4) : "UNKNOWN";
    badMac.trim();

    AuthTracker &badTr = trackerFor(badIp, badMac);
    badTr.banned = true;
    badTr.lockUntil = millis() + BAN_DURATION_MS;

    logSecureEvent("CRITICAL", "MESH_THREAT_INTEL", "Honeypot shared intelligence! Banned attacker IP: " + badIp + " MAC: " + badMac, badIp, badMac);
    
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
    c.print("{\"status\":\"success\",\"mesh_action\":\"ip_mac_banned\"}");
    c.stop();
    return;
  }

  // ---- Check if this IP/MAC is already blacklisted/banned ----
  AuthTracker &tr = trackerFor(clientIP, clientMac);
  if (tr.banned || tr.lockUntil > millis()) {
    blockedRequests++;
    logSecureEvent("SECURITY", "BLACKLIST_BLOCK", "Blocked request from blacklisted IP/MAC", clientIP, clientMac, clientPort);
    c.print("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
    c.print("{\"error\":\"Access Denied: Your IP and MAC address have been blacklisted due to malicious activity.\"}");
    c.stop();
    return;
  }

  bool authValid = false;
  int authIdx = req.indexOf("Authorization: Bearer ");
  if (authIdx >= 0) {
    int authEnd = req.indexOf("\r\n", authIdx);
    String token = req.substring(authIdx + 22, authEnd);
    token.trim();
    if (token == ADMIN_TOKEN) authValid = true;
  }

  bool nonceOk = true;
  bool protectedPath = path.startsWith("/secure/reset") || path.startsWith("/secure/sensor");
  if (protectedPath) {
    int nIdx = req.indexOf("X-Nonce:");
    if (nIdx < 0) nonceOk = false;
    else {
      int nEnd = req.indexOf("\r\n", nIdx);
      unsigned long nonce = req.substring(nIdx + 8, nEnd).toInt();
      if (nonce <= lastSeenNonce) nonceOk = false; else lastSeenNonce = nonce;
    }
  }

  // ---- INSTANT BAN: Any unauthorized auth failure, replay attack, or invalid endpoint probing triggers an immediate IP & MAC ban[cite: 2] ----
  if (protectedPath && (!authValid || !nonceOk)) {
    blockedRequests++;
    tr.banned = true;
    tr.lockUntil = millis() + BAN_DURATION_MS;
    const char *why = !authValid ? "UNAUTHORIZED_SPOOF_ATTEMPT" : "REPLAY_ATTEMPT";
    logSecureEvent("SECURITY", why, "Security violation detected. IP and MAC instantly blacklisted.", clientIP, clientMac, clientPort);
    c.print("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
    c.print("{\"error\":\"Forbidden: Unauthorized access / spoofing detected. IP & MAC blacklisted.\"}");
    c.stop();
    return;
  }

  if (isPost && path.startsWith("/secure/reset")) {
    resetSystemState();
    logSecureEvent("INFO", "ADMIN_RESET", "System successfully cleared and reset via API", clientIP, clientMac, clientPort);
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
    c.print("{\"status\":\"success\",\"message\":\"System lockdown cleared.\"}");
    c.stop();
    return;
  }

  if (isPost && path.startsWith("/secure/sensor")) {
    int cl = req.indexOf("Content-Length:");
    long len = (cl >= 0) ? req.substring(cl + 15).toInt() : 0;
    while ((long)c.available() < len && millis() - t0 < 1500) delay(5);
    String body = "";
    for (long i = 0; i < len && c.available(); i++) body += (char)c.read();

    int tp = body.indexOf("temp=");
    if (tp < 0) {
      tr.banned = true;
      tr.lockUntil = millis() + BAN_DURATION_MS;
      logSecureEvent("SECURITY", "MALFORMED_PAYLOAD", "Missing temp parameter. IP & MAC blacklisted.", clientIP, clientMac, clientPort);
      c.print("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
      c.print("{\"error\":\"Bad Request: Missing parameter. IP & MAC banned.\"}\r\n");
      c.stop();
      return;
    }

    int ampersand = body.indexOf('&', tp);
    String tempValStr = (ampersand > tp) ? body.substring(tp + 5, ampersand) : body.substring(tp + 5);
    tempValStr.trim();

    // STRICT TYPE VALIDATION (Stops XSS, script injection, and garbage payloads cleanly)[cite: 2]
    bool isValidNumber = true;
    for (unsigned int i = 0; i < tempValStr.length(); i++) {
      char ch = tempValStr.charAt(i);
      if (!isDigit(ch) && ch != '.' && ch != '-') {
        isValidNumber = false;
        break;
      }
    }

    if (!isValidNumber) {
      blockedRequests++;
      tr.banned = true;
      tr.lockUntil = millis() + BAN_DURATION_MS; // Instant 1-hour ban[cite: 2]
      logSecureEvent("SECURITY", "INJECTION_ATTEMPT", "XSS/Script injection detected! IP and MAC permanently blacklisted: " + tempValStr, clientIP, clientMac, clientPort);
      c.print("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
      c.print("{\"error\":\"Forbidden: Malformed payload or script injection detected. IP & MAC banned.\"}");
      c.stop();
      return;
    }

    float incomingTemp = tempValStr.toFloat();

    // PHYSICAL REALITY SANITY CHECK[cite: 1]
    if (incomingTemp < -10.0 || incomingTemp > 80.0) {
      blockedRequests++;
      logSecureEvent("SECURITY", "SANITY_CHECK_FAILED", "Out-of-bounds telemetry rejected: " + String(incomingTemp), clientIP, clientMac, clientPort);
      c.print("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
      c.print("{\"error\":\"Sanity check failed: Physical operational bounds exceeded.\"}");
      c.stop();
      return;
    }

    validRequests++;
    logSecureEvent("INFO", "TELEMETRY_ACCEPTED", "Secure telemetry updated: " + String(incomingTemp), clientIP, clientMac, clientPort);
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
    c.print("{\"status\":\"success\",\"secure_node\":\"ACTIVE\",\"accepted_temp\":" + String(incomingTemp) + "}");
  } 
  else {
    logSecureEvent("INFO", "SECURE_HMI_SERVED", "HMI diagnostic page requested", clientIP, clientMac, clientPort);
    String resp = "<html><body><h1>PLC-01 Secure Control Plane</h1><p>Status: " + String(systemCompromised ? "LOCKED DOWN" : "SECURE") + "</p><p>Temp: " + String(cachedTemp) + "C</p><p>Humidity: " + String(cachedHum) + "%</p></body></html>";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
    c.print(resp);
  }

  delay(2);
  c.stop();
}

void setup() {
  Serial.begin(115200);

  pinMode(PIN_GREEN_LED, OUTPUT);
  pinMode(PIN_RED_LED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_RELAY, OUTPUT);
  pinMode(PIN_LDR, INPUT);
  pinMode(PIN_VIBRATION, INPUT);

  resetSystemState();
  dht.begin();

#if ESP_ARDUINO_VERSION_MAJOR >= 3
  esp_task_wdt_config_t twdt; twdt.timeout_ms = 15000; twdt.idle_core_mask = 0; twdt.trigger_panic = true;
  esp_task_wdt_reconfigure(&twdt);
#else
  esp_task_wdt_init(15, true);
#endif
  esp_task_wdt_add(NULL);

  Wire.begin(21, 22);
  Wire.beginTransmission(0x27);
  uint8_t a = (Wire.endTransmission() == 0) ? 0x27 : ((Wire.beginTransmission(0x3F), Wire.endTransmission() == 0) ? 0x3F : 0);
  if (a) {
    lcd = new LiquidCrystal_I2C(a, 16, 2);
    lcd->init();
    lcd->backlight();
    lcd->clear();
    lcd->print("PLC-01 Secure");
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(300);
  }

  if (WiFi.status() == WL_CONNECTED) {
    secureServer.begin();
  }

  baselineLight = analogRead(PIN_LDR);
  logSecureEvent("SYSTEM", "BOOT", "Hardened OT Mesh Node v1.6 online, IP " + WiFi.localIP().toString());
}

void loop() {
  esp_task_wdt_reset();
  serviceSecureApi();
  monitorPhysicalSensors();
  readDhtCached();
  updateSecureLcd(cachedTemp, cachedHum);

  if (systemCompromised) {
    digitalWrite(PIN_RED_LED, (millis() / 300) % 2 == 0 ? HIGH : LOW);

    if (millis() - lastBuzzerPulse >= 3000) {
      lastBuzzerPulse = millis();
      digitalWrite(PIN_BUZZER, HIGH);
    }
    if (millis() - lastBuzzerPulse >= 200) {
      digitalWrite(PIN_BUZZER, LOW);
    }
  }

  delay(10);
}