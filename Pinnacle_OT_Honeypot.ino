/*
  Cyber-Physical OT Honeypot / Deception Node with Mesh Intelligence (v4.1.0)
  Project 19 | Pinnacle 1 | Atlas SkillTech
  Firmware Version: 4.1.0-honeypot-mesh

  ROLE IN THE STORY: Board #1, the lure. It behaves WEAK/decoy: wide open ports,
  a crackable admin password, and accepts any spoofed sensor value while quietly
  logging and broadcasting attacker threat intelligence to the Hardened Node.
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <esp_task_wdt.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>
#include "wifi_secrets.h"
#include "secrets.h"

struct Session;

#define FW_VERSION "4.1.0-honeypot-mesh"
#define NODE_ID "HONEYPOT-19A"

const int PIN_YELLOW = 25;      // steady on = node alive; blink = an attacker is currently connected
const int PIN_BUZZER = 27;      // short beep on a captured admin login or a tamper event
const int PIN_LDR = 34;

#define BUZZER_ACTIVE_HIGH 1

LiquidCrystal_I2C *lcd = nullptr;

WiFiServer cmdServer(23);
WiFiServer httpServer(80);
WiFiServer modbusServer(502);
WiFiServer mqttServer(1883);

enum UserRole { ROLE_GUEST = 0, ROLE_ADMIN = 1 };
enum TelnetState { STATE_PROMPT_USER, STATE_PROMPT_PASS, STATE_COMMAND_MODE };

unsigned long eventCount = 0, totalRequests = 0, acceptedRequests = 0, rejectedRequests = 0;
unsigned long loginAttempts = 0, loginSuccesses = 0;
int baselineLight = 0;
bool lidOpen = false;
unsigned long lastLcdUpdate = 0;
int lcdScreenIndex = 0;
String lastAttackerIP = "none yet";

const unsigned long THROTTLE_AFTER = 4;       
const unsigned long THROTTLE_WINDOW_MS = 60000; 
const unsigned long THROTTLE_DELAY_MS = 350;    

struct AttackerProfile {
  String ip; unsigned long firstSeenMs = 0; unsigned long connections = 0;
  unsigned long commands = 0; unsigned long failedLogins = 0; unsigned long successfulLogins = 0;
  bool used = false;
};
const int MAX_PROFILES = 10;
AttackerProfile profiles[MAX_PROFILES];

AttackerProfile &profileFor(const String &ip) {
  for (int i = 0; i < MAX_PROFILES; i++) if (profiles[i].used && profiles[i].ip == ip) return profiles[i];
  for (int i = 0; i < MAX_PROFILES; i++) if (!profiles[i].used) { profiles[i] = AttackerProfile(); profiles[i].used = true; profiles[i].ip = ip; profiles[i].firstSeenMs = millis(); return profiles[i]; }
  return profiles[0]; 
}

struct Session {
  WiFiClient client;
  String remoteIP;
  uint16_t remotePort = 0;
  UserRole role = ROLE_GUEST;
  TelnetState telnetState = STATE_PROMPT_USER;
  String currentUsername = "";
  unsigned long recentFails[8] = {0};  byte failRing = 0;   
  char buf[128]; byte idx = 0;
  bool active = false;
};
const int MAX_SESSIONS = 4;
Session sessions[MAX_SESSIONS];

void buzzer(bool on) { digitalWrite(PIN_BUZZER, (on == (BUZZER_ACTIVE_HIGH != 0)) ? HIGH : LOW); }
void beep(int ms) { buzzer(true); delay(ms); buzzer(false); }

String getMacAddress(const String &ipStr) {
  IPAddress ip;
  if (!ip.fromString(ipStr)) return "UNKNOWN_MAC";
  ip4_addr_t ip_addr; ip_addr.addr = (uint32_t)ip;
  struct eth_addr *eth_ret = NULL; const ip4_addr_t *ip_ret = NULL;
  if (etharp_find_addr(netif_default, &ip_addr, &eth_ret, &ip_ret) >= 0) {
    char macBuf[18];
    snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
             eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2], eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
    return String(macBuf);
  }
  return "UNKNOWN_MAC";
}

// ---- MESH THREAT INTELLIGENCE SHARING FUNCTION ----
void reportAttackerToHardNode(const String &ip) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin("http://172.20.10.7/internal/ban");
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    http.addHeader("X-Mesh-Secret", "MESH_SECRET_123");
    String mac = getMacAddress(ip);
    String payload = "ip=" + ip + "&mac=" + mac;
    int code = http.POST(payload);
    if (code > 0) {
      Serial.printf("[MESH] Threat intelligence shared with Hard Node -> IP: %s | MAC: %s | HTTP Code: %d\n", ip.c_str(), mac.c_str(), code);
    } else {
      Serial.printf("[MESH] Error sharing threat intel with Hard Node: %s\n", http.errorToString(code).c_str());
    }
    http.end();
  }
}

void updateLcd(bool attackerActive) {
  if (!lcd) return;
  if (millis() - lastLcdUpdate < 3000) return;
  lastLcdUpdate = millis();
  char l1[17], l2[17];
  snprintf(l1, sizeof(l1), "%-16.16s", (String("IP ") + WiFi.localIP().toString()).c_str());
  switch (lcdScreenIndex) {
    case 0: snprintf(l2, sizeof(l2), "%-16.16s", "GATEWAY NORMAL"); break;
    case 1: snprintf(l2, sizeof(l2), "%-16.16s", "TEMP: 42.5 C"); break;
    case 2: snprintf(l2, sizeof(l2), "%-16.16s", "TANK: 45.2 PSI"); break;
    case 3: snprintf(l2, sizeof(l2), "%-16.16s", (String("LAST ATK ") + lastAttackerIP).c_str()); break;
  }
  lcdScreenIndex = (lcdScreenIndex + 1) % 4;
  lcd->setCursor(0, 0); lcd->print(l1);
  lcd->setCursor(0, 1); lcd->print(l2);
  digitalWrite(PIN_YELLOW, attackerActive ? ((millis() / 400) % 2 == 0) : HIGH);
}

void logEvent(const char *svc, const char *result, const char *evt, const String &msg,
              const String &ip = "LOCAL", uint16_t port = 0, const String &meta = "") {
  eventCount++;
  String mac = (ip == "LOCAL") ? "LOCAL" : getMacAddress(ip);
  Serial.printf("#%-5lu t=%-8lu svc=%-8s result=%-9s event=%-20s ip=%-15s port=%-5u mac=%-17s msg=\"%s\"",
                eventCount, millis() / 1000UL, svc, result, evt, ip.c_str(), port, mac.c_str(), msg.c_str());
  if (meta.length() > 0) Serial.printf(" meta=\"%s\"", meta.c_str());
  Serial.println();
}

String handleConsoleInput(const String &lineIn, Session *sess, bool overSerial) {
  String line = lineIn; line.trim();
  String clientIP = overSerial ? "LOCAL" : sess->remoteIP;
  uint16_t clientPort = overSerial ? 0 : sess->remotePort;
  String out = "";

  if (!overSerial && sess->telnetState == STATE_PROMPT_USER) {
    sess->currentUsername = line.length() ? line : "(blank)";
    sess->telnetState = STATE_PROMPT_PASS;
    logEvent("CONSOLE", "INFO", "USERNAME_SUBMITTED", "Attacker submitted a username", clientIP, clientPort, "user=" + sess->currentUsername);
    return "Password: ";
  }

  if (!overSerial && sess->telnetState == STATE_PROMPT_PASS) {
    String pass = line;
    AttackerProfile &prof = profileFor(clientIP);
    bool isAdmin = (pass == ADMIN_PASS);
    loginAttempts++; prof.failedLogins += isAdmin ? 0 : 1;

    unsigned long now = millis(), recentFails = 0;
    for (byte i = 0; i < 8; i++) if (sess->recentFails[i] && now - sess->recentFails[i] < THROTTLE_WINDOW_MS) recentFails++;
    if (!isAdmin && recentFails >= THROTTLE_AFTER) delay(THROTTLE_DELAY_MS);

    if (isAdmin) {
      sess->role = ROLE_ADMIN; sess->telnetState = STATE_COMMAND_MODE;
      loginSuccesses++; prof.successfulLogins++;
      lastAttackerIP = clientIP;
      beep(120);
      logEvent("AUTH", "CRITICAL", "ADMIN_LOGIN_SUCCESS", "Admin credential guessed", clientIP, clientPort,
                "user=" + sess->currentUsername + " pass=" + pass + " attempt_no=" + String(loginAttempts));
      return "Login successful.\nIndustrial Gateway Console v2.4\nADMIN> ";
    } else {
      sess->recentFails[sess->failRing % 8] = now; sess->failRing++;
      logEvent("AUTH", "DENIED", "BAD_CREDENTIAL", "Password rejected", clientIP, clientPort, "pass=" + pass);
      
      // TRIGGER MESH INTEL BROADCAST ON FAILED AUTH
      reportAttackerToHardNode(clientIP);

      sess->telnetState = STATE_PROMPT_USER;
      return "Login incorrect\nlogin: ";
    }
  }

  totalRequests++;
  if (!overSerial) profileFor(clientIP).commands++;
  String word = line; int sp = line.indexOf(' ');
  if (sp >= 0) word = line.substring(0, sp);
  word.toUpperCase();
  if (!overSerial) logEvent("CONSOLE", "CAPTURED", "COMMAND", "Command received", clientIP, clientPort, "cmd=\"" + line + "\"");

  if (word == "SCAN" || word == "STATUS") {
    acceptedRequests++; out = "GATEWAY STATUS: NORMAL. All field devices reporting.\n";
  } else if (word == "STATS" || word == "INFO") {
    acceptedRequests++;
    out = "requests=" + String(totalRequests) + " events=" + String(eventCount) +
          " login_attempts=" + String(loginAttempts) + " login_successes=" + String(loginSuccesses) + "\n";
  } else if (word == "THREATS" && !overSerial && sess->role == ROLE_ADMIN) {
    acceptedRequests++;
    out = "Known attacker IPs this session:\n";
    for (int i = 0; i < MAX_PROFILES; i++) if (profiles[i].used)
      out += "  " + profiles[i].ip + "  conns=" + String(profiles[i].connections) + " cmds=" + String(profiles[i].commands) +
             " fails=" + String(profiles[i].failedLogins) + " admin_logins=" + String(profiles[i].successfulLogins) + "\n";
  } else if (word == "HELP" || word == "?") {
    acceptedRequests++; out = "Commands: SCAN, STATUS, STATS, THREATS (admin), HELP, EXIT\n";
  } else if (word == "EXIT" && !overSerial) {
    sess->client.stop(); return "";
  } else {
    rejectedRequests++; out = "ERR: unrecognized instruction: " + line + "\n";
    if (!overSerial) reportAttackerToHardNode(clientIP); // Malicious/invalid command triggers mesh warning
  }
  if (!overSerial) out += (sess->role == ROLE_ADMIN) ? "ADMIN> " : "GW> ";
  return out;
}

void serviceCommandPort() {
  WiFiClient incoming = cmdServer.available();
  if (incoming) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
      if (!sessions[i].active) {
        sessions[i] = Session();
        sessions[i].client = incoming;
        sessions[i].remoteIP = incoming.remoteIP().toString();
        sessions[i].remotePort = incoming.remotePort();
        sessions[i].active = true;
        sessions[i].telnetState = STATE_PROMPT_USER;
        profileFor(sessions[i].remoteIP).connections++;
        logEvent("CONSOLE", "INFO", "CONNECT", "New connection", sessions[i].remoteIP, sessions[i].remotePort);
        sessions[i].client.print("Industrial Gateway Console\nlogin: ");
        break;
      }
    }
  }
  for (int i = 0; i < MAX_SESSIONS; i++) {
    Session &s = sessions[i];
    if (!s.active) continue;
    if (!s.client.connected()) {
      logEvent("CONSOLE", "INFO", "DISCONNECT", "Client disconnected", s.remoteIP, s.remotePort);
      s.active = false; s.client.stop(); continue;
    }
    while (s.client.available()) {
      char c = s.client.read();
      if (c == '\n' || c == '\r') {
        if (s.idx > 0) {
          s.buf[s.idx] = '\0'; s.idx = 0;
          String line(s.buf); line.trim();
          if (line.length() > 0) { String resp = handleConsoleInput(line, &s, false); if (resp.length() > 0) s.client.print(resp); }
        }
      } else if (s.idx < sizeof(s.buf) - 1) s.buf[s.idx++] = c;
    }
  }
}

String htmlEscape(const String &in) {
  String out; out.reserve(in.length() + 16);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    if (c == '<') out += "&lt;"; else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;"; else if (c == '&') out += "&amp;"; else out += c;
  }
  return out;
}

void serviceHttpPort() {
  WiFiClient c = httpServer.available();
  if (!c) return;
  String clientIP = c.remoteIP().toString(); uint16_t clientPort = c.remotePort();
  profileFor(clientIP).connections++;
  logEvent("HTTP", "INFO", "HTTP_CONNECT", "Port 80 connection opened", clientIP, clientPort);

  unsigned long t0 = millis(); String req = ""; String userAgent = "unknown";
  while (c.connected() && millis() - t0 < 1000) { while (c.available()) { req += (char)c.read(); if (req.endsWith("\r\n\r\n")) goto headers_parsed; } }
headers_parsed:
  int uaIdx = req.indexOf("User-Agent:");
  if (uaIdx >= 0) { int uaEnd = req.indexOf("\r\n", uaIdx); if (uaEnd > uaIdx) { userAgent = req.substring(uaIdx + 11, uaEnd); userAgent.trim(); } }
  String firstLine = req.substring(0, req.indexOf('\n'));
  bool isPost = firstLine.startsWith("POST");
  String path = firstLine.substring(firstLine.indexOf(' ') + 1); path = path.substring(0, path.indexOf(' '));

  if (isPost && path.startsWith("/sensor")) {
    int cl = req.indexOf("Content-Length:"); long len = (cl >= 0) ? req.substring(cl + 15).toInt() : 0;
    while ((long)c.available() < len && millis() - t0 < 1500) delay(5);
    String body = ""; for (long i = 0; i < len && c.available(); i++) body += (char)c.read();
    int tp = body.indexOf("temp="); String val = (tp >= 0) ? body.substring(tp + 5) : "";
    int amp = val.indexOf('&'); if (amp >= 0) val = val.substring(0, amp);
    acceptedRequests++; profileFor(clientIP).commands++;
    logEvent("HTTP", "DECEPTION", "SPOOF_ACCEPTED", "Telemetry value accepted with no validation (decoy behaviour)", clientIP, clientPort, "spoofed_temp=" + val);
    
    // TRIGGER MESH INTEL ON SPOOF ATTEMPT
    reportAttackerToHardNode(clientIP);

    String resp = "{\"status\":\"success\",\"message\":\"telemetry updated\",\"recorded_temp\":" + val + "}";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"); c.print(resp);
  } else {
    int qp = path.indexOf('?'); String query = qp >= 0 ? path.substring(qp + 1) : "";
    String name = "guest"; int np = query.indexOf("name=");
    if (np >= 0) { String v = query.substring(np + 5); int amp = v.indexOf('&'); if (amp >= 0) v = v.substring(0, amp); name = v; }
    bool reflectedRaw = (htmlEscape(name) != name);
    if (reflectedRaw) { 
      profileFor(clientIP).commands++; 
      logEvent("HTTP", "VULNERABLE", "XSS_REFLECTED", "Unsanitized input reflected into the page (decoy behaviour)", clientIP, clientPort, "name=" + name); 
      
      // TRIGGER MESH INTEL ON XSS INJECTION ATTEMPT
      reportAttackerToHardNode(clientIP);
    }
    else logEvent("HTTP", "ALLOWED", "HMI_PAGE_SERVED", "HMI status page served", clientIP, clientPort, "user_agent=" + userAgent);
    String html = "<html><body><h1>Industrial Gateway HMI</h1><p>Status: NORMAL</p><p>Hello, " + name + "</p></body></html>";
    c.print("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"); c.print(html);
  }
  delay(2); c.stop();
}

void serviceDecoyPort(WiFiServer &srv, const char *serviceName, const char *banner) {
  WiFiClient c = srv.available();
  if (!c) return;
  String ip = c.remoteIP().toString();
  profileFor(ip).connections++;
  logEvent("DISCOVERY", "INFO", "PORT_SCAN_HIT", String(serviceName) + " port probed", ip, c.remotePort(), "banner_sent=\"" + String(banner) + "\"");
  c.print(banner);
  
  // TRIGGER MESH INTEL ON RECON/SCAN HIT
  reportAttackerToHardNode(ip);

  delay(2); c.stop();
}

void checkLdrTamper() {
  int currentLight = analogRead(PIN_LDR);
  if (!lidOpen && baselineLight > 0 && currentLight > (baselineLight + 800)) {
    lidOpen = true; beep(150);
    logEvent("PHYSICAL", "WARNING", "TAMPER_LID_OPEN", "Enclosure opened: light level rose above baseline");
  } else if (lidOpen && currentLight <= (baselineLight + 400)) {
    lidOpen = false;
    logEvent("PHYSICAL", "INFO", "TAMPER_LID_CLOSED", "Enclosure closed: light level back to baseline");
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_YELLOW, OUTPUT); pinMode(PIN_BUZZER, OUTPUT); pinMode(PIN_LDR, INPUT);
  digitalWrite(PIN_YELLOW, HIGH); buzzer(false);

  Wire.begin(21, 22);
  Wire.beginTransmission(0x27);
  uint8_t a = (Wire.endTransmission() == 0) ? 0x27 : ((Wire.beginTransmission(0x3F), Wire.endTransmission() == 0) ? 0x3F : 0);
  if (a) { lcd = new LiquidCrystal_I2C(a, 16, 2); lcd->init(); lcd->backlight(); lcd->clear(); lcd->print("Gateway booting"); }

#if ESP_ARDUINO_VERSION_MAJOR >= 3
  esp_task_wdt_config_t twdt; twdt.timeout_ms = 15000; twdt.idle_core_mask = 0; twdt.trigger_panic = true;
  esp_task_wdt_reconfigure(&twdt);
#else
  esp_task_wdt_init(15, true);
#endif
  esp_task_wdt_add(NULL);

  Serial.println("================================================================");
  Serial.printf("  %s  (firmware %s)\n", NODE_ID, FW_VERSION);
  Serial.println("  Role: WEAK/decoy lure node with Cooperative Mesh Intelligence.");
  Serial.println("================================================================");
  Serial.print("[BOOT] Joining WiFi");
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(300); Serial.print("."); esp_task_wdt_reset(); }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    cmdServer.begin(); httpServer.begin(); modbusServer.begin(); mqttServer.begin();
    Serial.printf("[BOOT] WiFi connected. IP address: %s\n", WiFi.localIP().toString().c_str());
    Serial.println("[BOOT] Listening on: 23 (console), 80 (HMI web), 502 (Modbus), 1883 (MQTT)");
  } else {
    Serial.println("[BOOT] WiFi FAILED to connect. Check wifi_secrets.h.");
  }

  baselineLight = analogRead(PIN_LDR);
  Serial.println("[BOOT] Self-test complete. Mesh intelligence enabled.");
  logEvent("SYSTEM", "INFO", "BOOT_COMPLETE", "Honeypot node online with Mesh", "LOCAL", 0, "ip=" + WiFi.localIP().toString());
}

char serialBuf[96]; byte serialIdx = 0;

void loop() {
  esp_task_wdt_reset();
  serviceCommandPort();
  serviceHttpPort();
  serviceDecoyPort(modbusServer, "MODBUS", "Modbus TCP Gateway v1.2 - Unit ready\n");
  serviceDecoyPort(mqttServer, "MQTT", "MQTT Broker v3.1.1 - industrial/telemetry\n");
  checkLdrTamper();

  bool attackerActive = false;
  for (int i = 0; i < MAX_SESSIONS; i++) if (sessions[i].active) attackerActive = true;
  updateLcd(attackerActive);

  if (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (serialIdx > 0) {
        serialBuf[serialIdx] = '\0'; serialIdx = 0;
        String line(serialBuf); line.trim();
        if (line.length() > 0) { Session dummySess; Serial.print(handleConsoleInput(line, &dummySess, true)); }
      }
    } else if (serialIdx < sizeof(serialBuf) - 1) serialBuf[serialIdx++] = c;
  }
  delay(2);
}