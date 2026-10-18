// ============================================================================
//  HoneypotSIEM  -  Honeypot multi-port + dashboard SIEM pour M5Stack StopWatch
//  ESP32-S3 / AMOLED rond 466x466. Portage du NanoC6/AtomS3 Honeypot-SIEM de
//  7h30th3r0n3 : 14 ports avec banners realistes (FTP/SSH/Telnet/SMTP/DNS/POP3/
//  IMAP/HTTPS/SMB/MySQL/RDP/VNC/HTTP-Alt/Ollama), log IP+port+payload, et un
//  dashboard SIEM circulaire TOUJOURS ALLUME (anneau radial 60min, donut ports,
//  compteur de menaces, flux live, alerte intrusion).
//
//  Par defaut : point d'acces WiFi autonome (AP). Renseigner STA_SSID pour
//  rejoindre un reseau a la place (ports exposes sur le LAN + heure NTP).
//  100% leurre passif cote applicatif (aucune emission offensive).
// ============================================================================

#include <WiFi.h>
#include <WiFiClient.h>
#include <M5Unified.h>
#include <esp_wifi.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include "siem_types.h"

static const float DEG2RAD = 0.017453292f;

// ───────────────────────── config reseau ──────────────────────────────
#define AP_SSID   "StopWatch-SIEM"
#define AP_PASS   "honeypot123"       // >=8 car. ; "" pour AP ouvert
#define STA_SSID  ""                  // defaut si pas de config web (rejoint ce LAN en plus de l'AP)
#define STA_PASS  ""

// config modifiable via la page web /setup (persistee sur FFat /config.json)
String g_cfgSsid, g_cfgPass, g_cfgWebhook;
bool   g_portEnabled[14];             // ports honeypot actives (defaut: tous)

// ───────────────────────── ports / banners ────────────────────────────
static const uint16_t PORT_LIST[PORT_COUNT] = {21,22,23,25,53,110,143,443,445,3306,3389,5900,8080,11434};
static const char* PORT_NAMES[PORT_COUNT]   = {"FTP","SSH","Telnet","SMTP","DNS","POP3","IMAP","HTTPS","SMB","MySQL","RDP","VNC","HTTP","Ollama"};
int portIndex(uint16_t port){ for(int i=0;i<PORT_COUNT;i++) if(PORT_LIST[i]==port) return i; return -1; }

WiFiServer ftpServer(21),sshServer(22),telnetServer(23),smtpServer(25),dnsServer(53),
           pop3Server(110),imapServer(143),httpsServer(443),smbServer(445),mysqlServer(3306),
           rdpServer(3389),vncServer(5900),ahttpServer(8080),ollamaServer(11434);

// ───────────────────────── etat SIEM (RAM) ────────────────────────────
uint32_t  g_total = 0;
uint32_t  portCounts[PORT_COUNT] = {};
TopIPEntry topIPs[MAX_TOP_IPS] = {};
uint8_t   g_topCount = 0;
uint16_t  g_min[MIN_BUCKETS] = {};     // events/minute glissant
uint8_t   g_minCursor = 0;
uint32_t  g_lastMin = 0;
EventRecord* g_feed = nullptr;         // ring des evenements en PSRAM (alloue au boot)
uint32_t  g_feedCap = 0;               // capacite effective (EVENT_CAP si PSRAM ok)
uint32_t  g_feedCount = 0, g_feedHead = 0;
bool      g_feedPsram = false;
EventRecord g_lastEvent; bool g_hasLast = false;
uint32_t  g_attackFlashUntil = 0;
uint8_t   g_apClients = 0;
bool      g_isAP = true;
char      g_ipStr[20] = "0.0.0.0";
char      g_netName[33] = AP_SSID;
uint32_t  g_bootMs = 0;

uint16_t  weeklyBuckets[WK_DAYS][WK_HOURS] = {};  // heatmap 7j x 24h
uint8_t   g_today = 0, g_curHour = 0;   // position courante dans la heatmap
bool      g_timeReal = false;           // true si heure NTP/RTC valide (sinon relatif au boot)

// stockage flash (partition FAT 9.9Mo) : journal persistant + stats
bool      g_fsOk = false;               // FFat monte
bool      g_statsDirty = false;         // stats a resauvegarder
uint32_t  g_flashEvents = 0;            // nb d'events dans l'anneau flash
uint32_t  g_fsTotalKB = 0, g_fsUsedKB = 0;

// vue / input
SView g_view = SV_SPLASH;
int   g_sel = 0;
uint32_t g_splashUntil = 0;
int   g_detailIdx = -1;                 // event affiche dans SV_DETAIL
int   g_filterPort = -1;                // filtre du journal : -1 = tous, sinon index PORT_LIST

// actions normalisees (boutons d'abord, tactile en bonus)
bool g_actViewNext=false, g_actViewPrev=false;   // BtnA click / hold   (swipe G/D)
bool g_actDown=false, g_actUp=false;             // BtnB click / PWR click (swipe bas/haut)
bool g_actSelect=false;                          // BtnB hold  (tap)
bool g_actFilter=false;                          // BtnB double-click
bool g_actBack=false;                            // PWR hold
int  g_tapX=-1, g_tapY=-1;
uint32_t g_clearArmUntil = 0;                    // confirmation du CLEAR STATS
int  g_feedWinTop = 0;                           // haut de fenetre du journal (pour le tap)

// ───────────────────────── helpers ip/temps ───────────────────────────
uint32_t ipToUint32(IPAddress a){ return ((uint32_t)a[0]<<24)|((uint32_t)a[1]<<16)|((uint32_t)a[2]<<8)|a[3]; }
void uint32ToIP(uint32_t v, char* out){ snprintf(out,16,"%u.%u.%u.%u",(v>>24)&255,(v>>16)&255,(v>>8)&255,v&255); }

// ───────────────────────── stats ──────────────────────────────────────
void siemTickBuckets() {
    uint32_t m = millis() / 60000;
    if (g_lastMin == 0) { g_lastMin = m; return; }
    if (m != g_lastMin) {
        uint32_t steps = m - g_lastMin; if (steps > MIN_BUCKETS) steps = MIN_BUCKETS;
        for (uint32_t i = 0; i < steps; i++) { g_minCursor = (g_minCursor + 1) % MIN_BUCKETS; g_min[g_minCursor] = 0; }
        g_lastMin = m;
    }
}
// heure courante (jour 0-6, heure 0-23) : NTP/RTC si dispo, sinon relatif au boot
void siemTimeNow(uint8_t& d, uint8_t& h, bool& real) {
    struct tm ti;
    if (getLocalTime(&ti, 5) && (ti.tm_year + 1900) > 2023) {
        d = ti.tm_wday % WK_DAYS; h = ti.tm_hour % WK_HOURS; real = true; return;
    }
    uint32_t hrs = (millis() - g_bootMs) / 3600000UL;   // heures depuis le boot
    h = hrs % WK_HOURS; d = (hrs / WK_HOURS) % WK_DAYS; real = false;
}
// remet a zero les cases qui entrent dans une nouvelle heure/jour (fenetre glissante)
void siemTickWeekly() {
    uint8_t d, h; bool real; siemTimeNow(d, h, real);
    g_timeReal = real; g_today = d; g_curHour = h;
    static uint8_t lastD = 0xFF, lastH = 0xFF;
    if (lastD == 0xFF) { lastD = d; lastH = h; return; }
    if (d != lastD) { memset(weeklyBuckets[d], 0, sizeof(weeklyBuckets[d])); lastD = d; }
    if (h != lastH) { weeklyBuckets[d][h] = 0; lastH = h; }
}
void clearStats() {
    g_total = 0; memset(portCounts, 0, sizeof(portCounts));
    g_topCount = 0; memset(topIPs, 0, sizeof(topIPs));
    memset(g_min, 0, sizeof(g_min));
    memset(weeklyBuckets, 0, sizeof(weeklyBuckets));
    g_feedCount = 0; g_feedHead = 0; g_hasLast = false; g_attackFlashUntil = 0;
    storeWipe();                         // efface aussi le journal/stats persistants
}
void updateStats(const EventRecord& rec) {
    g_total++;
    int idx = portIndex(rec.port); if (idx >= 0) portCounts[idx]++;
    if (g_min[g_minCursor] < 65535) g_min[g_minCursor]++;
    if (weeklyBuckets[g_today][g_curHour] < 65535) weeklyBuckets[g_today][g_curHour]++;
    bool found = false;
    for (int i = 0; i < g_topCount; i++) if (topIPs[i].ip == rec.ip) { topIPs[i].count++; found = true; break; }
    if (!found) {
        if (g_topCount < MAX_TOP_IPS) { topIPs[g_topCount].ip = rec.ip; topIPs[g_topCount].count = 1; g_topCount++; }
        else { int m = 0; for (int i = 1; i < MAX_TOP_IPS; i++) if (topIPs[i].count < topIPs[m].count) m = i;
               topIPs[m].ip = rec.ip; topIPs[m].count = 1; }
    }
}

// ───────────────────────── log event ──────────────────────────────────
void logEvent(const String& ipStr, uint16_t port, const String& data) {
    EventRecord rec; rec.ms = millis();
    IPAddress addr; addr.fromString(ipStr); rec.ip = ipToUint32(addr); rec.port = port;
    memset(rec.payload, 0, SIEM_PAYLOAD);
    memcpy(rec.payload, data.c_str(), min((int)data.length(), SIEM_PAYLOAD - 1));
    updateStats(rec);
    if (g_feed && g_feedCap) {
        g_feed[g_feedHead] = rec;
        g_feedHead = (g_feedHead + 1) % g_feedCap;
        if (g_feedCount < g_feedCap) g_feedCount++;
    }
    g_lastEvent = rec; g_hasLast = true;
    g_attackFlashUntil = millis() + 900;
    storeEvtAppend(rec);                 // persiste dans l'anneau flash
    g_statsDirty = true;
    webPushEvent(rec);                   // flux SSE -> dashboard web live
    webSendWebhook(rec);                 // webhook Discord/etc si configure + STA
    Serial.printf("[SIEM] %s:%u %.*s\n", ipStr.c_str(), port, SIEM_PAYLOAD, rec.payload);
}

// ── journal : resolution d'un index filtre (k-ieme plus recent matchant) ──
int feedResolve(int k) {
    if (!g_feed || g_feedCap == 0) return -1;
    int seen = 0;
    for (uint32_t i = 0; i < g_feedCount; i++) {
        uint32_t ri = (g_feedHead - 1 - i + g_feedCap * 2) % g_feedCap;
        int idx = portIndex(g_feed[ri].port);
        if (g_filterPort < 0 || idx == g_filterPort) { if (seen == k) return (int)ri; seen++; }
    }
    return -1;
}
int feedMatchCount() {
    if (!g_feed || g_feedCap == 0) return 0;
    int c = 0;
    for (uint32_t i = 0; i < g_feedCount; i++) {
        uint32_t ri = (g_feedHead - 1 - i + g_feedCap * 2) % g_feedCap;
        int idx = portIndex(g_feed[ri].port);
        if (g_filterPort < 0 || idx == g_filterPort) c++;
    }
    return c;
}

// ───────────────────────── banner grab (porte tel quel) ───────────────
// timeout court + sortie anticipee : des que le payload initial est lu on rend la
// main (sinon la loop - et donc l'affichage/navigation - gele pendant l'attaque).
String dumpBytes(WiFiClient& c, size_t maxLen = 256, uint32_t timeout = 50) {
    String s; unsigned long t0 = millis();
    while (millis() - t0 < timeout && s.length() < maxLen && c.connected()) {
        while (c.available() && s.length() < maxLen) { uint8_t b = c.read();
            if (isprint(b) || b == '\r' || b == '\n') s += (char)b;
            else { char buf[5]; sprintf(buf, "\\x%02X", b); s += buf; } }
        if (s.length() && !c.available()) break;   // payload lu -> on n'attend pas plus
        delay(1);
    }
    return s.length() ? s : "(no data)";
}
void handleBanner(WiFiClient client, uint16_t port, const char* banner) {
    if (!client.connected()) return; String ip = client.remoteIP().toString();
    String payload = dumpBytes(client); client.write((const uint8_t*)banner, strlen(banner));
    client.stop(); logEvent(ip, port, payload);
}
void handleBanner(WiFiClient client, uint16_t port, const uint8_t* banner, size_t len) {
    if (!client.connected()) return; String ip = client.remoteIP().toString();
    String payload = dumpBytes(client); client.write(banner, len);
    client.stop(); logEvent(ip, port, payload);
}
void handleServerBanner(WiFiClient client, uint16_t port, const char* banner) {
    if (!client.connected()) return; String ip = client.remoteIP().toString();
    client.write((const uint8_t*)banner, strlen(banner));
    String payload = dumpBytes(client, 256, 60); client.stop(); logEvent(ip, port, payload);
}
void handleServerBanner(WiFiClient client, uint16_t port, const uint8_t* banner, size_t len) {
    if (!client.connected()) return; String ip = client.remoteIP().toString();
    client.write(banner, len); String payload = dumpBytes(client, 256, 60);
    client.stop(); logEvent(ip, port, payload);
}

// ── Ollama honeypot ──
String extractJsonStr(const String& json, const char* key) {
    String k = String("\"") + key + "\""; int idx = json.indexOf(k);
    if (idx < 0) return ""; idx = json.indexOf(":", idx + k.length());
    if (idx < 0) return ""; idx = json.indexOf("\"", idx + 1); if (idx < 0) return "";
    int start = idx + 1, end = start;
    while (end < (int)json.length()) { if (json[end] == '\\') { end += 2; continue; } if (json[end] == '"') break; end++; }
    return json.substring(start, min(end, start + 200));
}
String escapeJsonStr(const String& s) {
    String r; for (int i = 0; i < (int)s.length() && i < 200; i++) { char c = s[i];
        if (c == '"') r += "\\\""; else if (c == '\\') r += "\\\\"; else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r"; else if (c >= 32) r += c; } return r;
}
void handleOllama(WiFiClient client) {
    if (!client.connected()) return; String ip = client.remoteIP().toString();
    String req; unsigned long t0 = millis();
    while (client.connected() && millis() - t0 < 250 && req.length() < 4096) {
        while (client.available() && req.length() < 4096) req += (char)client.read();
        if (req.indexOf("\r\n\r\n") >= 0) { int clIdx = req.indexOf("Content-Length:");
            if (clIdx >= 0) { int cl = req.substring(clIdx + 15).toInt(); int bs = req.indexOf("\r\n\r\n") + 4; if ((int)req.length() - bs >= cl) break; } else break; }
        delay(1);
    }
    String logData = req.substring(0, min((int)req.length(), 48));
    if (req.startsWith("POST")) {
        int bs = req.indexOf("\r\n\r\n"); String body = (bs >= 0) ? req.substring(bs + 4) : "";
        String prompt = extractJsonStr(body, "prompt"); if (!prompt.length()) prompt = extractJsonStr(body, "content");
        if (!prompt.length()) prompt = "(empty)"; logData = prompt.substring(0, 48);
        String mirror = escapeJsonStr("answer: " + prompt);
        String jr = "{\"model\":\"llama3.1:8b\",\"created_at\":\"2025-06-15T10:30:00Z\",\"response\":\"" + mirror + "\",\"done\":true}\n";
        client.print("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: " + String(jr.length()) + "\r\n\r\n" + jr);
    } else client.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 17\r\n\r\nOllama is running");
    client.stop(); logEvent(ip, 11434, logData);
}

// sert au plus une connexion par port ; renvoie true si au moins une servie
bool honeypotServeOnce() {
    bool any = false;
    if (WiFiClient c = telnetServer.available()) { any = true;
        const uint8_t neg[] = {0xFF,0xFB,0x01,0xFF,0xFB,0x03,0xFF,0xFD,0x03};
        c.write(neg, sizeof(neg)); handleServerBanner(c, 23, "\r\nUbuntu 20.04.5 LTS\r\nlogin: "); }
    if (WiFiClient c = ftpServer.available()) { any = true; handleServerBanner(c, 21, "220 ProFTPD 1.3.7c Server (Debian) [::ffff:192.168.1.10]\r\n"); }
    if (WiFiClient c = sshServer.available()) { any = true;
        String ip = c.remoteIP().toString(); c.print("SSH-2.0-OpenSSH_8.5p1 Debian-1\r\n");
        String p = dumpBytes(c, 256, 60); c.stop(); logEvent(ip, 22, p); }
    if (WiFiClient c = smtpServer.available()) { any = true; handleServerBanner(c, 25, "220 mail.local ESMTP Exim 4.94.2\r\n"); }
    if (WiFiClient c = pop3Server.available()) { any = true; handleServerBanner(c, 110, "+OK Dovecot ready.\r\n"); }
    if (WiFiClient c = imapServer.available()) { any = true; handleServerBanner(c, 143, "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE] Dovecot ready.\r\n"); }
    if (WiFiClient c = httpsServer.available()) { any = true; handleBanner(c, 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Debian)\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><body><h1>It works!</h1></body></html>"); }
    if (WiFiClient c = vncServer.available()) { any = true; handleServerBanner(c, 5900, "RFB 003.008\n"); }
    if (WiFiClient c = dnsServer.available()) { any = true; uint8_t q[514]; int n = c.read(q, sizeof(q));
        if (n >= 14) { uint16_t id = (q[2] << 8) | q[3];
            static uint8_t r[] = {0,0,0x85,0x80,0,1,0,1,0,0,0,0,7,'v','e','r','s','i','o','n',4,'b','i','n','d',0,0,0x10,0,3,0xC0,0x0C,0,0x10,0,3,0,0,0,0,0,7,6,'9','.','1','6','.','3'};
            r[0] = id >> 8; r[1] = id & 0xFF; uint16_t dl = sizeof(r); uint8_t p[dl + 2]; p[0] = dl >> 8; p[1] = dl & 0xFF; memcpy(p + 2, r, dl); handleBanner(c, 53, p, dl + 2); } else c.stop(); }
    if (WiFiClient c = smbServer.available()) { any = true;
        static const uint8_t S[] = {0xFF,0x53,0x4D,0x42,0x72,0,0,0,0,0x88,0x07,0xC8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x11,0x02,0,0x01,0,0x20,0x01,0,0,0,0};
        uint32_t l = sizeof(S); uint8_t p[l + 4]; p[0] = 0; p[1] = (l >> 16) & 0xFF; p[2] = (l >> 8) & 0xFF; p[3] = l & 0xFF; memcpy(p + 4, S, l); handleBanner(c, 445, p, l + 4); }
    if (WiFiClient c = mysqlServer.available()) { any = true;
        static const uint8_t M[] = {0x0A,'5','.','7','.','3','3',0,0x08,0,0,0,'r','a','n','d','s','a','l','t',0,0xFF,0xF7,0x08,0x02,0,0xFF,0xC7,0x15,0,0,0,0,0,0,0,0,0,0,'r','a','n','d','s','a','l','t','2',0,0,0,0,0,'m','y','s','q','l','_','n','a','t','i','v','e','_','p','a','s','s','w','o','r','d',0};
        uint8_t p[sizeof(M) + 4]; p[0] = sizeof(M) & 0xFF; p[1] = (sizeof(M) >> 8) & 0xFF; p[2] = (sizeof(M) >> 16) & 0xFF; p[3] = 0; memcpy(p + 4, M, sizeof(M)); handleServerBanner(c, 3306, p, sizeof(p)); }
    if (WiFiClient c = rdpServer.available()) { any = true;
        static const uint8_t R[] = {0x03,0,0,0x13,0x0E,0xD0,0,0,0x12,0x34,0,0x02,0,0x08,0,0,0,0,0}; handleBanner(c, 3389, R, sizeof(R)); }
    if (WiFiClient c = ollamaServer.available()) { any = true; handleOllama(c); }
    if (WiFiClient c = ahttpServer.available()) { any = true; handleBanner(c, 8080, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Debian)\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><body><h1>It works!</h1></body></html>"); }
    return any;
}
void honeypotLoop() {
    // 2 passes max : attrape les petites rafales sans affamer AsyncTCP/le web
    // (le vrai plafond est le taux d'accept TCP de LWIP, pas le nb de passes)
    if (honeypotServeOnce()) honeypotServeOnce();
}

void startServers() {
    WiFiServer* S[PORT_COUNT] = { &ftpServer,&sshServer,&telnetServer,&smtpServer,&dnsServer,&pop3Server,
        &imapServer,&httpsServer,&smbServer,&mysqlServer,&rdpServer,&vncServer,&ahttpServer,&ollamaServer };
    for (int i = 0; i < PORT_COUNT; i++) if (g_portEnabled[i]) { S[i]->begin(); Serial.printf("[+] port %u\n", PORT_LIST[i]); }
}

// ───────────────────────── wifi (AP toujours + STA optionnel) ──────────
// L'AP "StopWatch-SIEM" reste TOUJOURS actif -> page de config/dashboard
// accessible a 192.168.4.1. Si un LAN est configure (page /setup), on le
// rejoint aussi (le honeypot est alors expose sur ce LAN + heure NTP).
void siemWifiStart() {
    WiFi.persistent(false);
    M5.Display.setBrightness(40);        // ecran attenue -> limite le pic de courant (anti-brownout)

    String ss = g_cfgSsid.length() ? g_cfgSsid : String(STA_SSID);
    String pw = g_cfgSsid.length() ? g_cfgPass : String(STA_PASS);
    bool sta = false; uint8_t ch = 6;

    // 1) STA en mode WIFI_STA PUR d'abord : scan + association libres sur tous
    //    les canaux. (En AP_STA l'association a un routeur sur un autre canal
    //    echoue -> status=6. L'AP sera ajoute APRES, sur le canal du STA.)
    if (ss.length() > 0) {
        Serial.printf("[WIFI] join ssid='%s' pwlen=%d ...\n", ss.c_str(), pw.length());
        WiFi.onEvent([](WiFiEvent_t ev, WiFiEventInfo_t info) {
            Serial.printf("[WIFI] disconnect reason=%d\n", info.wifi_sta_disconnected.reason);
        }, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
        WiFi.mode(WIFI_STA); delay(50);
        // force le STA en 802.11 b/g/n standard : un firmware precedent (Totem/
        // DragonRadar) a pu laisser le protocole en Long-Range dans la NVS, ce
        // qui empeche l'association a un AP WPA2 normal (-> reason=2 AUTH_EXPIRE).
        esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
        WiFi.setTxPower(WIFI_POWER_11dBm);
        WiFi.begin(ss.c_str(), pw.c_str());
        int retry = 0; while (WiFi.status() != WL_CONNECTED && retry++ < 50) { delay(400); }  // ~20s
        sta = (WiFi.status() == WL_CONNECTED);
        if (sta) { ch = WiFi.channel(); configTime(0, 0, "pool.ntp.org", "time.nist.gov"); }
        else Serial.printf("[WIFI] STA fail status=%d\n", WiFi.status());
    }

    // 2) AP de config (toujours) + STA si connecte, sur LE MEME canal
    WiFi.mode(sta ? WIFI_AP_STA : WIFI_AP); delay(50);
    bool apOk = WiFi.softAP(AP_SSID, strlen(AP_PASS) >= 8 ? AP_PASS : nullptr, ch, 0, 4);
    esp_wifi_set_protocol(WIFI_IF_AP, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    WiFi.setTxPower(WIFI_POWER_11dBm);
    delay(100);
    M5.Display.setBrightness(190);

    g_isAP = !sta;
    if (sta) { strncpy(g_ipStr, WiFi.localIP().toString().c_str(), 19); strncpy(g_netName, ss.c_str(), 32); }
    else     { strncpy(g_ipStr, WiFi.softAPIP().toString().c_str(), 19); strncpy(g_netName, AP_SSID, 32); }
    Serial.printf("[WIFI] AP '%s' ok=%d ch=%d apIP=%s  STA=%s %s\n", AP_SSID, apOk, ch,
                  WiFi.softAPIP().toString().c_str(), sta ? "up" : "DOWN",
                  sta ? WiFi.localIP().toString().c_str() : "");
}

// ───────────────────────── input ──────────────────────────────────────
static int touchStartX=-1, touchStartY=-1; static bool touchDown=false; static uint32_t touchStartMs=0;
void pollInput() {
    g_actViewNext=g_actViewPrev=g_actDown=g_actUp=g_actSelect=g_actFilter=g_actBack=false;
    g_tapX=g_tapY=-1;

    // ----- boutons (navigation principale) -----
    if (M5.BtnA.wasClicked())        g_actViewNext = true;   // A court  : vue suivante
    if (M5.BtnA.wasHold())           g_actViewPrev = true;   // A long   : vue precedente
    if (M5.BtnB.wasDoubleClicked())  g_actFilter   = true;   // B double : filtre (journal)
    else if (M5.BtnB.wasClicked())   g_actDown     = true;   // B court  : descendre
    if (M5.BtnB.wasHold())           g_actSelect   = true;   // B long   : valider / detail / clear
    if (M5.BtnPWR.wasClicked())      g_actUp       = true;   // PWR court: monter
    if (M5.BtnPWR.wasHold())         g_actBack     = true;   // PWR long : retour

    // ----- tactile (bonus) -----
    auto t = M5.Touch.getDetail();
    if (t.isPressed()) { if (!touchDown) { touchDown = true; touchStartX = t.x; touchStartY = t.y; touchStartMs = millis(); } }
    else if (touchDown) {
        touchDown = false;
        int dx = t.x - touchStartX, dy = t.y - touchStartY, adx = abs(dx), ady = abs(dy);
        uint32_t dur = millis() - touchStartMs;
        if (adx < 45 && ady < 45) { g_tapX = touchStartX; g_tapY = touchStartY; }
        else if (dur < 400) { if (ady > adx * 3 / 2) { if (dy < 0) g_actUp = true; else g_actDown = true; }
                              else if (adx > ady * 3 / 2) { if (dx > 0) g_actViewNext = true; else g_actViewPrev = true; } }
    }
}

// ───────────────────────── app logic ──────────────────────────────────
void viewNext(int d) {
    int v = g_view; v += d;
    if (v < SV_CYCLE_LO) v = SV_CYCLE_HI; if (v > SV_CYCLE_HI) v = SV_CYCLE_LO;
    g_view = (SView)v; g_sel = 0;
}
// cycle le filtre de port du journal : tous -> ports actifs (hits>0) -> tous
void cycleFilter() {
    int start = g_filterPort;
    for (int step = 0; step < PORT_COUNT; step++) {
        int cand = start + 1 + step;
        if (cand >= PORT_COUNT) { g_filterPort = -1; return; }   // retour a "tous"
        if (portCounts[cand] > 0) { g_filterPort = cand; return; }
    }
    g_filterPort = -1;
}
// hit-test de la zone bouton CLEAR (bas de la vue STATUS)
bool tapInClearBtn() { return g_tapX >= 150 && g_tapX <= 316 && g_tapY >= 372 && g_tapY <= 408; }

void appUpdate() {
    // SPLASH : n'importe quelle action passe a l'OVERVIEW
    if (g_view == SV_SPLASH) {
        if (millis() > g_splashUntil || g_actSelect || g_actDown || g_actViewNext || g_tapX >= 0) g_view = SV_OVERVIEW;
        return;
    }
    // DETAIL : toute action revient au journal
    if (g_view == SV_DETAIL) {
        if (g_actBack || g_actSelect || g_actUp || g_actDown || g_actViewNext || g_actViewPrev || g_actFilter || g_tapX >= 0)
            g_view = SV_FEED;
        return;
    }

    // cycle de vues (BtnA court/long, swipe G/D)
    bool nav = false;
    if (g_actViewNext) { viewNext(+1); nav = true; }
    if (g_actViewPrev) { viewNext(-1); nav = true; }
    if (nav) return;

    switch (g_view) {
    case SV_OVERVIEW:
    case SV_HEATMAP:
    case SV_PORTS:
        g_sel = 0;
        break;
    case SV_STATUS:
        if (g_actSelect || (g_tapX >= 0 && tapInClearBtn())) {      // CLEAR avec double confirmation
            if (millis() < g_clearArmUntil) { clearStats(); g_clearArmUntil = 0; }
            else g_clearArmUntil = millis() + 2500;
        }
        g_sel = 0;
        break;
    case SV_IPS:
        if (g_actDown) g_sel++; if (g_actUp) g_sel--;
        break;
    case SV_FEED:
        if (g_actDown) g_sel++; if (g_actUp) g_sel--;
        if (g_actFilter) { cycleFilter(); g_sel = 0; }              // B double : filtre par port
        if (g_actSelect) { g_detailIdx = g_sel; g_view = SV_DETAIL; } // B long : detail du curseur
        if (g_tapX >= 0 && g_tapY >= 78) {                          // tap sur une ligne -> detail
            int row = (g_tapY - 78) / 34;
            if (row >= 0 && row < 8) { g_detailIdx = g_feedWinTop + row; g_view = SV_DETAIL; }
        }
        break;
    default: break;
    }
}

// ───────────────────────── setup / loop ───────────────────────────────
void setup() {
    Serial.begin(115200);
    Serial.setTxTimeoutMs(0);  // USB-CDC non-bloquant : si aucun hote ne lit, on drop
                               // (sinon chaque Serial.print gele la loop sur batterie)
    auto cfg = M5.config();
    cfg.clear_display = true;
    M5.begin(cfg);
    M5.Display.setRotation(0);
    M5.Display.setBrightness(190);

    g_bootMs = millis();
    hudInit();
    hudBootMsg("SIEM INIT");
    hudBootMsg("STORAGE (PSRAM + FLASH)");
    storeBegin();              // alloue le journal PSRAM + monte/charge le flash FAT
    webConfigEnsureDefault();  // cree /config.json par defaut si absent
    webConfigLoad();           // charge ssid/pass/webhook/ports
    hudBootMsg("WIFI AP + WEB UI");
    siemWifiStart();
    startServers();
    webBegin();                // serveur web : dashboard + /setup + API + SSE

    g_lastMin = millis() / 60000;
    g_view = SV_SPLASH; g_splashUntil = millis() + 2000;
}

void loop() {
    M5.update();
    pollInput();
    honeypotLoop();            // sert les connexions entrantes
    siemTickBuckets();
    siemTickWeekly();
    storeFlushTick();          // flush differe de l'en-tete du journal flash
    if (g_isAP) g_apClients = WiFi.softAPgetStationNum();
    appUpdate();
    hudRender();               // TOUJOURS allume, pas de veille

    // autosave stats sur flash (toutes les 30s si modifie)
    static uint32_t lastSave = 0;
    uint32_t now = millis();
    if (g_statsDirty && now - lastSave > 30000) { storeSaveStats(); storeFsStats(); g_statsDirty = false; lastSave = now; }
}
