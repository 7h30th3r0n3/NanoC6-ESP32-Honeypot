// ============================================================================
//  siem_web.ino  -  Interface web complete (portage du webui NanoC6/AtomS3-SIEM)
//  Serveur async sur le port 80 :
//    /            dashboard SIEM (heatmap 7x24, ports, top IPs, event log, SSE)
//    /setup       page de configuration (SSID/pass LAN, webhook, ports actifs)
//    /config      GET/POST du /config.json (FFat)
//    /api/stats   JSON stats agregees        /api/events  journal pagine+filtre
//    /api/stream  SSE live events            /api/clear /reset /reboot
//  Coexiste avec le honeypot (ports de leurre) et le SIEM a l'ecran.
// ============================================================================
#include <ESPAsyncWebServer.h>
#include <HTTPClient.h>
#include <FFat.h>
#include <time.h>
#include "siem_types.h"
#include "siem_webpages.h"

static const char* CFG_PATH = "/config.json";
AsyncWebServer   webServer(80);
AsyncEventSource sseStream("/api/stream");
static bool g_webUp = false;

// ───────────────────────── config (FFat /config.json) ─────────────────
static void applyPortsFromJson(const String& js) {
    int pi = js.indexOf("\"ports\"");
    if (pi < 0) { for (int i = 0; i < PORT_COUNT; i++) g_portEnabled[i] = true; return; }
    int lb = js.indexOf('[', pi), rb = js.indexOf(']', lb);
    if (lb < 0 || rb < 0) { for (int i = 0; i < PORT_COUNT; i++) g_portEnabled[i] = true; return; }
    for (int i = 0; i < PORT_COUNT; i++) g_portEnabled[i] = false;
    String arr = js.substring(lb + 1, rb);
    int start = 0;
    while (start < (int)arr.length()) {
        int comma = arr.indexOf(',', start); if (comma < 0) comma = arr.length();
        String tok = arr.substring(start, comma); tok.trim();
        if (tok.length()) { int idx = portIndex((uint16_t)tok.toInt()); if (idx >= 0) g_portEnabled[idx] = true; }
        start = comma + 1;
    }
}
void webConfigEnsureDefault() {
    if (!g_fsOk) { for (int i = 0; i < PORT_COUNT; i++) g_portEnabled[i] = true; return; }
    if (FFat.exists(CFG_PATH)) return;
    File f = FFat.open(CFG_PATH, "w");
    if (f) { f.print("{\"ssid\":\"\",\"password\":\"\",\"webhook\":\"\",\"ports\":[21,22,23,25,53,110,143,443,445,3306,3389,5900,8080,11434]}"); f.close(); }
}
bool webConfigLoad() {
    for (int i = 0; i < PORT_COUNT; i++) g_portEnabled[i] = true;
    if (!g_fsOk) return false;
    File f = FFat.open(CFG_PATH, "r");
    if (!f || f.size() == 0) { if (f) f.close(); return false; }
    String js = f.readString(); f.close();
    g_cfgSsid    = extractJsonStr(js, "ssid");
    g_cfgPass    = extractJsonStr(js, "password");
    g_cfgWebhook = extractJsonStr(js, "webhook");
    applyPortsFromJson(js);
    return g_cfgSsid.length() > 0;
}

// ───────────────────────── helpers ────────────────────────────────────
// epoch (s) d'un event : heure reelle - age ; 0 si pas de synchro (dashboard -> "--")
static uint32_t webEpochOf(const EventRecord& e) {
    if (!g_timeReal) return 0;
    time_t now = time(nullptr);
    uint32_t age = (millis() >= e.ms) ? (millis() - e.ms) / 1000 : 0;
    return (uint32_t)now - age;
}
static int jsonEscPayload(const EventRecord& e, char* out, int cap) {
    int j = 0;
    for (int k = 0; k < SIEM_PAYLOAD && e.payload[k] && j < cap - 2; k++) {
        char c = e.payload[k];
        if (c == '"' || c == '\\') out[j++] = '\\';
        if (c >= 32) out[j++] = c;
    }
    out[j] = 0; return j;
}
static String curIpStr() {
    return (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : WiFi.softAPIP().toString();
}

// ───────────────────────── SSE + webhook (appeles par logEvent) ───────
void webPushEvent(const EventRecord& rec) {
    if (!g_webUp || sseStream.count() == 0) return;
    char ip[16]; uint32ToIP(rec.ip, ip);
    char esc[SIEM_PAYLOAD * 2 + 2]; jsonEscPayload(rec, esc, sizeof(esc));
    char json[220];
    snprintf(json, sizeof(json), "{\"t\":%u,\"ip\":\"%s\",\"p\":%u,\"d\":\"%s\"}", webEpochOf(rec), ip, rec.port, esc);
    sseStream.send(json, "event", millis());
}
void webSendWebhook(const EventRecord& rec) {
    if (WiFi.status() != WL_CONNECTED || g_cfgWebhook.length() == 0) return;
    HTTPClient http; http.begin(g_cfgWebhook); http.addHeader("Content-Type", "application/json");
    char ip[16]; uint32ToIP(rec.ip, ip);
    String msg = "{\"content\":\"**Honeypot SIEM**\\nIP: `"; msg += ip; msg += "`\\nPort: `"; msg += rec.port;
    msg += "`\\nPayload: `"; msg += String(rec.payload).substring(0, 50); msg += "`\"}";
    http.POST(msg); http.end();
}

// ───────────────────────── API ────────────────────────────────────────
static void handleStats(AsyncWebServerRequest* r) {
    uint32_t upSec = millis() / 1000; if (upSec < 1) upSec = 1;
    uint32_t rate  = (uint32_t)((uint64_t)g_total * 3600ULL / upSec);
    size_t used = g_fsOk ? FFat.usedBytes() : 0, total = g_fsOk ? FFat.totalBytes() : 1;
    uint8_t pct = total > 0 ? (used * 100) / total : 0;

    String j = "{\"total\":"; j += g_total;
    j += ",\"events\":"; j += g_feedCount;
    j += ",\"ips\":";    j += g_topCount;
    j += ",\"rate\":";   j += rate;
    j += ",\"uptime\":"; j += upSec;
    j += ",\"storage\":"; j += pct;
    j += ",\"ip\":\"";  j += curIpStr(); j += "\"";
    j += ",\"heap\":";  j += ESP.getFreeHeap();
    j += ",\"capacity\":"; j += g_feedCap;
    j += ",\"device\":\"StopWatch\",\"today\":"; j += g_today;
    j += ",\"heatmap\":[";
    for (int d = 0; d < WK_DAYS; d++) { if (d) j += ","; j += "[";
        for (int h = 0; h < WK_HOURS; h++) { if (h) j += ","; j += weeklyBuckets[d][h]; } j += "]"; }
    j += "]";
    // top IPs tries
    int ord[MAX_TOP_IPS]; for (int i = 0; i < g_topCount; i++) ord[i] = i;
    for (int a = 0; a < g_topCount; a++) for (int b = a + 1; b < g_topCount; b++)
        if (topIPs[ord[b]].count > topIPs[ord[a]].count) { int t = ord[a]; ord[a] = ord[b]; ord[b] = t; }
    j += ",\"topIPs\":[";
    for (int i = 0; i < g_topCount; i++) { if (i) j += ","; char ip[16]; uint32ToIP(topIPs[ord[i]].ip, ip);
        j += "[\""; j += ip; j += "\","; j += topIPs[ord[i]].count; j += "]"; }
    j += "]";
    // ports tries
    struct PD { uint16_t port; uint32_t count; }; PD pds[PORT_COUNT]; int pdc = 0;
    for (int i = 0; i < PORT_COUNT; i++) if (portCounts[i] > 0) pds[pdc++] = { PORT_LIST[i], portCounts[i] };
    for (int i = 0; i < pdc - 1; i++) for (int k = i + 1; k < pdc; k++)
        if (pds[k].count > pds[i].count) { PD t = pds[i]; pds[i] = pds[k]; pds[k] = t; }
    j += ",\"portDist\":[";
    for (int i = 0; i < pdc; i++) { if (i) j += ","; j += "["; j += pds[i].port; j += ","; j += pds[i].count; j += "]"; }
    j += "]}";
    AsyncWebServerResponse* res = r->beginResponse(200, "application/json", j);
    res->addHeader("Cache-Control", "no-store"); r->send(res);
}
static void handleEvents(AsyncWebServerRequest* r) {
    int page = 1, limit = 30; uint16_t fPort = 0; String fIP = "";
    if (r->hasParam("page"))  page  = r->getParam("page")->value().toInt();
    if (r->hasParam("limit")) limit = constrain(r->getParam("limit")->value().toInt(), 1, 100);
    if (r->hasParam("port"))  fPort = r->getParam("port")->value().toInt();
    if (r->hasParam("ip"))    fIP   = r->getParam("ip")->value();
    if (page < 1) page = 1;
    bool hasF = (fPort > 0 || fIP.length() > 0);
    int skip = (page - 1) * limit;

    if (!g_feed || g_feedCap == 0) { r->send(200, "application/json", "{\"total\":0,\"page\":1,\"events\":[]}"); return; }
    int total = 0;
    for (uint32_t i = 0; i < g_feedCount; i++) {
        uint32_t ri = (g_feedHead - 1 - i + g_feedCap * 2) % g_feedCap; EventRecord& e = g_feed[ri];
        if (hasF) { if (fPort > 0 && e.port != fPort) continue;
                    if (fIP.length() > 0) { char ip[16]; uint32ToIP(e.ip, ip); if (!strstr(ip, fIP.c_str())) continue; } }
        total++;
    }
    AsyncResponseStream* res = r->beginResponseStream("application/json");
    res->addHeader("Cache-Control", "no-store");
    res->printf("{\"total\":%d,\"page\":%d,\"events\":[", total, page);
    int seen = 0, emitted = 0; bool first = true;
    for (uint32_t i = 0; i < g_feedCount && emitted < limit; i++) {
        uint32_t ri = (g_feedHead - 1 - i + g_feedCap * 2) % g_feedCap; EventRecord& e = g_feed[ri];
        if (hasF) { if (fPort > 0 && e.port != fPort) continue;
                    if (fIP.length() > 0) { char ip[16]; uint32ToIP(e.ip, ip); if (!strstr(ip, fIP.c_str())) continue; } }
        if (seen++ < skip) continue;
        char ip[16]; uint32ToIP(e.ip, ip);
        char esc[SIEM_PAYLOAD * 2 + 2]; jsonEscPayload(e, esc, sizeof(esc));
        if (!first) res->print(","); first = false;
        res->printf("{\"t\":%u,\"ip\":\"%s\",\"p\":%u,\"d\":\"%s\"}", webEpochOf(e), ip, e.port, esc);
        emitted++;
    }
    res->print("]}"); r->send(res);
}

void webBegin() {
    webServer.addHandler(&sseStream);
    webServer.on("/", HTTP_GET, [](AsyncWebServerRequest* r) {
        AsyncWebServerResponse* resp = r->beginResponse(200, "text/html", DASHBOARD_HTML_GZ, DASHBOARD_HTML_GZ_LEN);
        resp->addHeader("Content-Encoding", "gzip"); r->send(resp); });
    webServer.on("/setup", HTTP_GET, [](AsyncWebServerRequest* r) {
        AsyncWebServerResponse* resp = r->beginResponse(200, "text/html", SETUP_HTML_GZ, SETUP_HTML_GZ_LEN);
        resp->addHeader("Content-Encoding", "gzip"); r->send(resp); });
    webServer.on("/config", HTTP_GET, [](AsyncWebServerRequest* r) {
        if (!g_fsOk) { r->send(500, "application/json", "{\"error\":\"no fs\"}"); return; }
        File f = FFat.open(CFG_PATH, "r"); if (!f) { r->send(500); return; }
        String js = f.readString(); f.close();
        AsyncWebServerResponse* res = r->beginResponse(200, "application/json", js);
        res->addHeader("Cache-Control", "no-store"); r->send(res); });
    webServer.on("/config", HTTP_POST, [](AsyncWebServerRequest* r) {}, NULL,
        [](AsyncWebServerRequest* r, uint8_t* data, size_t len, size_t index, size_t total) {
            File f = FFat.open(CFG_PATH, index == 0 ? "w" : "a"); if (!f) { r->send(500); return; }
            f.write(data, len); f.close();
            if (index + len >= total) r->send(200, "application/json", "{\"status\":\"OK\"}"); });
    webServer.on("/reboot", HTTP_POST, [](AsyncWebServerRequest* r) { r->send(200); delay(400); ESP.restart(); });
    webServer.on("/reset", HTTP_POST, [](AsyncWebServerRequest* r) { clearStats(); r->send(200, "application/json", "{\"status\":\"OK\"}"); });
    webServer.on("/api/clear", HTTP_POST, [](AsyncWebServerRequest* r) { clearStats(); r->send(200, "application/json", "{\"status\":\"OK\"}"); });
    webServer.on("/api/stats",  HTTP_GET, handleStats);
    webServer.on("/api/events", HTTP_GET, handleEvents);
    webServer.begin();
    g_webUp = true;
    Serial.println("[WEB] server up on :80");
}
