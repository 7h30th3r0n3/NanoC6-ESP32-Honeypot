// ============================================================================
//  siem_hud.ino  -  Dashboard SIEM circulaire (AMOLED rond 466x466)
//  Toujours allume. Anneau radial 60min, donut ports, compteur de menaces,
//  flux live, alerte intrusion. Theme SIEM sombre (teal/blue/amber/red).
// ============================================================================

static M5Canvas  g_spr(&M5.Display);
static LovyanGFX* cv = nullptr;
static bool      g_useSprite = false;

static const int CX = 233, CY = 233, SCRW = 466, SCRH = 466;

static uint16_t C_BG, C_PANEL, C_TEAL, C_BLUE, C_AMBER, C_RED, C_TXT, C_DIM, C_GRID, C_WHITE;
static inline uint16_t rgb(uint8_t r, uint8_t g, uint8_t b) { return M5.Display.color565(r,g,b); }

void txt(const lgfx::IFont* f, uint16_t color, int x, int y, textdatum_t datum, const char* s) {
    cv->setFont(f); cv->setTextSize(1); cv->setTextColor(color); cv->setTextDatum(datum);
    cv->drawString(s, x, y);
}
void txtf(const lgfx::IFont* f, uint16_t color, int x, int y, textdatum_t datum, const char* fmt, ...) {
    char buf[96]; va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    txt(f, color, x, y, datum, buf);
}
const char* clampName(const char* s, int maxpx, const lgfx::IFont* f) {
    static char out[40];
    cv->setFont(f); cv->setTextSize(1);
    strncpy(out, (s && s[0]) ? s : "?", sizeof(out) - 1); out[sizeof(out) - 1] = 0;
    int n = strlen(out);
    while (n > 1 && cv->textWidth(out) > maxpx) { out[--n] = 0; }
    return out;
}
// gradient froid->chaud selon f (0..1)
uint16_t heat(float f) {
    if (f < 0) f = 0; if (f > 1) f = 1;
    uint8_t r, g, b;
    if (f < 0.5f) { float t = f / 0.5f; r = 0 + t * 255; g = 229 - t * 53; b = 160 - t * 128; }   // teal->amber
    else          { float t = (f - 0.5f) / 0.5f; r = 255; g = 176 - t * 105; b = 32 + t * 55; }     // amber->red
    return rgb(r, g, b);
}
uint16_t portColor(int i) {
    static const uint8_t P[14][3] = {
        {0,229,160},{59,130,246},{168,85,247},{255,176,32},{236,72,153},{34,197,94},{14,165,233},
        {249,115,22},{99,102,241},{20,184,166},{244,63,94},{132,204,22},{250,204,21},{217,70,239}};
    return rgb(P[i%14][0], P[i%14][1], P[i%14][2]);
}

// ───────────────────────── frame + helpers ────────────────────────────
void hudFrame() {
    cv->fillScreen(C_BG);
    cv->drawCircle(CX, CY, 231, rgb(20,28,48));
    cv->drawCircle(CX, CY, 222, C_GRID);
}
void hudBootMsg(const char* s) {
    if (!cv) return;
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, CY, middle_center, s);
    if (g_useSprite) g_spr.pushSprite(0, 0);
}
void uptimeStr(char* out, size_t n) {
    uint32_t s = (millis() - g_bootMs) / 1000;
    if (s < 3600) snprintf(out, n, "%lum%02lus", (unsigned long)(s/60), (unsigned long)(s%60));
    else snprintf(out, n, "%luh%02lum", (unsigned long)(s/3600), (unsigned long)((s/60)%60));
}
void bigNum(const lgfx::IFont* f, uint16_t col, int x, int y, uint32_t v) {
    char b[16];
    if (v >= 100000) snprintf(b, 16, "%lu.%luK", (unsigned long)(v/1000), (unsigned long)((v/100)%10));
    else snprintf(b, 16, "%lu", (unsigned long)v);
    txt(f, col, x, y, middle_center, b);
}

// bandeau haut commun (nom reseau / ip / clients)
void drawTopStatus() {
    txtf(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 56, middle_center, "%s", clampName(g_netName, 300, &fonts::FreeSansBold9pt7b));
    if (g_isAP) txtf(&fonts::Font2, C_DIM, CX, 76, middle_center, "AP %s  clients:%d", g_ipStr, g_apClients);
    else        txtf(&fonts::Font2, C_DIM, CX, 76, middle_center, "STA %s", g_ipStr);
}

// ───────────────────────── SPLASH ─────────────────────────────────────
void drawSplash() {
    uint32_t now = millis();
    float t = (now % 1400) / 1400.0f;
    hudFrame();
    for (int k = 0; k < 3; k++) {
        float p = fmodf(t + k / 3.0f, 1.0f);
        cv->drawCircle(CX, CY, (int)(30 + p * 180), heat(1 - p));
    }
    txt(&fonts::FreeSansBold12pt7b, C_TEAL, CX, CY - 8, middle_center, "HONEYPOT");
    txt(&fonts::Font2, C_DIM, CX, CY + 14, middle_center, "SIEM DASHBOARD");
    txt(&fonts::Font2, C_DIM, CX, SCRH - 60, middle_center, "14-PORT DECOY  LIVE");
}

// ───────────────────────── OVERVIEW (hero) ────────────────────────────
void drawOverview() {
    uint32_t now = millis();
    hudFrame();
    const int rcx = 233, rcy = 238, Rin = 150, Lmax = 56;

    // anneaux repere
    cv->drawCircle(rcx, rcy, Rin, rgb(24,34,58));
    cv->drawCircle(rcx, rcy, Rin + Lmax, rgb(20,28,48));

    // anneau radial : 60 minutes glissantes (plus recent en haut, horaire antihoraire->passe)
    uint16_t mx = 1;
    for (int i = 0; i < MIN_BUCKETS; i++) if (g_min[i] > mx) mx = g_min[i];
    for (int i = 0; i < MIN_BUCKETS; i++) {
        uint16_t val = g_min[(g_minCursor - i + MIN_BUCKETS) % MIN_BUCKETS];
        float a = i * 6.0f * DEG2RAD;
        float fr = (float)val / mx;
        int len = (val > 0) ? (int)(fr * Lmax) + 2 : 0;
        uint16_t col = (val > 0) ? heat(fr) : rgb(22,30,52);
        int x0 = rcx + sinf(a) * Rin,       y0 = rcy - cosf(a) * Rin;
        int x1 = rcx + sinf(a) * (Rin + (len ? len : 2)), y1 = rcy - cosf(a) * (Rin + (len ? len : 2));
        cv->drawWideLine(x0, y0, x1, y1, 3.4f, col);
    }

    // donut des ports (proportion des hits)
    uint32_t sum = 0; for (int i = 0; i < PORT_COUNT; i++) sum += portCounts[i];
    if (sum > 0) {
        float start = -90;
        for (int i = 0; i < PORT_COUNT; i++) {
            if (!portCounts[i]) continue;
            float sweep = 360.0f * portCounts[i] / sum; if (sweep < 1.5f) sweep = 1.5f;
            cv->fillArc(rcx, rcy, 120, 131, start, start + sweep, portColor(i));
            start += sweep;
        }
    } else cv->drawCircle(rcx, rcy, 126, rgb(24,34,58));

    // centre : compteur de menaces (Font7 = chiffres only)
    txtf(&fonts::Font7, C_WHITE, rcx, rcy - 6, middle_center, "%lu", (unsigned long)g_total);
    txt(&fonts::Font2, C_DIM, rcx, rcy + 26, middle_center, "THREATS");
    uint16_t rate = g_min[g_minCursor];
    txtf(&fonts::Font2, C_TEAL, rcx, rcy + 44, middle_center, "%u / min", rate);

    // flux : dernier evenement
    bool alert = now < g_attackFlashUntil;
    if (g_hasLast) {
        char ip[16]; uint32ToIP(g_lastEvent.ip, ip);
        int idx = portIndex(g_lastEvent.port);
        const char* pn = idx >= 0 ? PORT_NAMES[idx] : "?";
        txtf(&fonts::Font2, alert ? C_RED : C_AMBER, rcx, rcy + 66, middle_center, "%s :%u %s", ip, g_lastEvent.port, pn);
    }

    drawTopStatus();

    // alerte intrusion : ping rouge + bandeau
    if (alert) {
        float p = (float)(g_attackFlashUntil - now) / 900.0f;        // 1 -> 0
        int pr = (int)(Rin - 10 - (1 - p) * 60);
        if (pr > 20) cv->drawCircle(rcx, rcy, pr, C_RED);
        cv->drawArc(CX, CY, 214, 222, 0, 360, C_RED);
        txt(&fonts::FreeSansBold9pt7b, C_RED, CX, 100, middle_center, "! INTRUSION !");
    }

    // uptime bas + hint
    char up[16]; uptimeStr(up, sizeof(up));
    txtf(&fonts::Font2, C_DIM, CX, SCRH - 40, middle_center, "up %s", up);
    txt(&fonts::Font2, C_GRID, CX, SCRH - 22, middle_center, "A: vue suiv.   A-long: prec.");
}

// ───────────────────────── PORTS ──────────────────────────────────────
void drawPorts() {
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 50, middle_center, "PORT ACTIVITY");
    int ord[PORT_COUNT]; for (int i = 0; i < PORT_COUNT; i++) ord[i] = i;
    for (int a = 0; a < PORT_COUNT; a++) for (int b = a+1; b < PORT_COUNT; b++) if (portCounts[ord[b]] > portCounts[ord[a]]) { int t = ord[a]; ord[a] = ord[b]; ord[b] = t; }
    uint32_t mx = 1; for (int i = 0; i < PORT_COUNT; i++) if (portCounts[i] > mx) mx = portCounts[i];
    int y = 78, lh = 25, shown = 0;
    for (int i = 0; i < PORT_COUNT && shown < 12; i++, shown++) {
        int p = ord[i]; uint16_t col = portColor(p);
        txtf(&fonts::Font2, C_TXT, 78, y + 6, middle_left, "%-6s %u", PORT_NAMES[p], PORT_LIST[p]);
        int bw = (int)(140.0f * portCounts[p] / mx); if (bw > 140) bw = 140;   // ends <=330
        cv->fillSmoothRoundRect(190, y + 2, bw + 1, 11, 2, col);
        txtf(&fonts::Font2, C_DIM, 402, y + 6, middle_right, "%lu", (unsigned long)portCounts[p]);
        y += lh;
    }
    txt(&fonts::Font2, C_GRID, CX, SCRH - 26, middle_center, "A: vue suiv.   A-long: prec.");
}

// ───────────────────────── STATUS (micro-SIEM : stat cards) ────────────
void statCard(int cx, int cy, int w, int h, const char* label, const char* val, uint16_t accent) {
    cv->fillSmoothRoundRect(cx - w/2, cy - h/2, w, h, 8, C_PANEL);
    cv->drawRoundRect(cx - w/2, cy - h/2, w, h, 8, C_GRID);
    cv->fillSmoothRoundRect(cx - w/2 + 5, cy - h/2 + 7, 4, h - 14, 2, accent);
    txt(&fonts::Font2, C_DIM, cx - w/2 + 17, cy - 13, middle_left, label);
    txt(&fonts::FreeSansBold12pt7b, C_WHITE, cx - w/2 + 16, cy + 11, middle_left, val);
}
void drawStatus() {
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 42, middle_center, "SYSTEM STATUS");

    // panneau connexion : AP de config toujours dispo + LAN si rejoint + URL web
    cv->fillSmoothRoundRect(86, 56, 294, 76, 8, C_PANEL);
    cv->drawRoundRect(86, 56, 294, 76, 8, C_GRID);
    txtf(&fonts::Font2, C_TEAL, 100, 69, middle_left, "AP %s  cli:%d", AP_SSID, g_apClients);
    txtf(&fonts::Font2, C_DIM, 100, 87, middle_left, "pass %s  192.168.4.1", strlen(AP_PASS) >= 8 ? AP_PASS : "(open)");
    if (!g_isAP) txtf(&fonts::Font2, C_AMBER, 100, 105, middle_left, "LAN %s", g_ipStr);
    else         txt (&fonts::Font2, C_DIM,   100, 105, middle_left, "LAN: /setup pour rejoindre");
    txtf(&fonts::Font0, C_TEAL, 100, 122, middle_left, "web http://%s/   config /setup", g_ipStr);

    // 6 cartes metriques (2 colonnes x 3 lignes)
    uint32_t upSec = (millis() - g_bootMs) / 1000; if (upSec < 1) upSec = 1;
    uint32_t ratH  = (uint32_t)((uint64_t)g_total * 3600ULL / upSec);
    char bTot[16], bUniq[8], bRate[12], bUp[16], bRam[12], bLog[16];
    if (g_total >= 100000) snprintf(bTot, 16, "%lu.%luK", (unsigned long)(g_total/1000), (unsigned long)((g_total/100)%10));
    else snprintf(bTot, 16, "%lu", (unsigned long)g_total);
    snprintf(bUniq, 8, "%u", g_topCount);
    snprintf(bRate, 12, "%lu", (unsigned long)ratH);
    uptimeStr(bUp, sizeof(bUp));
    snprintf(bRam, 12, "%luK", (unsigned long)(ESP.getFreeHeap() / 1024));
    snprintf(bLog, 16, "%lu", (unsigned long)g_feedCount);

    const int cw = 150, ch = 58;
    statCard(150, 166, cw, ch, "THREATS",    bTot,  C_RED);
    statCard(316, 166, cw, ch, "UNIQUE IPS", bUniq, C_BLUE);
    statCard(150, 230, cw, ch, "EVENTS/H",   bRate, C_AMBER);
    statCard(316, 230, cw, ch, "UPTIME",     bUp,   C_TEAL);
    statCard(150, 294, cw, ch, "FREE RAM",   bRam,  C_TEAL);
    statCard(316, 294, cw, ch, "PSRAM LOG",  bLog,  C_BLUE);

    // ligne stockage : PSRAM (journal) + flash FAT (persistance)
    txtf(&fonts::Font0, C_DIM, CX, 338, middle_center,
         "PSRAM %s %lu evt / %luk  |  PSRAM free %luK",
         g_feedPsram ? "ring" : "RAM", (unsigned long)g_feedCount,
         (unsigned long)(g_feedCap >= 1000 ? g_feedCap / 1000 : g_feedCap),
         (unsigned long)(ESP.getFreePsram() / 1024));
    if (g_fsOk)
        txtf(&fonts::Font0, C_TEAL, CX, 353, middle_center,
             "FLASH %lu evt persist  |  %lu/%lu MB",
             (unsigned long)g_flashEvents,
             (unsigned long)(g_fsUsedKB / 1024), (unsigned long)(g_fsTotalKB / 1024));
    else
        txt(&fonts::Font0, C_RED, CX, 353, middle_center, "FLASH indisponible (RAM only)");

    // bouton CLEAR (reset stats) - tap zone 150..316 / 372..408, confirmation requise
    bool armed = millis() < g_clearArmUntil;
    cv->fillSmoothRoundRect(150, 372, 166, 32, 8, armed ? rgb(120,24,32) : rgb(60,20,28));
    cv->drawRoundRect(150, 372, 166, 32, 8, C_RED);
    txt(&fonts::Font2, armed ? C_WHITE : C_RED, CX, 388, middle_center, armed ? "CONFIRM ? B/tap" : "CLEAR STATS");
    txt(&fonts::Font2, C_GRID, CX, SCRH - 18, middle_center, "A:vue  B-long:clear");
}

// ───────────────────────── HEATMAP (7j x 24h radiale) ──────────────────
void drawHeatmap() {
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 40, middle_center, "WEEKLY HEATMAP");
    txt(&fonts::Font2, C_DIM, CX, 60, middle_center, "7 days  x  24 hours");

    const int hx = 233, hy = 250, r0 = 62, r1 = 196;
    const float ringW = (r1 - r0) / (float)WK_DAYS;
    uint16_t mx = 1;
    for (int d = 0; d < WK_DAYS; d++) for (int h = 0; h < WK_HOURS; h++) if (weeklyBuckets[d][h] > mx) mx = weeklyBuckets[d][h];

    for (int d = 0; d < WK_DAYS; d++) {
        float inR = r0 + d * ringW, outR = inR + ringW - 1.5f;
        for (int h = 0; h < WK_HOURS; h++) {
            uint16_t v = weeklyBuckets[d][h];
            float a0 = -90 + h * 15.0f;
            uint16_t col = v ? heat((float)v / mx) : rgb(18,24,44);
            cv->fillArc(hx, hy, (int)inR, (int)outR, a0, a0 + 14.0f, col);
        }
    }
    // surbrillance : anneau du jour courant + case heure courante
    float tInR = r0 + g_today * ringW, tOutR = tInR + ringW - 1.5f;
    cv->drawArc(hx, hy, (int)tInR, (int)tOutR, -90 + g_curHour * 15.0f, -90 + g_curHour * 15.0f + 14.0f, C_WHITE);
    cv->drawCircle(hx, hy, (int)tOutR, rgb(40,60,90));

    // reperes horaires
    txt(&fonts::Font0, C_DIM, hx,        hy - r1 - 9, middle_center, "00");
    txt(&fonts::Font0, C_DIM, hx + r1 + 9, hy,         middle_center, "06");
    txt(&fonts::Font0, C_DIM, hx,        hy + r1 + 9, middle_center, "12");
    txt(&fonts::Font0, C_DIM, hx - r1 - 9, hy,         middle_center, "18");

    // source de l'heure + legende
    txtf(&fonts::Font0, C_GRID, hx, hy, middle_center, g_timeReal ? "RTC" : "boot");
    txt(&fonts::Font2, C_GRID, CX, SCRH - 20, middle_center, "A: vue suiv.   A-long: prec.");
}

// ───────────────────────── FEED (flux live / event log) ────────────────
// age robuste (les ms d'un event recharge du flash datent d'un boot anterieur)
static uint32_t evtAge(const EventRecord& e) {
    uint32_t now = millis(); return (now >= e.ms) ? (now - e.ms) / 1000 : 0xFFFFFFFF;
}
static void ageStr(char* out, size_t n, const EventRecord& e) {
    uint32_t a = evtAge(e);
    if (a == 0xFFFFFFFF) snprintf(out, n, "old");
    else if (a < 600)    snprintf(out, n, "%lus", (unsigned long)a);
    else if (a < 36000)  snprintf(out, n, "%lum", (unsigned long)(a / 60));
    else                 snprintf(out, n, "%luh", (unsigned long)(a / 3600));
}

void drawFeed() {
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 42, middle_center, "LIVE FEED");
    if (g_filterPort >= 0)
        txtf(&fonts::Font2, C_AMBER, CX, 62, middle_center, "filter: %s :%u", PORT_NAMES[g_filterPort], PORT_LIST[g_filterPort]);
    else
        txt(&fonts::Font2, C_DIM, CX, 62, middle_center, "filter: ALL");

    int total = feedMatchCount();
    if (total == 0) {
        txt(&fonts::Font2, C_DIM, CX, CY, middle_center, "waiting for probes...");
        txt(&fonts::Font2, C_GRID, CX, SCRH - 28, middle_center, "A:vue   B2:filtre");
        return;
    }
    if (g_sel < 0) g_sel = 0; if (g_sel > total - 1) g_sel = total - 1;
    int winTop = g_sel - 3; if (winTop > total - 8) winTop = total - 8; if (winTop < 0) winTop = 0;
    g_feedWinTop = winTop;

    int y = 84, lh = 34, shown = 0;
    for (int k = winTop; k < total && shown < 8; k++, shown++) {
        int ri = feedResolve(k); if (ri < 0) break;
        EventRecord& e = g_feed[ri];
        char ip[16]; uint32ToIP(e.ip, ip);
        int idx = portIndex(e.port); const char* pn = idx >= 0 ? PORT_NAMES[idx] : "?";
        bool cur = (k == g_sel);
        if (cur) cv->fillSmoothRoundRect(58, y - 14, 352, 31, 5, rgb(18,30,54));   // curseur
        char ag[8]; ageStr(ag, sizeof(ag), e);
        txtf(&fonts::Font2, cur ? C_WHITE : C_AMBER, 70, y, middle_left, "%s :%u %s", ip, e.port, pn);
        txtf(&fonts::Font2, C_DIM, 400, y, middle_right, "%s", ag);
        char snip[26]; strncpy(snip, e.payload, 25); snip[25] = 0;
        txt(&fonts::Font0, cur ? C_TEAL : C_DIM, 70, y + 15, middle_left, clampName(snip, 320, &fonts::Font0));
        y += lh;
    }
    txtf(&fonts::Font2, C_GRID, CX, SCRH - 26, middle_center, "%d/%d  B:detail  B2:filtre", g_sel + 1, total);
}

// ───────────────────────── DETAIL (modal event) ────────────────────────
void drawDetail() {
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 54, middle_center, "EVENT DETAIL");
    int ri = feedResolve(g_detailIdx);
    if (ri < 0) {
        txt(&fonts::Font2, C_DIM, CX, CY, middle_center, "no event");
        txt(&fonts::Font2, C_GRID, CX, SCRH - 50, middle_center, "PWR / B : retour"); return;
    }
    EventRecord& e = g_feed[ri];
    char ip[16]; uint32ToIP(e.ip, ip);
    int idx = portIndex(e.port); const char* pn = idx >= 0 ? PORT_NAMES[idx] : "?";
    char ag[8]; ageStr(ag, sizeof(ag), e);

    cv->fillSmoothRoundRect(70, 86, 326, 118, 10, C_PANEL);
    cv->drawRoundRect(70, 86, 326, 118, 10, C_GRID);
    txt (&fonts::Font2, C_DIM,   86, 104, middle_left, "TIME");
    txtf(&fonts::Font2, C_TXT,  180, 104, middle_left, "%s ago", ag);
    txt (&fonts::Font2, C_DIM,   86, 132, middle_left, "SOURCE");
    txtf(&fonts::Font2, C_AMBER,180, 132, middle_left, "%s", ip);
    txt (&fonts::Font2, C_DIM,   86, 160, middle_left, "PORT");
    txtf(&fonts::Font2, C_TEAL, 180, 160, middle_left, "%u  %s", e.port, pn);
    txt (&fonts::Font2, C_DIM,   86, 188, middle_left, "SERVICE");
    txtf(&fonts::Font2, C_TXT,  180, 188, middle_left, "%s decoy", pn);

    // payload capture (multi-lignes)
    txt(&fonts::Font2, C_DIM, CX, 222, middle_center, "PAYLOAD");
    char pl[SIEM_PAYLOAD]; strncpy(pl, e.payload, SIEM_PAYLOAD - 1); pl[SIEM_PAYLOAD - 1] = 0;
    int py = 244;
    for (int off = 0, line = 0; off < (int)strlen(pl) && line < 4; line++) {
        char seg[33]; int n = 0;
        while (n < 32 && pl[off + n]) { seg[n] = pl[off + n]; n++; }
        seg[n] = 0; off += n;
        txt(&fonts::Font0, C_TEAL, CX, py, middle_center, seg);
        py += 16;
    }
    txt(&fonts::Font2, C_GRID, CX, SCRH - 40, middle_center, "PWR / B : retour");
}

// ───────────────────────── IPS (top attaquants) ───────────────────────
void drawIPs() {
    hudFrame();
    txt(&fonts::FreeSansBold9pt7b, C_TEAL, CX, 50, middle_center, "TOP ATTACKERS");
    if (g_topCount == 0) { txt(&fonts::Font2, C_DIM, CX, CY, middle_center, "no source yet"); return; }
    int ord[MAX_TOP_IPS]; for (int i = 0; i < g_topCount; i++) ord[i] = i;
    for (int a = 0; a < g_topCount; a++) for (int b = a+1; b < g_topCount; b++) if (topIPs[ord[b]].count > topIPs[ord[a]].count) { int t = ord[a]; ord[a] = ord[b]; ord[b] = t; }
    uint32_t mx = 1; for (int i = 0; i < g_topCount; i++) if (topIPs[i].count > mx) mx = topIPs[i].count;
    int y = 80, lh = 30, shown = 0;
    for (int i = 0; i < g_topCount && shown < 9; i++, shown++) {
        char ip[16]; uint32ToIP(topIPs[ord[i]].ip, ip);
        txtf(&fonts::Font2, C_TXT, 78, y, middle_left, "%s", ip);
        // barre bornee a [248..336] ; le compteur a sa zone a droite (>=348) -> pas de chevauchement
        int bw = (int)(88.0f * topIPs[ord[i]].count / mx); if (bw > 88) bw = 88;
        cv->fillSmoothRoundRect(248, y - 4, bw + 1, 10, 2, i == 0 ? C_RED : C_BLUE);
        txtf(&fonts::Font2, C_DIM, 402, y, middle_right, "%lu", (unsigned long)topIPs[ord[i]].count);
        y += lh;
    }
    txt(&fonts::Font2, C_GRID, CX, SCRH - 26, middle_center, "A:vue   B:bas  PWR:haut");
}

// ───────────────────────── init / render ──────────────────────────────
void hudInit() {
    C_BG=rgb(8,11,20); C_PANEL=rgb(15,21,40); C_TEAL=rgb(0,229,160); C_BLUE=rgb(59,130,246);
    C_AMBER=rgb(255,176,32); C_RED=rgb(255,71,87); C_TXT=rgb(210,222,240); C_DIM=rgb(90,100,128);
    C_GRID=rgb(30,40,69); C_WHITE=rgb(240,248,255);
    g_spr.setPsram(true); g_spr.setColorDepth(16);
    g_useSprite = g_spr.createSprite(SCRW, SCRH);
    if (!g_useSprite) { g_spr.setColorDepth(8); g_useSprite = g_spr.createSprite(SCRW, SCRH); }
    cv = g_useSprite ? (LovyanGFX*)&g_spr : (LovyanGFX*)&M5.Display;
    Serial.printf("[HUD] sprite=%s psram=%u\n", g_useSprite ? "OK" : "FAIL", ESP.getFreePsram());
}
static uint32_t g_lastDraw = 0;
void hudRender() {
    uint32_t now = millis();
    // on rafraichit vite si alerte/overview, plus lentement sinon (anti-scintillement)
    uint32_t period = (g_view == SV_OVERVIEW || now < g_attackFlashUntil) ? 60 : 120;
    if (now - g_lastDraw < period) return;
    g_lastDraw = now;
    switch (g_view) {
        case SV_SPLASH:   drawSplash();   break;
        case SV_OVERVIEW: drawOverview(); break;
        case SV_STATUS:   drawStatus();   break;
        case SV_HEATMAP:  drawHeatmap();  break;
        case SV_PORTS:    drawPorts();    break;
        case SV_IPS:      drawIPs();      break;
        case SV_FEED:     drawFeed();     break;
        case SV_DETAIL:   drawDetail();   break;
    }
    if (g_useSprite) g_spr.pushSprite(0, 0);
}
