// ============================================================================
//  siem_store.ino  -  Stockage HoneypotSIEM
//  - Journal des events en PSRAM (anneau EVENT_CAP, profondeur d'affichage)
//  - Persistance sur la partition FAT 9.9Mo (FFat) : anneau d'events
//    FLASH_EVT_CAP + blob de stats agregees -> survit au reboot.
// ============================================================================
#include <FFat.h>
#include <esp_heap_caps.h>
#include "siem_types.h"

static const char* EVT_PATH   = "/evt.ring";
static const char* STATS_PATH = "/stats.bin";
static const uint32_t STORE_MAGIC = 0x53494556;   // "SIEV"
static const uint32_t HDR_SIZE    = 64;

struct RingHdr { uint32_t magic, cap, head, count; };
struct StatsBlob {
    uint32_t  magic;
    uint32_t  total;
    uint32_t  portCounts[PORT_COUNT];
    uint8_t   topCount;
    TopIPEntry topIPs[MAX_TOP_IPS];
    uint16_t  weekly[WK_DAYS][WK_HOURS];
};

static uint32_t g_ringHead = 0;                   // prochain slot d'ecriture (0..cap-1)
static const uint32_t REC = sizeof(EventRecord);
static File     g_evtFile;                        // handle du journal garde OUVERT (perf)
static bool     g_evtHdrDirty = false;            // en-tete a reflusher
static uint32_t g_evtLastFlush = 0;

// ── alloc du journal en PSRAM (fallback RAM interne) ───────────────────
void storeAllocRing() {
    g_feed = (EventRecord*) heap_caps_malloc((size_t)EVENT_CAP * REC, MALLOC_CAP_SPIRAM);
    if (g_feed) { g_feedCap = EVENT_CAP; g_feedPsram = true; }
    else { g_feed = (EventRecord*) malloc((size_t)FEED_N * REC); g_feedCap = g_feed ? FEED_N : 0; g_feedPsram = false; }
    g_feedHead = 0; g_feedCount = 0;
    Serial.printf("[STORE] ring=%s cap=%lu\n", g_feedPsram ? "PSRAM" : "RAM", (unsigned long)g_feedCap);
}

static void writeRingHdr() {
    File f = FFat.open(EVT_PATH, "r+"); if (!f) f = FFat.open(EVT_PATH, "w");
    if (!f) return;
    RingHdr h = { STORE_MAGIC, FLASH_EVT_CAP, g_ringHead, g_flashEvents };
    f.seek(0); f.write((uint8_t*)&h, sizeof(h)); f.close();
}
static void initRingFile() {
    if (g_evtFile) g_evtFile.close();
    File f = FFat.open(EVT_PATH, "w");
    if (!f) return;
    RingHdr h = { STORE_MAGIC, FLASH_EVT_CAP, 0, 0 };
    uint8_t pad[HDR_SIZE] = {0}; memcpy(pad, &h, sizeof(h));
    f.write(pad, HDR_SIZE); f.close();
    g_ringHead = 0; g_flashEvents = 0;
}

// ── stats agregees ─────────────────────────────────────────────────────
void storeSaveStats() {
    if (!g_fsOk) return;
    StatsBlob b; memset(&b, 0, sizeof(b));
    b.magic = STORE_MAGIC; b.total = g_total;
    memcpy(b.portCounts, portCounts, sizeof(portCounts));
    b.topCount = g_topCount; memcpy(b.topIPs, topIPs, sizeof(topIPs));
    memcpy(b.weekly, weeklyBuckets, sizeof(weeklyBuckets));
    File f = FFat.open(STATS_PATH, "w"); if (!f) return;
    f.write((uint8_t*)&b, sizeof(b)); f.close();
}
static void loadStats() {
    File f = FFat.open(STATS_PATH, "r"); if (!f) return;
    StatsBlob b; if (f.read((uint8_t*)&b, sizeof(b)) == (int)sizeof(b) && b.magic == STORE_MAGIC) {
        g_total = b.total; memcpy(portCounts, b.portCounts, sizeof(portCounts));
        g_topCount = b.topCount > MAX_TOP_IPS ? MAX_TOP_IPS : b.topCount;
        memcpy(topIPs, b.topIPs, sizeof(topIPs));
        memcpy(weeklyBuckets, b.weekly, sizeof(weeklyBuckets));
    }
    f.close();
}

// ── anneau d'events persistant ─────────────────────────────────────────
// ecrit l'enregistrement sur le handle garde ouvert (seek+write seulement).
// L'en-tete n'est reflushee que periodiquement (storeFlushTick) -> pas de
// open/close FFat par event, la loop ne bloque plus sous bombardement.
void storeEvtAppend(const EventRecord& rec) {
    if (!g_fsOk) return;
    if (!g_evtFile) { g_evtFile = FFat.open(EVT_PATH, "r+"); if (!g_evtFile) { initRingFile(); g_evtFile = FFat.open(EVT_PATH, "r+"); if (!g_evtFile) return; } }
    uint32_t slot = g_ringHead % FLASH_EVT_CAP;
    g_evtFile.seek(HDR_SIZE + (uint32_t)slot * REC);
    g_evtFile.write((const uint8_t*)&rec, REC);
    g_ringHead = (slot + 1) % FLASH_EVT_CAP;
    if (g_flashEvents < FLASH_EVT_CAP) g_flashEvents++;
    g_evtHdrDirty = true;
}
// flush differe de l'en-tete + sync disque (appele depuis la loop, throttle 1s)
void storeFlushTick() {
    if (!g_fsOk || !g_evtHdrDirty || !g_evtFile) return;
    uint32_t now = millis();
    if (now - g_evtLastFlush < 1000) return;
    g_evtLastFlush = now;
    RingHdr h = { STORE_MAGIC, FLASH_EVT_CAP, g_ringHead, g_flashEvents };
    g_evtFile.seek(0); g_evtFile.write((uint8_t*)&h, sizeof(h));
    g_evtFile.flush();
    g_evtHdrDirty = false;
}
// recharge les events recents du flash vers l'anneau PSRAM (ordre chrono)
static void loadRecentEvents() {
    if (!g_fsOk || !g_feed || g_feedCap == 0 || g_flashEvents == 0) return;
    File f = FFat.open(EVT_PATH, "r"); if (!f) return;
    uint32_t n = g_flashEvents < g_feedCap ? g_flashEvents : g_feedCap;
    for (uint32_t j = 0; j < n; j++) {
        uint32_t slot = (g_ringHead - n + j + FLASH_EVT_CAP * 2) % FLASH_EVT_CAP;
        f.seek(HDR_SIZE + (uint32_t)slot * REC);
        if (f.read((uint8_t*)&g_feed[j], REC) != (int)REC) break;
    }
    f.close();
    g_feedCount = n; g_feedHead = n % g_feedCap;
    if (n > 0) { g_lastEvent = g_feed[(g_feedHead - 1 + g_feedCap) % g_feedCap]; g_hasLast = true; }
}

// ── effacement total ───────────────────────────────────────────────────
void storeWipe() {
    if (!g_fsOk) return;
    FFat.remove(STATS_PATH);
    initRingFile();
    storeSaveStats();
}

// ── usage FS (pour l'affichage) ────────────────────────────────────────
void storeFsStats() {
    if (!g_fsOk) return;
    g_fsTotalKB = FFat.totalBytes() / 1024;
    g_fsUsedKB  = FFat.usedBytes() / 1024;
}

// ── init au boot ───────────────────────────────────────────────────────
void storeBegin() {
    storeAllocRing();                                   // PSRAM d'abord (toujours)
    g_fsOk = FFat.begin(true, "/ffat", 10, "ffat");     // format si 1er boot
    if (!g_fsOk) { Serial.println("[STORE] FFat FAIL (RAM-only)"); return; }
    File f = FFat.open(EVT_PATH, "r");
    if (f) { RingHdr h; if (f.read((uint8_t*)&h, sizeof(h)) == (int)sizeof(h) && h.magic == STORE_MAGIC && h.cap == FLASH_EVT_CAP) {
                 g_ringHead = h.head % FLASH_EVT_CAP; g_flashEvents = h.count > FLASH_EVT_CAP ? FLASH_EVT_CAP : h.count; }
             else { f.close(); initRingFile(); f = File(); }
             if (f) f.close(); }
    else initRingFile();
    loadStats();
    loadRecentEvents();
    storeFsStats();
    Serial.printf("[STORE] FFat ok  flashEvt=%lu  used=%luKB/%luKB\n",
                  (unsigned long)g_flashEvents, (unsigned long)g_fsUsedKB, (unsigned long)g_fsTotalKB);
}
