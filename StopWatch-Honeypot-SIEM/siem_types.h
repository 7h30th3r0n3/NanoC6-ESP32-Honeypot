// ============================================================================
//  siem_types.h  -  types partages HoneypotSIEM (header inclus -> auto-proto OK)
// ============================================================================
#pragma once
#include <Arduino.h>
#include <ESPAsyncWebServer.h>   // type AsyncWebServerRequest connu avant l'auto-prototypage

#define SIEM_PAYLOAD 64
#define PORT_COUNT   14
#define MAX_TOP_IPS  16
#define FEED_N          120       // fallback RAM interne si pas de PSRAM
#define EVENT_CAP       6000      // journal en PSRAM (profondeur d'affichage/scroll)
#define FLASH_EVT_CAP   40000     // journal persistant (anneau sur la partition FAT)
#define MIN_BUCKETS     60        // 60 minutes glissantes (anneau radial)
#define WK_DAYS         7         // heatmap hebdo : 7 jours
#define WK_HOURS        24        // x 24 heures

struct EventRecord {
    uint32_t ms;               // millis() de capture (pour l'age)
    uint32_t ip;
    uint16_t port;
    char     payload[SIEM_PAYLOAD];
};

struct TopIPEntry { uint32_t ip; uint32_t count; };

// Vues : SPLASH -> [OVERVIEW STATUS HEATMAP PORTS IPS FEED] cyclables au swipe,
// DETAIL = sous-vue ouverte depuis FEED (modal "Event Details").
enum SView : uint8_t { SV_SPLASH, SV_OVERVIEW, SV_STATUS, SV_HEATMAP, SV_PORTS, SV_IPS, SV_FEED, SV_DETAIL };
#define SV_CYCLE_LO  SV_OVERVIEW
#define SV_CYCLE_HI  SV_FEED
