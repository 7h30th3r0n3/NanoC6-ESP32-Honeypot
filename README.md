<div align="center">

## M5Stack NanoC6 ESP32 Honeypot

<img alt="logo" src="./m5nanohoney.png" width="33%" height="33%"/>
  
This project is a standalone Multi-port honeypot for NanoC6 and ESP32 platform. It emulates a realistic Linux shell environment on telnet and multiple port banner to attract and analyze unauthorized access attempts. It features a full web-based configuration UI, persistent storage using SPIFFS, and webhook-based alerting that can be integrated with Discord, Telegram, Signal, WhatsApp, or SIEM platforms like ELK.
  
  Here the demo video on Evil-Cardputer:
  
  <a href="https://youtube.com/shorts/P73wcEghjso" >
      <img alt="Demo Video" src="https://img.youtube.com/vi/P73wcEghjso/0.jpg" width="33%" height="33%"/>
  </a>

Thanks to hosseios for the video ! 


<table>
  <tr>
    <td align="center">
      <strong>Web Interface (WebUI)</strong><br>
      <img src="./WebUi-1.png" width="300px">
    </td>
    <td align="center">
      <strong>What an Attacker Sees (Nmap Scan)</strong><br>
      <img src="./nmap.png" width="900px">
    </td>
  </tr>
  <tr>
    <td align="center">
      <strong>Real-time Alerts on Discord</strong><br>
      <img src="./WebHookDiscord.jpg" width="200px">
    </td>
    <td align="center">
      <strong>5 Days of ELK Data Collection</strong><br>
      <img src="./honeypot.png" width="900px">
    </td>
  </tr>
</table>

</div>

---

## ✅ Features

- Interactive Telnet honeypot server on port 23
- Fake file system structure with secrets to lure attackers
- Realistic Linux shell simulation with multiple commands supported (pwd, whoami, cat, ls, cd, apt, etc.)  
- Banner grabbing for port 21,22,25,53,110,143,443,445,3306,3389,5900,8080  
- Automatic logging of all client inputs with timestamp and IP address
- Webhooks for real-time alerts (Discord, Telegram, Signal, WhatsApp, SIEM, etc.)
- Web-based configuration panel (SSID, password, port selection and webhook configuration)
- SPIFFS-based file system for persistent config and logs
- Modular code, compatible with any ESP32 board

---
## 🧩 Compatible Devices

Tested and confirmed working on:

- **Atom C6** (one of the smallest): [Buy here](https://shop.m5stack.com/products/m5stack-nanoc6-dev-kit?ref=7h30th3r0n3)
- **M5Stack AtomS3**: [Buy here](https://s.click.aliexpress.com/e/_DnDXSKJ) or [Buy here](https://shop.m5stack.com/products/atoms3-dev-kit-w-0-85-inch-screen?ref=7h30th3r0n3)
- **M5Stack Atom Lite**: [Buy here](https://s.click.aliexpress.com/e/_Dm0e95D)
- **ESP32-C3** (with external antenna): [Buy here](https://s.click.aliexpress.com/e/_DD1yibp) (Be carefull to select sets WITH antenna) 
- **M5Stack StopWatch** (466x466 round AMOLED, full on-screen SIEM dashboard): see the `StopWatch-Honeypot-SIEM` folder

Any ESP32 Dev Board should work (e.g. DevKitC, NodeMCU-32S, Wemos D1 R32)  
please report no working devices 

---

## 🕹️ StopWatch SIEM edition

The `StopWatch-Honeypot-SIEM` folder is a dedicated build for the M5Stack StopWatch (ESP32-S3, 466x466 round AMOLED). It runs the same 14 port decoys and the full web dashboard, plus a complete circular SIEM UI directly on the watch screen, always on:

- Views: overview (60 min radial ring, port donut, threat counter, intrusion ping), system status, weekly heatmap (7d x 24h radial), port activity, top attackers, live feed, per event detail. Button driven navigation (BtnA cycles views, BtnB scrolls and selects, PWR back), touch as a bonus.
- Storage: event journal in PSRAM (ring of 6000) with persistence on the 9.9 MB FAT partition (up to 40000 events) plus aggregated stats, all surviving reboot.
- Web UI on port 80 (dashboard + `/setup` config page) stays available on the always on access point at 192.168.4.1, and the watch joins your LAN when configured.
- Non blocking honeypot handlers and USB CDC so the on-screen navigation stays smooth while under attack.

Build: Arduino, board M5Stack StampS3, 16MB flash, partition `app3M_fat9M_16MB`, OPI PSRAM. Needs M5Unified, ESP Async WebServer and Async TCP.

---

## ⚙️ Installation

1. Flash this firmware on any ESP32 using Arduino IDE or PlatformIO
2. On first boot, ESP32 will create a Wi-Fi access point:
   - SSID: HoneypotConfig
   - Password: HoneyPotConfig123
3. Connect and open `http://192.168.4.1` to configure
4. After saving the configuration, the ESP32 will reboot and connect to your Wi-Fi
5. Telnet honeypot starts on port 23, listening for attackers
6. All captured inputs will be logged and optionally sent to your webhook

If the AP is not near it, mode configuration is enabled and web portal is accessible.

Note : NanoC6 can be put in configuration mode by olding the button when the white light is ON at boot.

--- 

## 🌳 LED Behavior Decision Tree for NanoC6

```
                        🔵 Device Boot
                              │
                              v
                    ⚪ LED: White (3 seconds)
                              │
                              v
                   Is Button A stay pressed?
                        /           \
                       /             \
                ⬅️ No                  Yes ➡️
           🌈 LED Rainbow        🔵 LED Blue (WebUI configuration Mode)
                  │
                  v
        Try connecting to Wi-Fi
                  │
                  v
         Wi-Fi connection success?
              /              \
             /                \
        ⬅️ No                   Yes ➡️
 🔵 LED Blue flashing ×3    🟩 LED Green (Honeypot Active)
      then fix blue               │
(WebUI configuration Mode)        |
                                  v
                       Incoming connection?
                             /        \
                            /          \
                       ⬅️ No             Yes ➡️
                    (Stay Green)   🔴 LED Red flashes ×2
                                          then Red fixed
```

---

## 📦 Dependencies

- ESPAsyncWebServer
- ArduinoJson
- SPIFFS (built-in)
- WiFi (built-in)

Make sure to install the required libraries via Library Manager or PlatformIO.

---

## 📁 SPIFFS Structure

/config.json       → Contains Wi-Fi and webhook settings  
/honeypot_logs.txt → Stores captured login attempts and commands  
/index.html        → Web-based configuration UI  

All files are automatically created at first boot if missing.

---

## 📡 Webhook Format

Example payload (JSON, sent as POST):

{
  "content": "📡 Honeypot\n🔍 IP: 192.168.1.5\n💻 Command: `cat /etc/passwd`"
}

You can route this to:

- Discord (via Webhook URL)
- Telegram (via Bot API Gateway)
- Signal (via relay server or bridge)
- WhatsApp (via Business API)
- SIEMs or custom log collectors

---

## 🧠 Emulated Commands

Basic commands:
- pwd, whoami, uptime, hostname, uname -a, id, lscpu, df -h, free -h, env, set, history

Filesystem:
- ls, ls -l, cd, cat, mkdir, rm, rmdir, touch, chmod, chown

Networking:
- ifconfig, ip addr, ping, netstat -an, curl, wget

Services:
- service <name> start/stop/status
- systemctl status/start/stop

Package manager:
- apt-get update, apt-get install

Privilege escalation:
- sudo (with denial)

Fake files like `/etc/passwd`, `secrets.txt`, `mysql_credentials.txt`, etc. are included to bait the attacker.

---

## 🛡️ Usage Notes

This honeypot is designed for educational and defensive cybersecurity purposes. Do not expose to the internet without proper upstream firewalling or network segmentation. It is not intended to replace full honeynet frameworks like Cowrie, but serves as a lightweight ESP32-based trap canary.

---

## 📄 License

MIT License - Use freely with attribution.
