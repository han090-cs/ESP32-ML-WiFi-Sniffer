/*
 * Project: ML-Ready Wi-Fi Telemetry Sniffer
 * Device: ESP32 / ESP32-S3
 * Description: A low-power, stealthy Wi-Fi sniffer that aggregates raw probe requests 
 *              into Machine Learning ready features (Duration, Hit Count, Mean RSSI, etc.)
 *              and serves a Captive Portal web dashboard.
 */

#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <esp_wifi.h>
#include <map>
#include <DNSServer.h> // Added for Captive Portal

// --- Hardware Config ---
// Note for ESP32-S3 users: Change this to your specific LED pin. 
// Many S3 boards use Pin 39, 48 (RGB), or require an external LED.
#define STATUS_LED 4 

// --- AP & Server Config ---
IPAddress apIP(192, 168, 4, 1);
WebServer server(80);
DNSServer dnsServer;
const byte DNS_PORT = 53;

#define MAX_TRACKED_DEVICES 300       // Max devices to track in RAM simultaneously
#define FLUSH_INTERVAL_SEC 30         // Batch write to flash every 30 seconds
#define MAX_FILE_SIZE (5 * 1024 * 1024) // 5MB Max storage

// --- Machine Learning Telemetry Structure ---
typedef struct {
  uint32_t first_seen;
  uint32_t last_seen;
  uint16_t hit_count;
  int16_t rssi_sum;
  int8_t max_rssi;
  uint8_t channel;
  uint16_t last_seq;
  char oui[9]; // Vendor OUI "XX:XX:XX"
} ml_device_t;

typedef struct {
  uint8_t mac[6];
  int8_t rssi;
  uint8_t channel;
  uint16_t seq_num;
  uint32_t timestamp;
} raw_pkt_t;

QueueHandle_t packetQueue;
std::map<uint64_t, ml_device_t> deviceRegistry;

unsigned long lastFlushTime = 0;
unsigned long lastHopTime = 0;
uint8_t currentChannel = 1;
bool memoryFull = false;
bool stealthMode = false;
String liveJsonData = "{}";

// --- Modern Web Dashboard (English) ---
const char* htmlPage PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ML Telemetry Node</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0b0f19; color: #f8fafc; text-align: center; margin: 0; padding: 20px; }
    .card { background: #151d30; padding: 25px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); max-width: 650px; margin: auto; }
    h2 { color: #38bdf8; margin: 0 0 5px 0; letter-spacing: 1px; }
    p { color: #94a3b8; font-size: 14px; margin-top: 0; }
    .badge { background: #047857; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
    .btn-group { margin: 20px 0; display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; }
    button { padding: 12px 18px; font-weight: bold; cursor: pointer; border: none; border-radius: 6px; transition: 0.2s; }
    .btn-dl { background: #10b981; color: white; }
    .btn-dl:hover { background: #059669; }
    .btn-clr { background: #ef4444; color: white; }
    .btn-clr:hover { background: #dc2626; }
    .btn-st { background: #334155; color: white; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
    th, td { border-bottom: 1px solid #1e293b; padding: 10px; text-align: left; }
    th { background: #1e293b; color: #94a3b8; text-transform: uppercase; font-size: 12px; }
    .mono { font-family: monospace; color: #fbbf24; }
  </style>
</head>
<body>
  <div class="card">
    <h2>📡 ML-Ready Sensor Node</h2>
    <p>Cold State <span class="badge">80MHz</span> Low-Power Profile</p>
    
    <div class="btn-group">
      <button class="btn-dl" onclick="window.location.href='/download'">📥 Export Dataset</button>
      <button class="btn-clr" onclick="if(confirm('Erase all stored telemetry data?')) window.location.href='/clear'">🗑 Clear Storage</button>
      <button id="stBtn" class="btn-st" onclick="toggleStealth()">🌙 Stealth Mode</button>
    </div>

    <table>
      <thead><tr><th>Vendor OUI</th><th>Hits</th><th>Avg Signal</th><th>Dwell(s)</th><th>Ch</th></tr></thead>
      <tbody id="liveTable">
        <tr><td colspan="5" style="text-align:center; padding: 20px;">Scanning 802.11 spectrum...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    function toggleStealth() {
      fetch('/stealth').then(r => r.text()).then(st => {
        let btn = document.getElementById('stBtn');
        if(st === 'ON') {
          btn.innerHTML = '🕵️ Stealth: ON';
          btn.style.background = '#000000';
        } else {
          btn.innerHTML = '🌙 Stealth Mode';
          btn.style.background = '#334155';
        }
      });
    }

    setInterval(function() {
      fetch('/live').then(r => r.json()).then(d => {
        if(d.oui) {
          let html = `<tr>
                        <td class='mono'>${d.oui}</td>
                        <td>${d.hits}</td>
                        <td>${d.mean_rssi} dBm</td>
                        <td>${d.dur}s</td>
                        <td>CH ${d.ch}</td>
                      </tr>`;
          document.getElementById("liveTable").innerHTML = html;
        }
      }).catch(e => {});
    }, 1500);
  </script>
</body>
</html>
)rawliteral";

// --- MAC Filtering (Exclude Randomized MACs) ---
inline bool isRealMac(uint8_t firstOctet) {
  uint8_t secondNibble = firstOctet & 0x0F;
  return !(secondNibble == 0x02 || secondNibble == 0x06 || secondNibble == 0x0A || secondNibble == 0x0E);
}

// --- Frame Sniffer Callback ---
void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || memoryFull) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;

  if (payload[0] == 0x40) { // Probe Request Frame
    if (isRealMac(payload[10])) {
      raw_pkt_t r_pkt;
      memcpy(r_pkt.mac, payload + 10, 6);
      r_pkt.rssi = pkt->rx_ctrl.rssi;
      r_pkt.channel = pkt->rx_ctrl.channel;
      
      uint16_t seq = payload[22] | (payload[23] << 8);
      r_pkt.seq_num = (seq >> 4); 
      r_pkt.timestamp = millis() / 1000;

      xQueueSendFromISR(packetQueue, &r_pkt, NULL);
    }
  }
}

void setup() {
  Serial.begin(115200);

  // 1. Underclock CPU to 80MHz to prevent thermal throttling
  setCpuFrequencyMhz(80);

  pinMode(STATUS_LED, OUTPUT);
  digitalWrite(STATUS_LED, LOW);

  packetQueue = xQueueCreate(150, sizeof(raw_pkt_t));

  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS Mount Failed");
    return;
  }

  // 2. Setup Access Point
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP("ML_Telemetry_Node", "12345678");
  
  // Reduce TX Power for thermal management
  WiFi.setTxPower(WIFI_POWER_8_5dBm); 

  // 3. Start Captive Portal DNS
  dnsServer.start(DNS_PORT, "*", apIP);

  // 4. Web Server Routes
  server.on("/", []() { server.send(200, "text/html", htmlPage); });
  server.on("/live", []() { server.send(200, "application/json", liveJsonData); });
  
  server.on("/stealth", []() {
    stealthMode = !stealthMode;
    if (stealthMode) digitalWrite(STATUS_LED, LOW);
    server.send(200, "text/plain", stealthMode ? "ON" : "OFF");
  });

  server.on("/download", []() {
    File file = LittleFS.open("/ml_dataset.csv", "r");
    if (!file) { server.send(404, "text/plain", "No Data Found"); return; }
    server.sendHeader("Content-Disposition", "attachment; filename=\"ml_features.csv\"");
    server.streamFile(file, "text/csv");
    file.close();
  });

  server.on("/clear", []() {
    LittleFS.remove("/ml_dataset.csv");
    deviceRegistry.clear();
    memoryFull = false;
    digitalWrite(STATUS_LED, LOW);
    server.send(200, "text/html", "<meta charset='utf-8'><h3>Storage Cleared. <a href='/'>Go Back</a></h3>");
  });

  // Redirect all unknown requests to Captive Portal
  server.onNotFound([]() {
    server.sendHeader("Location", String("http://") + apIP.toString(), true);
    server.send(302, "text/plain", "");
  });

  server.begin();

  // Create CSV Header if not exists
  if (!LittleFS.exists("/ml_dataset.csv")) {
    File file = LittleFS.open("/ml_dataset.csv", "w");
    if (file) {
      file.println("MAC_Hash,OUI,First_Seen,Last_Seen,Duration,Hit_Count,Mean_RSSI,Max_RSSI,Last_Channel,Last_Seq");
      file.close();
    }
  }

  // Start Sniffer
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
}

void loop() {
  dnsServer.processNextRequest(); // Handle Captive Portal
  server.handleClient();          // Handle Web Dashboard

  unsigned long now = millis();
  
  // Channel Hopping (300ms intervals to save CPU)
  if (now - lastHopTime > 300) {
    lastHopTime = now;
    currentChannel = (currentChannel % 13) + 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }

  // Packet Processing
  raw_pkt_t p;
  if (xQueueReceive(packetQueue, &p, 10 / portTICK_PERIOD_MS) == pdTRUE) {
    if (memoryFull) return;

    if (!stealthMode) digitalWrite(STATUS_LED, HIGH);

    uint64_t macKey = 0;
    for (int i = 0; i < 6; i++) macKey = (macKey << 8) | p.mac[i];

    // Aggregation Logic
    if (deviceRegistry.find(macKey) == deviceRegistry.end()) {
      if (deviceRegistry.size() < MAX_TRACKED_DEVICES) {
        ml_device_t dev;
        dev.first_seen = p.timestamp;
        dev.last_seen = p.timestamp;
        dev.hit_count = 1;
        dev.rssi_sum = p.rssi;
        dev.max_rssi = p.rssi;
        dev.channel = p.channel;
        dev.last_seq = p.seq_num;
        snprintf(dev.oui, sizeof(dev.oui), "%02X:%02X:%02X", p.mac[0], p.mac[1], p.mac[2]);
        deviceRegistry[macKey] = dev;
      }
    } else {
      deviceRegistry[macKey].last_seen = p.timestamp;
      deviceRegistry[macKey].hit_count++;
      deviceRegistry[macKey].rssi_sum += p.rssi;
      if (p.rssi > deviceRegistry[macKey].max_rssi) {
        deviceRegistry[macKey].max_rssi = p.rssi;
      }
      deviceRegistry[macKey].channel = p.channel;
      deviceRegistry[macKey].last_seq = p.seq_num;
    }

    // Update Live Dashboard
    char liveBuf[160];
    int meanR = deviceRegistry[macKey].rssi_sum / deviceRegistry[macKey].hit_count;
    uint32_t dur = deviceRegistry[macKey].last_seen - deviceRegistry[macKey].first_seen;
    snprintf(liveBuf, sizeof(liveBuf), 
             "{\"oui\":\"%s\",\"hits\":%d,\"mean_rssi\":%d,\"dur\":%d,\"ch\":%d}",
             deviceRegistry[macKey].oui, deviceRegistry[macKey].hit_count, meanR, dur, p.channel);
    liveJsonData = String(liveBuf);

    if (!stealthMode) {
      delay(2);
      digitalWrite(STATUS_LED, LOW);
    }
  }

  // Batch Write to Flash Memory (Every 30 seconds)
  if ((now / 1000) - lastFlushTime >= FLUSH_INTERVAL_SEC) {
    lastFlushTime = now / 1000;

    if (deviceRegistry.size() > 0) {
      File file = LittleFS.open("/ml_dataset.csv", "a");
      if (file) {
        if (file.size() >= MAX_FILE_SIZE) {
          memoryFull = true;
          if(!stealthMode) digitalWrite(STATUS_LED, HIGH);
        } else {
          for (auto const& [key, dev] : deviceRegistry) {
            float mean_rssi = (float)dev.rssi_sum / dev.hit_count;
            uint32_t duration = dev.last_seen - dev.first_seen;
            uint32_t macHash = (uint32_t)(key & 0xFFFFFFFF); // Anonymized Hash

            file.printf("%08X,%s,%u,%u,%u,%u,%.1f,%d,%u,%u\n",
                        macHash, dev.oui, dev.first_seen, dev.last_seen,
                        duration, dev.hit_count, mean_rssi, dev.max_rssi,
                        dev.channel, dev.last_seq);
          }
        }
        file.close();
      }
    }
  }
}