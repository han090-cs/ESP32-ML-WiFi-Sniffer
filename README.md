# ESP32-ML-WiFi-Sniffer
A low-power, ML-ready Wi-Fi telemetry sniffer for ESP32/ESP32-S3

# 📡 ML-Ready Wi-Fi Telemetry Node (ESP32/ESP32-S3)

A highly optimized, low-power Wi-Fi sniffer designed specifically for Data Scientists and Security Researchers. Instead of just dumping raw MAC addresses, this firmware aggregates 802.11 Probe Requests directly in RAM and exports a **Machine Learning-ready dataset** containing spatial and behavioral features.

## ✨ Key Features
* **Cold State Architecture:** Underclocked to 80MHz with throttled channel hopping. Runs 24/7 on a battery bank without thermal throttling.
* **Captive Portal:** No IP typing required. Connect to the node's Wi-Fi, and the dashboard pops up automatically.
* **In-Memory ML Aggregation:** Calculates Dwell Time, Hit Count, Mean RSSI, and Extracts Vendor OUI on the fly.
* **Batch Storage (LittleFS):** Reduces Flash I/O by flushing aggregated arrays to storage every 30 seconds. Max cap set to 5MB (months of data).
* **Stealth Mode:** Toggle LED activity off via the web interface for covert field operations.
* **Real-MAC Filter:** Automatically drops iOS/Android randomized MAC addresses, logging only genuine hardware footprints.

## 📦 Extracted Features (ml_features.csv)
Ready for Pandas, Scikit-Learn (DBSCAN, K-Means, Isolation Forest):
`MAC_Hash, OUI, First_Seen, Last_Seen, Duration, Hit_Count, Mean_RSSI, Max_RSSI, Last_Channel, Last_Seq`

## 🚀 Installation & Setup
1. Open the `.ino` file in **Arduino IDE**.
2. Install the ESP32 Board Manager by Espressif.
3. Select your board (e.g., `ESP32S3 Dev Module`).
   * **Important for S3 N16R8:** Set Flash Size to `16MB` and Partition Scheme to something with a large LittleFS partition (e.g., `16M Flash (3MB APP/9.9MB FATFS)`).
4. Upload the sketch.

## 📱 How to Use
1. Power the ESP32 via a power bank or 3.7V LiPo.
2. Connect your phone/laptop to the Wi-Fi network: **`ML_Telemetry_Node`** (Password: `12345678`).
3. The Web Dashboard will open automatically (Captive Portal).
4. Click **Download Dataset** to get the CSV file for Python analysis.

## 📜 License
MIT License. Feel free to fork and build upon this for your Data Science projects!
