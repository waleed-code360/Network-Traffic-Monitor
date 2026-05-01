Network Traffic Monitoring and Analysis Platform
A web-based application that monitors, logs, and analyzes real-time network traffic using Python (Flask) and Scapy.

Features

Real-Time Packet Capture — Captures live network packets using Scapy
Protocol Detection — Identifies TCP, UDP, ICMP, HTTP, and HTTPS traffic
Port-to-Service Mapping — Maps destination ports to service names (e.g., port 443 → HTTPS)
Packet Filtering — Filter captured packets by protocol, source IP, or destination IP
Live Statistics — Displays total packets, per-protocol counts, and average packet size
Activity Log — Logs all monitoring actions with timestamps
Scrollable Packet Table — Live-updating table with all captured packet details


Project Structure
CN_Project/
│
├── app.py                  ← Python backend (Flask + Scapy)
└── templates/
    └── index.html          ← Frontend (HTML, CSS, JavaScript)

Dataset
This project uses real-time packet sniffing via the Scapy library. No static dataset file is used. Packets are captured live from the active network interface when monitoring is started.

Requirements

Python 3.x
Flask
Flask-CORS
Scapy
Npcap (Windows only — required for Scapy packet capture)

Install dependencies:
bashpip install flask flask-cors scapy

Windows users: Install Npcap before running. Select "Install Npcap in WinPcap API-compatible Mode" during installation.


How to Run

Clone or download this repository
Install the required dependencies (see above)
Run VS Code or terminal as Administrator (required for packet capture)
Navigate to the project folder
Run the backend:

bashpython app.py

Open your browser and go to:

http://127.0.0.1:5000

How to Use
ActionDescriptionStart MonitoringBegins capturing live network packetsStop MonitoringStops packet captureProtocol FilterFilter by TCP, UDP, ICMP, HTTP, or HTTPSSource IP FilterFilter packets by source IP addressDestination IP FilterFilter packets by destination IP addressResetClears all filters and shows all captured packets

Statistics Displayed

Total number of captured packets
Count of TCP, UDP, ICMP, HTTP, and HTTPS packets
Average packet size in bytes


Technologies Used
TechnologyPurposePythonBackend logicFlaskWeb server / APIScapyLive packet captureHTML/CSSFrontend interfaceJavaScript (Fetch API)Live data updates without page refresh

Notes

The application must be run with Administrator privileges for Scapy to access the network interface
Tested on Windows with Wi-Fi interface
Real-time packet table updates every 1 second automatically
