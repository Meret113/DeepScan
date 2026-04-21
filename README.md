# DeepScan | Cloud & Signature Intelligence

**DeepScan** is a proactive security scanner designed for automated threat detection and system auditing. It combines local signature-based analysis with cloud intelligence.

## 🚀 Key Features
* **Dual-Engine Scanning:** Supports local analysis using **YARA rules** and cloud-based scanning via **VirusTotal API**.
* **Quarantine Manager:** Securely isolates threats with a restoration feature powered by JSON-based path mapping.
* **Multi-threaded Architecture:** Scans are performed in background threads to ensure UI responsiveness.
* **Automated Updates:** Built-in logic to fetch and compile the latest YARA signatures from remote repositories.
* **Multi-language Support:** Interface available in **English, Russian, and Turkmen**.

## 🛠 Tech Stack
* **Language:** Python 3.x
* **GUI:** CustomTkinter (Modern Dark UI)
* **Security:** YARA (yara-python), VirusTotal API v2
* **DevOps:** Logging, Dotenv for API key management, JSON for state persistence

## 📂 Project Status
*Currently in active development. Core scanning logic and quarantine systems are fully operational.*
