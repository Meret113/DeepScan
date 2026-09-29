# ☁️ DeepScan | Cloud & Signature Intelligence

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-blueviolet.svg)
![Architecture](https://img.shields.io/badge/Architecture-Modular-orange.svg)

**DeepScan** is a proactive security scanner designed for automated threat detection and system auditing. It combines local signature-based analysis with cloud intelligence.

---

## 🚀 Key Features

- 🔍 **Dual-Engine Scanning**: Supports local analysis using **YARA rules** and cloud-based scanning via **VirusTotal API**.
- 🔐 **Quarantine Manager**: Securely isolates threats with a restoration feature powered by JSON-based path mapping.
- ⚡ **Multi-threaded Architecture**: Scans are performed in background threads to ensure UI responsiveness.
- 🔄 **Automated Updates**: Built-in logic to fetch and compile the latest YARA signatures from remote repositories.
- 🌐 **Multi-language Support**: Interface available in **English**, **Russian**, and **Turkmen**.

---

## 🏗️ Project Architecture

```text
DeepScan/
├── src/
│   └── deepscan/
│       ├── config.py         # Configuration & UI Translations
│       ├── core/             # Business Logic Layer
│       │   ├── yara_engine.py# YARA Engine Wrapper
│       │   └── quarantine.py # Quarantine Manager
│       └── ui/               # Presentation Layer
│           └── app.py        # CustomTkinter GUI Application
├── tests/                    # Unit tests suite
├── .env.example              # Sample environment template
├── .gitignore                # Git exclusions
├── main.py                   # Application Entrypoint
└── requirements.txt          # Dependencies
