import os
from dotenv import load_dotenv

# Корень проекта (папка, где лежит main.py) и папка с данными, не зависящие от места запуска
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

load_dotenv(os.path.join(BASE_DIR, '.env'))

# --- Цветовая палитра (Cloudflare Style) ---
CF_ORANGE = "#F38020"
CF_ORANGE_HOVER = "#c46212"

COLOR_SAFE = "#28a745"
COLOR_DANGER = "#dc3545"
COLOR_WARN = "#ffc107"
COLOR_NEUTRAL = "#17a2b8"

# --- Настройки API и Пути ---
VIRUSTOTAL_API_KEY = os.getenv('VT_API_KEY')
VT_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
YARA_RULES_PATH = os.path.join(DATA_DIR, 'yara-rules-full.yar')
QUARANTINE_FOLDER = os.path.join(DATA_DIR, 'quarantine')
QUARANTINE_MAP_FILE = os.path.join(DATA_DIR, 'quarantine_map.json')
VERSION_FILE = os.path.join(DATA_DIR, 'db_version.txt')
LOG_FILE = os.path.join(DATA_DIR, 'deepscan_full.log')
YARA_API_URL = 'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest'

# Если прокси не указан в .env, запросы идут напрямую через интернет
PROXY_URL = os.getenv('PROXY_URL', '')
PROXY_CONFIG = {'https': PROXY_URL, 'http': PROXY_URL} if PROXY_URL else None

# --- Локализация ---
TRANSLATIONS = {
    "en": {
        "nav_dash": "Overview", "nav_scan": "Security Scanner", "nav_quar": "Quarantine", "nav_set": "Settings",
        "lbl_target": "Target Selection", "btn_file": "Select File", "btn_folder": "Select Folder",
        "btn_yara": "Start Scan (YARA)", "btn_vt": "Cloud Scan (VirusTotal)",
        "lbl_status": "System Status", "lbl_db": "Rules Database",
        "header_engine": "Engine", "header_result": "Detection",
        "theme_label": "Appearance", "lang_label": "Language",
        "safe": "Secure", "malicious": "Threat Detected", "scanning": "Scanning...",
        "dash_title": "Security Overview", "scan_title": "Threat Intelligence",
        "quar_title": "Quarantine Manager", "set_title": "Preferences",
        "net_status": "Network Status",
        "about_header": "About DeepScan", "dev_by": "Developed by:", "version": "Version:", "update_btn": "Update Database",
        "status_check": "Checking...", "status_risk": "System at Risk", "status_ok": "Protected",
        "btn_restore": "Restore", "btn_delete": "Delete"
    },
    "ru": {
        "nav_dash": "Обзор", "nav_scan": "Сканер безопасности", "nav_quar": "Карантин", "nav_set": "Настройки",
        "lbl_target": "Выбор цели", "btn_file": "Выбрать файл", "btn_folder": "Выбрать папку",
        "btn_yara": "Запуск (YARA)", "btn_vt": "Облачный скан (VirusTotal)",
        "lbl_status": "Статус системы", "lbl_db": "База сигнатур",
        "header_engine": "Антивирус", "header_result": "Результат",
        "theme_label": "Оформление", "lang_label": "Язык",
        "safe": "Безопасно", "malicious": "Угроза", "scanning": "Сканирование...",
        "dash_title": "Обзор безопасности", "scan_title": "Поиск угроз",
        "quar_title": "Управление карантином", "set_title": "Настройки",
        "net_status": "Статус сети",
        "about_header": "О программе", "dev_by": "Разработчик:", "version": "Версия:", "update_btn": "Обновить базы",
        "status_check": "Проверка...", "status_risk": "Есть риски", "status_ok": "Защищено",
        "btn_restore": "Восстановить", "btn_delete": "Удалить"
    },
    "tk": {
        "nav_dash": "Gözden geçiriş", "nav_scan": "Howpsuzlyk skaneri", "nav_quar": "Karantin", "nav_set": "Sazlamalar",
        "lbl_target": "Faýl/Papka saýla", "btn_file": "Faýl saýla", "btn_folder": "Papka saýla",
        "btn_yara": "Barlag (YARA)", "btn_vt": "Bulut barlag (VirusTotal)",
        "lbl_status": "Ulgam ýagdaýy", "lbl_db": "Wirus bazasy",
        "header_engine": "Antiwirus", "header_result": "Netije",
        "theme_label": "Daşky görnüş", "lang_label": "Dil",
        "safe": "Arassa", "malicious": "Howply", "scanning": "Barlanýar...",
        "dash_title": "Howpsuzlyk umumy", "scan_title": "Howp gözlegi",
        "quar_title": "Karantin dolandyryş", "set_title": "Sazlamalar",
        "net_status": "Internet ýagdaýy",
        "about_header": "Programma barada", "dev_by": "Düzüiji:", "version": "Wersiýa:", "update_btn": "Bazany täzele",
        "status_check": "Barlanylýar...", "status_risk": "Howp bar", "status_ok": "Goragly",
        "btn_restore": "Dikelt", "btn_delete": "Poz"
    }
}