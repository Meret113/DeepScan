import os
import shutil
import threading
import time
import requests
import yara
import zipfile
import io
import logging
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
from dotenv import load_dotenv
import customtkinter as ctk

# ===== КОНФИГУРАЦИЯ =====
load_dotenv()

# --- Цветовая палитра (Cloudflare Style) ---
CF_ORANGE = "#F38020"
CF_ORANGE_HOVER = "#c46212"

# Цвета статусов
COLOR_SAFE = "#28a745"  # Green
COLOR_DANGER = "#dc3545"  # Red
COLOR_WARN = "#ffc107"  # Yellow
COLOR_NEUTRAL = "#17a2b8"  # Blue

# --- Настройки API и Пути ---
VIRUSTOTAL_API_KEY = os.getenv('VT_API_KEY')
VT_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VT_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
YARA_RULES_PATH = 'yara-rules-full.yar'
QUARANTINE_FOLDER = 'quarantine'
QUARANTINE_MAP_FILE = 'quarantine_map.json'  # Файл для памяти путей
VERSION_FILE = 'db_version.txt'
LOG_FILE = 'deepscan_full.log'
YARA_API_URL = 'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest'
PROXY_URL = os.getenv('PROXY_URL', 'http://127.0.0.1:10808')
PROXY_CONFIG = {'https': PROXY_URL, 'http': PROXY_URL}
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
# ===== ЛОГИРОВАНИЕ =====
log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.DEBUG)
logger = logging.getLogger("DeepScan")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)
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
        "about_header": "About DeepScan", "dev_by": "Developed by:", "version": "Version:",
        "update_btn": "Update Database",
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


class GuiLogHandler(logging.Handler):
    """Класс для вывода логов прямо в интерфейс"""

    def __init__(self, text_widget):
        super().__init__()
        self.widget = text_widget
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        msg = self.format(record)

        def append():
            try:
                self.widget.configure(state='normal')
                prefix = "ℹ️"
                tag = "info"
                if record.levelno >= logging.ERROR:
                    prefix = "❌"
                    tag = "error"
                elif record.levelno == logging.WARNING:
                    prefix = "⚠️"
                    tag = "warning"

                self.widget.insert("end", f"{prefix} {msg}\n", tag)
                self.widget.see("end")
                self.widget.configure(state='disabled')
            except Exception:
                pass

        self.widget.after(0, append)


class DeepScanApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        logger.info("========================================")
        logger.info("DeepScan Application Initialized")

        self.lang_code = "ru"
        self.target_path = ctk.StringVar()
        self.db_version = ctk.StringVar(value="Unknown")
        self.system_status_text = ctk.StringVar(value="Checking...")
        self.scan_lock = False
        self.threats_detected_session = 0

        # Загрузка карты карантина
        self.quarantine_map = self.load_quarantine_map()

        # UI Setup
        self.title("DeepScan | Cloud Intelligence")
        self.geometry("1150x780")
        ctk.set_appearance_mode("Dark")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_frames()
        self.change_language("ru")

        # Initial Checks
        self.check_local_db()
        self.update_system_health()  # Запуск проверки статуса
        self.select_frame("dashboard")

    def t(self, key):
        return TRANSLATIONS[self.lang_code].get(key, key)

    # --- SIDEBAR ---
    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        self.lbl_logo = ctk.CTkLabel(self.sidebar, text="☁ DeepScan", font=("Segoe UI", 22, "bold"),
                                     text_color=CF_ORANGE)
        self.lbl_logo.grid(row=0, column=0, padx=20, pady=(30, 30), sticky="w")

        self.nav_btns = {}
        self.add_nav_btn("nav_dash", "dashboard", 1)
        self.add_nav_btn("nav_scan", "scanner", 2)
        self.add_nav_btn("nav_quar", "quarantine", 3)
        self.add_nav_btn("nav_set", "settings", 4)

        self.lbl_ver_mini = ctk.CTkLabel(self.sidebar, text="v2.4 Pro", text_color="gray")
        self.lbl_ver_mini.grid(row=6, column=0, pady=20)

    def add_nav_btn(self, lang_key, frame_name, row):
        btn = ctk.CTkButton(self.sidebar, text="...",
                            fg_color="transparent",
                            text_color=("gray20", "gray80"),
                            hover_color=("gray80", "gray30"),
                            anchor="w", height=45, font=("Segoe UI", 13, "bold"),
                            command=lambda: self.select_frame(frame_name))
        btn.grid(row=row, column=0, sticky="ew", padx=10, pady=2)
        self.nav_btns[lang_key] = btn

    # --- FRAMES ---
    def create_frames(self):
        self.frames = {}
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames["dashboard"] = self.build_dashboard()
        self.frames["scanner"] = self.build_scanner()
        self.frames["quarantine"] = self.build_quarantine()
        self.frames["settings"] = self.build_settings()

    # --- DASHBOARD ---
    def build_dashboard(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.lbl_dash_title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 28, "bold"))
        self.lbl_dash_title.pack(anchor="w", pady=(0, 20))

        grid = ctk.CTkFrame(frame, fg_color="transparent")
        grid.pack(fill="x", pady=10)

        # Status Card
        self.card_status = self.create_metric_card(grid, "lbl_status", self.system_status_text, "🛡️", CF_ORANGE)
        self.card_status.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # DB Card
        self.card_db = self.create_metric_card(grid, "lbl_db", self.db_version, "📂", "#3B8ED0")
        self.card_db.pack(side="left", fill="both", expand=True, padx=10)
        return frame

    def create_metric_card(self, parent, title_key, variable, icon, color):
        card = ctk.CTkFrame(parent, fg_color=("white", "#2b2b2b"))
        self.status_bar_color = ctk.CTkFrame(card, height=4, fg_color=color)
        self.status_bar_color.pack(fill="x")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(padx=20, pady=20, fill="both")

        self.status_icon = ctk.CTkLabel(content, text=icon, font=("Segoe UI", 30))
        self.status_icon.pack(side="left", padx=(0, 15))

        info = ctk.CTkFrame(content, fg_color="transparent")
        info.pack(side="left")

        title_lbl = ctk.CTkLabel(info, text="...", font=("Segoe UI", 12, "bold"), text_color="gray")
        title_lbl.pack(anchor="w")
        setattr(self, f"card_{title_key}", title_lbl)

        # Здесь используем textvariable для автообновления
        val_lbl = ctk.CTkLabel(info, textvariable=variable, font=("Segoe UI", 18, "bold"))
        val_lbl.pack(anchor="w")

        return card

    # --- SCANNER ---
    def build_scanner(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.lbl_scan_title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 28, "bold"))
        self.lbl_scan_title.pack(anchor="w", pady=(0, 20))

        input_card = ctk.CTkFrame(frame, fg_color=("white", "#2b2b2b"))
        input_card.pack(fill="x", pady=10)

        self.lbl_target = ctk.CTkLabel(input_card, text="", font=("Segoe UI", 12, "bold"), text_color="gray")
        self.lbl_target.pack(anchor="w", padx=20, pady=(15, 5))

        row = ctk.CTkFrame(input_card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 20))

        entry = ctk.CTkEntry(row, textvariable=self.target_path, height=40, font=("Consolas", 12))
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_file = ctk.CTkButton(row, text="File", width=80, height=40, fg_color="#333", command=self.browse_file)
        self.btn_file.pack(side="right", padx=5)
        self.btn_folder = ctk.CTkButton(row, text="Folder", width=80, height=40, fg_color="#333",
                                        command=self.browse_folder)
        self.btn_folder.pack(side="right")

        actions = ctk.CTkFrame(frame, fg_color="transparent")
        actions.pack(fill="x", pady=10)

        self.btn_yara = ctk.CTkButton(actions, text="...", height=50, fg_color="transparent", border_width=2,
                                      border_color=CF_ORANGE, text_color=("gray10", "white"), command=self.run_yara)
        self.btn_yara.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_vt = ctk.CTkButton(actions, text="...", height=50, fg_color=CF_ORANGE, hover_color=CF_ORANGE_HOVER,
                                    command=self.run_vt)
        self.btn_vt.pack(side="right", fill="x", expand=True, padx=(10, 0))

        self.progress = ctk.CTkProgressBar(frame, height=5, progress_color=CF_ORANGE)
        self.progress.pack(fill="x", pady=15)
        self.progress.set(0)

        self.results_frame = ctk.CTkScrollableFrame(frame, fg_color=("white", "#1e1e1e"),
                                                    label_text="Live Logs & Results")
        self.results_frame.pack(fill="both", expand=True, pady=10)

        self.log_box = ctk.CTkTextbox(self.results_frame, height=150, fg_color="transparent",
                                      text_color=("gray20", "gray80"), font=("Consolas", 12))
        self.log_box.pack(fill="both", expand=True, pady=5)
        self.log_box.configure(state='disabled')

        self.log_box.tag_config("error", foreground=COLOR_DANGER)
        self.log_box.tag_config("warning", foreground=COLOR_WARN)
        self.log_box.tag_config("info", foreground=COLOR_SAFE)

        self.gui_handler = GuiLogHandler(self.log_box)
        logger.addHandler(self.gui_handler)

        return frame

    # --- QUARANTINE ---
    def build_quarantine(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.lbl_quar_title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 28, "bold"))
        self.lbl_quar_title.pack(anchor="w", pady=(0, 20))

        # Список карантина
        self.quar_list = ctk.CTkScrollableFrame(frame, fg_color=("white", "#2b2b2b"))
        self.quar_list.pack(fill="both", expand=True)

        ctk.CTkButton(frame, text="Refresh", command=self.refresh_quarantine, fg_color="gray").pack(pady=10)
        return frame

    # --- SETTINGS ---
    def build_settings(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.lbl_set_title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 28, "bold"))
        self.lbl_set_title.pack(anchor="w", pady=(0, 20))

        card = ctk.CTkFrame(frame, fg_color=("white", "#2b2b2b"))
        card.pack(fill="x", pady=10, ipady=10)

        self.lbl_lang = ctk.CTkLabel(card, text="Language", font=("Segoe UI", 14, "bold"))
        self.lbl_lang.pack(anchor="w", padx=20, pady=(10, 5))
        self.combo_lang = ctk.CTkOptionMenu(card, values=["English", "Русский", "Türkmençe"],
                                            fg_color=CF_ORANGE, button_color=CF_ORANGE_HOVER,
                                            command=self.on_lang_change)
        self.combo_lang.pack(anchor="w", padx=20, pady=(0, 20))

        self.lbl_theme = ctk.CTkLabel(card, text="Appearance", font=("Segoe UI", 14, "bold"))
        self.lbl_theme.pack(anchor="w", padx=20, pady=(10, 5))
        self.combo_theme = ctk.CTkOptionMenu(card, values=["Dark", "Light", "System"],
                                             fg_color=CF_ORANGE, button_color=CF_ORANGE_HOVER,
                                             command=self.on_theme_change)
        self.combo_theme.pack(anchor="w", padx=20, pady=(0, 10))

        self.btn_update = ctk.CTkButton(card, text="Update Database", fg_color="#3B8ED0", command=self.update_db_thread)
        self.btn_update.pack(padx=20, pady=20, anchor="w")

        # About
        about_card = ctk.CTkFrame(frame, fg_color=("white", "#2b2b2b"))
        about_card.pack(fill="x", pady=20, ipady=10)

        self.lbl_about_head = ctk.CTkLabel(about_card, text="About", font=("Segoe UI", 16, "bold"),
                                           text_color=CF_ORANGE)
        self.lbl_about_head.pack(anchor="w", padx=20, pady=(10, 10))

        row_dev = ctk.CTkFrame(about_card, fg_color="transparent")
        row_dev.pack(fill="x", padx=20, pady=2)
        self.lbl_dev_key = ctk.CTkLabel(row_dev, text="Developer:", width=100, anchor="w", text_color="gray")
        self.lbl_dev_key.pack(side="left")
        ctk.CTkLabel(row_dev, text="Meredow Meret © 2026", font=("Segoe UI", 13, "bold")).pack(side="left")

        row_ver = ctk.CTkFrame(about_card, fg_color="transparent")
        row_ver.pack(fill="x", padx=20, pady=2)
        self.lbl_ver_key = ctk.CTkLabel(row_ver, text="Version:", width=100, anchor="w", text_color="gray")
        self.lbl_ver_key.pack(side="left")
        ctk.CTkLabel(row_ver, text="v2.4 Professional", font=("Segoe UI", 13)).pack(side="left")

        return frame

    # ===== ЛОГИКА ОБНОВЛЕНИЯ ИНТЕРФЕЙСА =====

    def update_system_health(self):
        """Обновляет статус системы на основе проверок"""
        status_text = self.t("status_ok")
        color = COLOR_SAFE

        # 1. Проверка базы данных
        if not os.path.exists(YARA_RULES_PATH):
            status_text = self.t("status_risk") + " (No DB)"
            color = COLOR_DANGER

        # 2. Проверка угроз в сессии
        elif self.threats_detected_session > 0:
            status_text = self.t("status_risk") + f" ({self.threats_detected_session} threats)"
            color = COLOR_WARN

        self.system_status_text.set(status_text)

        # Обновляем цвет полоски (если виджет уже создан)
        try:
            self.status_bar_color.configure(fg_color=color)
        except:
            pass

    def on_theme_change(self, choice):
        ctk.set_appearance_mode(choice)

    def on_lang_change(self, choice):
        codes = {"English": "en", "Русский": "ru", "Türkmençe": "tk"}
        self.change_language(codes.get(choice, "en"))

    def change_language(self, lang_code):
        self.lang_code = lang_code

        for key, btn in self.nav_btns.items():
            btn.configure(text=self.t(key))

        self.lbl_dash_title.configure(text=self.t("dash_title"))
        self.lbl_scan_title.configure(text=self.t("scan_title"))
        self.lbl_quar_title.configure(text=self.t("quar_title"))
        self.lbl_set_title.configure(text=self.t("set_title"))
        self.card_lbl_status.configure(text=self.t("lbl_status"))
        self.card_lbl_db.configure(text=self.t("lbl_db"))

        self.lbl_target.configure(text=self.t("lbl_target"))
        self.btn_file.configure(text=self.t("btn_file"))
        self.btn_folder.configure(text=self.t("btn_folder"))
        self.btn_yara.configure(text=self.t("btn_yara"))
        self.btn_vt.configure(text=self.t("btn_vt"))
        self.results_frame.configure(label_text="Live Logs & Results")

        self.lbl_lang.configure(text=self.t("lang_label"))
        self.lbl_theme.configure(text=self.t("theme_label"))
        self.btn_update.configure(text=self.t("update_btn"))

        self.lbl_about_head.configure(text=self.t("about_header"))
        self.lbl_dev_key.configure(text=self.t("dev_by"))
        self.lbl_ver_key.configure(text=self.t("version"))

        self.update_system_health()  # Обновить тексты статуса

    # ===== ЛОГИКА СКАНИРОВАНИЯ =====

    def run_yara(self):
        path = self.target_path.get()
        if not path: return
        self.clear_logs()
        self.progress.start()

        if os.path.isdir(path):
            logger.info(f"Starting FOLDER scan: {path}")
            threading.Thread(target=self.thread_yara_folder, args=(path,), daemon=True).start()
        elif os.path.isfile(path):
            logger.info(f"Starting FILE scan: {path}")
            threading.Thread(target=self.thread_yara_file, args=(path,), daemon=True).start()

    def thread_yara_file(self, path):
        try:
            if not os.path.exists(YARA_RULES_PATH):
                logger.error("YARA DB missing. Update required.")
                self.after(0, self.update_system_health)
                return
            rules = yara.compile(filepath=YARA_RULES_PATH)
            matches = self.scan_single_file(path, rules)
            if matches:
                self.threats_detected_session += 1
                logger.warning(f"THREAT FOUND: {os.path.basename(path)}")
                self.quarantine_file(path)
                self.after(0, self.update_system_health)
            else:
                logger.info(f"Clean: {os.path.basename(path)}")
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            self.after(0, self.progress.stop)

    def thread_yara_folder(self, folder_path):
        try:
            if not os.path.exists(YARA_RULES_PATH):
                logger.error("YARA DB missing.")
                self.after(0, self.update_system_health)
                return
            rules = yara.compile(filepath=YARA_RULES_PATH)
            count = 0
            threats = 0

            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    count += 1
                    if count % 10 == 0: logger.info(f"Scanned {count} files...")

                    matches = self.scan_single_file(full_path, rules)
                    if matches:
                        threats += 1
                        self.threats_detected_session += 1
                        logger.warning(f"THREAT [{file}]: {[m.rule for m in matches]}")
                        self.quarantine_file(full_path)

            self.after(0, self.update_system_health)
            logger.info(f"Folder scan complete. Files: {count}. Threats: {threats}")

        except Exception as e:
            logger.error(f"Folder scan failed: {e}")
        finally:
            self.after(0, self.progress.stop)

    def scan_single_file(self, filepath, rules):
        try:
            with open(filepath, "rb") as f:
                return rules.match(data=f.read())
        except:
            return None

    def run_vt(self):
        path = self.target_path.get()
        if not path: return
        if os.path.isdir(path):
            messagebox.showerror("Limit", "VirusTotal does not support folders.")
            return

        self.clear_logs()
        self.progress.start()
        threading.Thread(target=self.thread_vt, args=(path,), daemon=True).start()

    def thread_vt(self, path):
        if not VIRUSTOTAL_API_KEY:
            logger.error("API Key missing")
            self.after(0, self.progress.stop)
            return
        try:
            with open(path, "rb") as f:
                resp = requests.post(VT_SCAN_URL, files={"file": f}, params={"apikey": VIRUSTOTAL_API_KEY},
                                     proxies=PROXY_CONFIG)
                resource = resp.json().get("resource")
            logger.info(f"Uploaded. Waiting for report...")
            for _ in range(6):
                time.sleep(5)
                report = requests.get(VT_REPORT_URL, params={"apikey": VIRUSTOTAL_API_KEY, "resource": resource},
                                      proxies=PROXY_CONFIG).json()
                if report.get("response_code") == 1:
                    scans = report.get("scans", {})
                    positives = report.get("positives", 0)
                    if positives > 0: self.threats_detected_session += 1
                    self.after(0, lambda: self.render_vt_table(scans, positives))
                    self.after(0, self.update_system_health)
                    return
            logger.error("VT Timeout")
        except Exception as e:
            logger.error(f"VT Error: {e}")
        finally:
            self.after(0, self.progress.stop)

    def render_vt_table(self, scans, positives):
        for w in self.results_frame.winfo_children():
            if w != self.log_box: w.destroy()

        status_color = COLOR_DANGER if positives > 0 else COLOR_SAFE
        status_text = f"THREATS: {positives}" if positives > 0 else "CLEAN"

        header = ctk.CTkLabel(self.results_frame, text=f"VERDICT: {status_text}", text_color=status_color,
                              font=("Segoe UI", 16, "bold"))
        header.pack(pady=10)

        for engine, data in scans.items():
            detected = data.get("detected", False)
            if positives > 0 and not detected: continue

            row = ctk.CTkFrame(self.results_frame, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=10)
            ctk.CTkLabel(row, text=engine, width=150, anchor="w", font=("Consolas", 12, "bold")).pack(side="left")
            color = COLOR_DANGER if detected else COLOR_SAFE
            icon = "🦠" if detected else "✅"
            ctk.CTkLabel(row, text=f"{icon} {data.get('result', 'Clean')}", text_color=color).pack(side="left", padx=10)
            ctk.CTkFrame(self.results_frame, height=1, fg_color="gray30").pack(fill="x")

    # ===== КАРАНТИН (С ПАМЯТЬЮ) =====

    def load_quarantine_map(self):
        """Загружает JSON с историей путей"""
        if os.path.exists(QUARANTINE_MAP_FILE):
            try:
                with open(QUARANTINE_MAP_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_quarantine_map(self):
        with open(QUARANTINE_MAP_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.quarantine_map, f, indent=4)

    def quarantine_file(self, path):
        try:
            base = os.path.basename(path)
            dest = os.path.join(QUARANTINE_FOLDER, base + ".quarantine")

            # Сохраняем исходный путь
            self.quarantine_map[base + ".quarantine"] = path
            self.save_quarantine_map()

            shutil.move(path, dest)
            logger.info(f"Quarantined: {path} -> {dest}")
        except Exception as e:
            logger.error(f"Quarantine error: {e}")

    def refresh_quarantine(self):
        for w in self.quar_list.winfo_children(): w.destroy()
        if not os.path.exists(QUARANTINE_FOLDER): return

        files = [f for f in os.listdir(QUARANTINE_FOLDER) if f.endswith(".quarantine")]

        for f in files:
            original = self.quarantine_map.get(f, "Unknown Origin")

            row = ctk.CTkFrame(self.quar_list, fg_color="transparent")
            row.pack(fill="x", pady=5, padx=10)

            # Info
            info_frame = ctk.CTkFrame(row, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(info_frame, text=f, font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ctk.CTkLabel(info_frame, text=original, font=("Segoe UI", 10), text_color="gray").pack(anchor="w")

            # Buttons
            ctk.CTkButton(row, text=self.t("btn_delete"), width=60, height=25, fg_color=COLOR_DANGER,
                          command=lambda x=f: self.delete_file_permanently(x)).pack(side="right", padx=5)

            ctk.CTkButton(row, text=self.t("btn_restore"), width=80, height=25, fg_color=COLOR_NEUTRAL,
                          command=lambda x=f: self.restore_file(x)).pack(side="right", padx=5)

    def restore_file(self, filename):
        original_path = self.quarantine_map.get(filename)
        if not original_path:
            messagebox.showerror("Error", "Original path unknown.")
            return

        src = os.path.join(QUARANTINE_FOLDER, filename)

        try:
            # Создаем папку если ее уже нет
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(src, original_path)

            # Чистим карту
            del self.quarantine_map[filename]
            self.save_quarantine_map()

            logger.info(f"Restored: {original_path}")
            self.refresh_quarantine()
            messagebox.showinfo("Restored", f"File restored to:\n{original_path}")
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            messagebox.showerror("Error", str(e))

    def delete_file_permanently(self, filename):
        if not messagebox.askyesno("Confirm", "Delete permanently?"): return
        try:
            os.remove(os.path.join(QUARANTINE_FOLDER, filename))
            if filename in self.quarantine_map:
                del self.quarantine_map[filename]
                self.save_quarantine_map()
            self.refresh_quarantine()
            logger.info(f"Deleted permanently: {filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # --- UTILS ---
    def browse_file(self):
        p = filedialog.askopenfilename()
        if p: self.target_path.set(p)

    def browse_folder(self):
        p = filedialog.askdirectory()
        if p: self.target_path.set(p)

    def clear_logs(self):
        self.log_box.configure(state='normal')
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state='disabled')
        for w in self.results_frame.winfo_children():
            if w != self.log_box: w.destroy()

    def select_frame(self, name):
        for f in self.frames.values(): f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)
        if name == "quarantine": self.refresh_quarantine()

    def update_db_thread(self):
        threading.Thread(target=self.bg_update, daemon=True).start()

    def bg_update(self):
        logger.info("Updating DB...")
        try:
            api = requests.get(YARA_API_URL, proxies=PROXY_CONFIG).json()
            remote_ver = api.get('tag_name')

            assets = api.get('assets', [])
            dl_url = next((a['browser_download_url'] for a in assets if
                           'full' in a['name'].lower() and a['name'].endswith('.zip')), None)

            if dl_url:
                r = requests.get(dl_url, stream=True, proxies=PROXY_CONFIG)
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    yar = next((n for n in z.namelist() if n.endswith(".yar")), None)
                    with open("temp.yar", 'wb') as f: f.write(z.read(yar))
                yara.compile(filepath="temp.yar")
                shutil.move("temp.yar", YARA_RULES_PATH)
                with open(VERSION_FILE, 'w') as f: f.write(remote_ver)
                logger.info("Update Success")
                self.after(0, lambda: messagebox.showinfo("Success", "Updated!"))
                self.after(0, self.check_local_db)
                self.after(0, self.update_system_health)
        except Exception as e:
            logger.error(f"Update failed: {e}")
    def check_local_db(self):
        if os.path.exists(VERSION_FILE):
            with open(VERSION_FILE) as f: self.db_version.set(f.read().strip())
        self.update_system_health()
if __name__ == "__main__":
    app = DeepScanApp()
    app.mainloop()