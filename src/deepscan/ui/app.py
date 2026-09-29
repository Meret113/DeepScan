import os
import threading
import time
import requests
import logging
import zipfile
import io
from tkinter import filedialog, messagebox
import customtkinter as ctk

from deepscan.config import (
    CF_ORANGE, CF_ORANGE_HOVER, COLOR_SAFE, COLOR_DANGER, COLOR_WARN, COLOR_NEUTRAL,
    VIRUSTOTAL_API_KEY, VT_SCAN_URL, VT_REPORT_URL, YARA_RULES_PATH, QUARANTINE_FOLDER,
    VERSION_FILE, LOG_FILE, YARA_API_URL, PROXY_CONFIG, TRANSLATIONS
)
from deepscan.core.quarantine import QuarantineManager
from deepscan.core.yara_engine import YaraEngine

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


class GuiLogHandler(logging.Handler):
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
        self.threats_detected_session = 0

        self.quarantine_mgr = QuarantineManager()
        self.yara_engine = YaraEngine()

        self.title("DeepScan | Cloud Intelligence")
        self.geometry("1150x780")
        ctk.set_appearance_mode("Dark")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_frames()
        self.change_language("ru")

        self.check_local_db()
        self.update_system_health()
        self.select_frame("dashboard")

    def t(self, key: str) -> str:
        return TRANSLATIONS[self.lang_code].get(key, key)

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

        self.lbl_ver_mini = ctk.CTkLabel(self.sidebar, text="v3.0 Architecture", text_color="gray")
        self.lbl_ver_mini.grid(row=6, column=0, pady=20)

    def add_nav_btn(self, lang_key, frame_name, row):
        btn = ctk.CTkButton(self.sidebar, text="...", fg_color="transparent",
                            text_color=("gray20", "gray80"), hover_color=("gray80", "gray30"),
                            anchor="w", height=45, font=("Segoe UI", 13, "bold"),
                            command=lambda: self.select_frame(frame_name))
        btn.grid(row=row, column=0, sticky="ew", padx=10, pady=2)
        self.nav_btns[lang_key] = btn

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

    def build_dashboard(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.lbl_dash_title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 28, "bold"))
        self.lbl_dash_title.pack(anchor="w", pady=(0, 20))

        grid = ctk.CTkFrame(frame, fg_color="transparent")
        grid.pack(fill="x", pady=10)

        self.card_status = self.create_metric_card(grid, "lbl_status", self.system_status_text, "🛡️", CF_ORANGE)
        self.card_status.pack(side="left", fill="both", expand=True, padx=(0, 10))

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

        val_lbl = ctk.CTkLabel(info, textvariable=variable, font=("Segoe UI", 18, "bold"))
        val_lbl.pack(anchor="w")
        return card

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

    def build_quarantine(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.lbl_quar_title = ctk.CTkLabel(frame, text="", font=("Segoe UI", 28, "bold"))
        self.lbl_quar_title.pack(anchor="w", pady=(0, 20))

        self.quar_list = ctk.CTkScrollableFrame(frame, fg_color=("white", "#2b2b2b"))
        self.quar_list.pack(fill="both", expand=True)

        ctk.CTkButton(frame, text="Refresh", command=self.refresh_quarantine, fg_color="gray").pack(pady=10)
        return frame

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
        ctk.CTkLabel(row_ver, text="v3.0 Professional Modular", font=("Segoe UI", 13)).pack(side="left")

        return frame

    def update_system_health(self):
        status_text = self.t("status_ok")
        color = COLOR_SAFE

        if not os.path.exists(YARA_RULES_PATH):
            status_text = self.t("status_risk") + " (No DB)"
            color = COLOR_DANGER
        elif self.threats_detected_session > 0:
            status_text = self.t("status_risk") + f" ({self.threats_detected_session} threats)"
            color = COLOR_WARN

        self.system_status_text.set(status_text)
        try:
            self.status_bar_color.configure(fg_color=color)
        except Exception:
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

        self.update_system_health()

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
            matches = self.yara_engine.scan_file(path)
            if matches:
                self.threats_detected_session += 1
                logger.warning(f"THREAT FOUND: {os.path.basename(path)}")
                self.quarantine_mgr.quarantine_file(path)
                self.after(0, self.update_system_health)
            else:
                logger.info(f"Clean: {os.path.basename(path)}")
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            self.after(0, self.progress.stop)

    def thread_yara_folder(self, folder_path):
        try:
            count = 0
            threats = 0
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    count += 1
                    if count % 10 == 0: logger.info(f"Scanned {count} files...")

                    matches = self.yara_engine.scan_file(full_path)
                    if matches:
                        threats += 1
                        self.threats_detected_session += 1
                        logger.warning(f"THREAT [{file}]: {[m.rule for m in matches]}")
                        self.quarantine_mgr.quarantine_file(full_path)

            self.after(0, self.update_system_health)
            logger.info(f"Folder scan complete. Files: {count}. Threats: {threats}")
        except Exception as e:
            logger.error(f"Folder scan failed: {e}")
        finally:
            self.after(0, self.progress.stop)

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
            logger.info("Uploaded. Waiting for report...")
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

    def refresh_quarantine(self):
        for w in self.quar_list.winfo_children(): w.destroy()
        if not os.path.exists(QUARANTINE_FOLDER): return

        files = [f for f in os.listdir(QUARANTINE_FOLDER) if f.endswith(".quarantine")]
        for f in files:
            original = self.quarantine_mgr.quarantine_map.get(f, "Unknown Origin")

            row = ctk.CTkFrame(self.quar_list, fg_color="transparent")
            row.pack(fill="x", pady=5, padx=10)

            info_frame = ctk.CTkFrame(row, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(info_frame, text=f, font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ctk.CTkLabel(info_frame, text=original, font=("Segoe UI", 10), text_color="gray").pack(anchor="w")

            ctk.CTkButton(row, text=self.t("btn_delete"), width=60, height=25, fg_color=COLOR_DANGER,
                          command=lambda x=f: self.on_delete_quarantine(x)).pack(side="right", padx=5)

            ctk.CTkButton(row, text=self.t("btn_restore"), width=80, height=25, fg_color=COLOR_NEUTRAL,
                          command=lambda x=f: self.on_restore_quarantine(x)).pack(side="right", padx=5)

    def on_restore_quarantine(self, filename):
        success, res = self.quarantine_mgr.restore_file(filename)
        if success:
            self.refresh_quarantine()
            messagebox.showinfo("Restored", f"File restored to:\n{res}")
        else:
            messagebox.showerror("Error", res)

    def on_delete_quarantine(self, filename):
        if messagebox.askyesno("Confirm", "Delete permanently?"):
            self.quarantine_mgr.delete_file(filename)
            self.refresh_quarantine()

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

                import yara
                yara.compile(filepath="temp.yar")
                import shutil
                shutil.move("temp.yar", YARA_RULES_PATH)
                with open(VERSION_FILE, 'w') as f: f.write(remote_ver)
                logger.info("Update Success")
                self.yara_engine.load_rules()
                self.after(0, lambda: messagebox.showinfo("Success", "Updated!"))
                self.after(0, self.check_local_db)
                self.after(0, self.update_system_health)
        except Exception as e:
            logger.error(f"Update failed: {e}")

    def check_local_db(self):
        if os.path.exists(VERSION_FILE):
            with open(VERSION_FILE) as f: self.db_version.set(f.read().strip())
        self.update_system_health()