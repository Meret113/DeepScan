"""Локальный YARA-сканер с автообновлением базы правил (YARA-Forge).

Логика:
  * при старте правила загружаются в фоне (из бинарного кэша, если он свежий);
  * сразу после старта и затем каждые N часов проверяется последний релиз на GitHub;
  * архив скачивается ТОЛЬКО если тег релиза отличается от сохранённого в db_version.txt;
  * новая база проверяется компиляцией и подменяется атомарно — сломанный
    или недокачанный файл никогда не заменит рабочую базу.
"""
import io
import logging
import os
import threading
import time
import zipfile
from typing import Callable, NamedTuple, Optional

import requests
import yara

from deepscan.config import PROXY_CONFIG, VERSION_FILE, YARA_API_URL, YARA_RULES_PATH

logger = logging.getLogger("DeepScan")

# Минимальное правило только для случая «первый запуск + нет интернета»,
# чтобы движок не падал. Как только база скачана, оно не используется.
_BOOTSTRAP_RULE = """
rule Bootstrap_Placeholder { condition: false }
"""

_HEADERS = {"User-Agent": "DeepScan-Scanner"}
_RELEASES_LATEST = "https://github.com/YARAHQ/yara-forge/releases/latest"
_ASSET_URL = "https://github.com/YARAHQ/yara-forge/releases/download/{tag}/yara-forge-rules-full.zip"


class UpdateResult(NamedTuple):
    status: str   # "updated" | "up_to_date" | "error" | "busy"
    version: str
    message: str


class YaraEngine:
    def __init__(self, rules_path: str = YARA_RULES_PATH, version_file: str = VERSION_FILE,
                 proxies: Optional[dict] = PROXY_CONFIG):
        self.rules_path = rules_path
        self.compiled_path = rules_path + "c"       # yara-rules-full.yarc — быстрый кэш
        self.version_file = version_file
        self.proxies = proxies

        self.rules = None
        self._ready = threading.Event()
        self._update_lock = threading.Lock()
        self._stop = threading.Event()
        self._updater = None

        threading.Thread(target=self.load_rules, daemon=True, name="yara-load").start()

    # ------------------------------------------------------------------ загрузка
    def load_rules(self) -> bool:
        """Загружает правила (кэш -> .yar -> заглушка). Возвращает True, если загружена реальная база."""
        try:
            if os.path.exists(self.rules_path):
                if self._cache_is_fresh():
                    try:
                        self.rules = yara.load(self.compiled_path)
                        logger.info("YARA rules loaded from compiled cache")
                        return True
                    except yara.Error:
                        logger.info("Compiled cache unusable, recompiling")
                self.rules = yara.compile(filepath=self.rules_path)
                self._save_cache(self.rules)
                logger.info("YARA rules compiled")
                return True
            logger.warning("No rules database yet — waiting for the first update")
            self.rules = yara.compile(source=_BOOTSTRAP_RULE)
            return False
        except yara.Error as e:
            logger.error(f"Rules load failed: {e}")
            self.rules = yara.compile(source=_BOOTSTRAP_RULE)
            return False
        finally:
            self._ready.set()

    def _cache_is_fresh(self) -> bool:
        return (os.path.exists(self.compiled_path)
                and os.path.getmtime(self.compiled_path) >= os.path.getmtime(self.rules_path))

    def _save_cache(self, rules) -> None:
        try:
            rules.save(self.compiled_path)
        except Exception as e:
            logger.warning(f"Could not save compiled cache: {e}")

    # ------------------------------------------------------------------ сканирование
    def scan_file(self, path: str, timeout: int = 60) -> list:
        """Возвращает список yara.Match (у каждого есть .rule)."""
        if not self._ready.wait(timeout=300):
            raise RuntimeError("YARA rules are still loading")
        return self.rules.match(filepath=path, timeout=timeout)

    # ------------------------------------------------------------------ версия
    def local_version(self) -> str:
        try:
            with open(self.version_file, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""

    # ------------------------------------------------------------------ обновление
    def update_if_needed(self, force: bool = False) -> UpdateResult:
        """Скачивает базу только если на GitHub вышла новая версия."""
        if not self._update_lock.acquire(blocking=False):
            return UpdateResult("busy", self.local_version(), "Update already in progress")
        try:
            local = self.local_version()
            logger.info("Checking YARA database version...")

            remote = self._latest_tag()
            if not remote:
                return UpdateResult("error", local, "Could not determine latest release")

            if (not force and remote == local and os.path.exists(self.rules_path)):
                logger.info(f"YARA database is up-to-date ({local})")
                return UpdateResult("up_to_date", local, f"Up to date ({local})")

            asset_url = self._asset_url(remote)

            logger.info(f"New database {remote} (local: {local or 'none'}), downloading...")
            data = self._download(asset_url)
            new_rules = self._install(data, remote)
            self.rules = new_rules
            self._ready.set()
            logger.info(f"Update Success: {remote}")
            return UpdateResult("updated", remote, f"Updated to {remote}")
        except Exception as e:
            logger.error(f"Update failed: {e}")
            return UpdateResult("error", self.local_version(), str(e))
        finally:
            self._update_lock.release()

    def _latest_tag(self) -> str:
        """Тег последнего релиза. Сначала редирект github.com (без лимита API), затем API."""
        try:
            r = requests.get(_RELEASES_LATEST, headers=_HEADERS, proxies=self.proxies,
                             timeout=(5, 15), allow_redirects=False)
            loc = r.headers.get("Location", "")
            if "/tag/" in loc:
                return loc.rsplit("/tag/", 1)[1].strip()
        except requests.RequestException as e:
            logger.warning(f"Redirect check failed: {e}")
        r = requests.get(YARA_API_URL, headers=_HEADERS, proxies=self.proxies, timeout=(5, 15))
        r.raise_for_status()
        return r.json().get("tag_name", "")

    def _asset_url(self, tag: str) -> str:
        """Прямая ссылка на архив 'full'. Если имя изменится — ищем через API."""
        url = _ASSET_URL.format(tag=tag)
        try:
            if requests.head(url, headers=_HEADERS, proxies=self.proxies, timeout=(5, 15),
                             allow_redirects=True).status_code == 200:
                return url
        except requests.RequestException:
            pass
        r = requests.get(YARA_API_URL, headers=_HEADERS, proxies=self.proxies, timeout=(5, 15))
        r.raise_for_status()
        asset = next((a for a in r.json().get("assets", [])
                      if "full" in a["name"].lower() and a["name"].endswith(".zip")), None)
        if asset is None:
            raise RuntimeError("No 'full' zip asset in the latest release")
        return asset["browser_download_url"]

    def _download(self, url: str, attempts: int = 3) -> bytes:
        last_err = None
        for i in range(1, attempts + 1):
            try:
                with requests.get(url, headers=_HEADERS, proxies=self.proxies,
                                  stream=True, timeout=(5, 30)) as resp:
                    resp.raise_for_status()
                    expected = int(resp.headers.get("Content-Length", 0))
                    buf = io.BytesIO()
                    for chunk in resp.iter_content(chunk_size=256 * 1024):
                        buf.write(chunk)
                if expected and buf.tell() != expected:
                    raise IOError(f"Incomplete download: {buf.tell()} of {expected} bytes")
                return buf.getvalue()
            except Exception as e:
                last_err = e
                logger.warning(f"Download attempt {i}/{attempts} failed: {e}")
                time.sleep(2 * i)
        raise last_err

    def _install(self, zip_bytes: bytes, version: str):
        """Распаковывает, проверяет компиляцией и атомарно подменяет файлы. Возвращает скомпилированные правила."""
        tmp_yar = self.rules_path + ".tmp"
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                name = next((n for n in z.namelist() if n.endswith(".yar")), None)
                if name is None:
                    raise RuntimeError("No .yar file inside the archive")
                with open(tmp_yar, "wb") as f:
                    f.write(z.read(name))

            compiled = yara.compile(filepath=tmp_yar)       # если тут ошибка — старая база остаётся
            os.replace(tmp_yar, self.rules_path)
            self._save_cache(compiled)

            tmp_ver = self.version_file + ".tmp"
            with open(tmp_ver, "w", encoding="utf-8") as f:
                f.write(version)
            os.replace(tmp_ver, self.version_file)
            return compiled
        finally:
            if os.path.exists(tmp_yar):
                os.remove(tmp_yar)

    # ------------------------------------------------------------------ автообновление
    def start_auto_update(self, on_result: Optional[Callable[[UpdateResult], None]] = None,
                          interval_hours: float = 6) -> None:
        """Проверка при старте и далее каждые interval_hours часов (в фоновом потоке)."""
        if self._updater and self._updater.is_alive():
            return

        def loop():
            while not self._stop.is_set():
                result = self.update_if_needed()
                if on_result:
                    try:
                        on_result(result)
                    except Exception as e:
                        logger.error(f"Update callback failed: {e}")
                # при ошибке (нет сети) пробуем снова через 5 минут
                wait = 300 if result.status == "error" else interval_hours * 3600
                self._stop.wait(wait)

        self._updater = threading.Thread(target=loop, daemon=True, name="yara-autoupdate")
        self._updater.start()

    def stop_auto_update(self) -> None:
        self._stop.set()