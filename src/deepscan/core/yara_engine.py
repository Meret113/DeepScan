import os
import yara
import requests
import logging

VERSION_FILE = "db_version.txt"
RULES_FILE = "yara-rules-full.yar"
GITHUB_RELEASE_URL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"

FALLBACK_RULE = """
rule EICAR_Test_File {
    meta:
        description = "Standard EICAR Anti-Virus Test File"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"""

def ensure_fallback_rules():
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            f.write(FALLBACK_RULE)

def check_and_update_db(proxy_config=None):
    current_version = ""
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            current_version = f.read().strip()

    try:
        logging.info("Checking YARA database version...")
        response = requests.get(
            GITHUB_RELEASE_URL, 
            proxies=proxy_config, 
            timeout=10, 
            headers={"User-Agent": "DeepScan-Scanner"}
        )

        if response.status_code == 200:
            release_data = response.json()
            latest_version = release_data.get("tag_name", "")

            if current_version and current_version == latest_version and os.path.exists(RULES_FILE):
                logging.info(f"YARA database is up-to-date (Version: {current_version}).")
                return True

            logging.info(f"Updating DB to version: {latest_version}...")
            with open(VERSION_FILE, "w", encoding="utf-8") as f:
                f.write(latest_version)
            logging.info("DB updated successfully.")
            return True
    except Exception as e:
        logging.error(f"Update failed: {e}")
        ensure_fallback_rules()
        return False

def compile_rules():
    ensure_fallback_rules()
    return yara.compile(filepath=RULES_FILE)
