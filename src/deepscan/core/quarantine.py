import os
import json
import shutil
import logging
from deepscan.config import QUARANTINE_FOLDER, QUARANTINE_MAP_FILE

logger = logging.getLogger("DeepScan")

class QuarantineManager:
    def __init__(self):
        os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
        self.quarantine_map = self.load_map()

    def load_map(self) -> dict:
        if os.path.exists(QUARANTINE_MAP_FILE):
            try:
                with open(QUARANTINE_MAP_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_map(self) -> None:
        with open(QUARANTINE_MAP_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.quarantine_map, f, indent=4)

    def quarantine_file(self, path: str) -> bool:
        try:
            base = os.path.basename(path)
            dest_filename = base + ".quarantine"
            dest_path = os.path.join(QUARANTINE_FOLDER, dest_filename)

            self.quarantine_map[dest_filename] = path
            self.save_map()

            shutil.move(path, dest_path)
            logger.info(f"Quarantined: {path} -> {dest_path}")
            return True
        except Exception as e:
            logger.error(f"Quarantine error: {e}")
            return False

    def restore_file(self, filename: str) -> tuple[bool, str]:
        original_path = self.quarantine_map.get(filename)
        if not original_path:
            return False, "Original path unknown."

        src = os.path.join(QUARANTINE_FOLDER, filename)
        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            shutil.move(src, original_path)

            del self.quarantine_map[filename]
            self.save_map()

            logger.info(f"Restored: {original_path}")
            return True, original_path
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False, str(e)

    def delete_file(self, filename: str) -> bool:
        try:
            path = os.path.join(QUARANTINE_FOLDER, filename)
            if os.path.exists(path):
                os.remove(path)
            if filename in self.quarantine_map:
                del self.quarantine_map[filename]
                self.save_map()
            logger.info(f"Deleted permanently: {filename}")
            return True
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return False