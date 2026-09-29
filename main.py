import sys
import os

# Добавляем папку src в путь системного импорта Python
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from deepscan.ui.app import DeepScanApp

if __name__ == "__main__":
    app = DeepScanApp()
    app.mainloop()