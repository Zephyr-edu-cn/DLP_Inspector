# run.py
import os
import sys

# 锁定系统路径，确保打包后引擎能找到所有的 core 和 utils
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# 导入我们的主视窗
from ui.main_window import DLPScannerApp

if __name__ == "__main__":
    app = DLPScannerApp()
    app.mainloop()


# pyinstaller -D --name "DLP_DeepWatcher" --collect-all Cython --collect-all paddle --collect-all paddleocr --collect-all customtkinter --collect-all skimage --collect-all imgaug --collect-all lmdb --hidden-import pyclipper --hidden-import shapely --copy-metadata imageio --copy-metadata imgaug run.py