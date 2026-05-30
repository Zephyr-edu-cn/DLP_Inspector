# main.py
"""Compatibility entry point for DLP Inspector."""

from ui.main_window import DLPScannerApp


def main() -> None:
    app = DLPScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
