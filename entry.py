"""Entry point for PyInstaller."""
import sys
import os

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

if application_path not in sys.path:
    sys.path.insert(0, application_path)

if __name__ == '__main__':
    from src.main import main
    main()
