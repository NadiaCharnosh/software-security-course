import sys
from pathlib import Path

# cvss.py і scoring.py лежать у каталозі lab01_threat_model
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
