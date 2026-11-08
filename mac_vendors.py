"""Offline IEEE MAC vendor lookup (MA-L, MA-M, MA-S)."""
import csv
import re
from pathlib import Path
from functools import lru_cache

BASE = Path(__file__).resolve().parent / 'data' / 'ieee'
FILES = ('oui36.csv', 'mam.csv', 'oui.csv')

@lru_cache(maxsize=1)
def _database():
    records = {}
    for filename in FILES:
        path = BASE / filename
        if not path.exists():
            continue
        with path.open(encoding='utf-8-sig', newline='') as f:
            for row in csv.DictReader(f):
                assignment = re.sub(r'[^0-9A-F]', '', row.get('Assignment', '').upper())
                company = (row.get('Organization Name') or '').strip()
                if len(assignment) in (6, 7, 9) and company:
                    records[assignment] = company
    return records

def vendor(mac):
    normalized = re.sub(r'[^0-9A-F]', '', str(mac).upper())
    if len(normalized) != 12:
        return 'Nieznany (brak adresu MAC)'
    if int(normalized[:2], 16) & 1:
        return 'Adres grupowy / multicast'
    if int(normalized[:2], 16) & 2:
        return 'MAC lokalny / losowy (brak wiarygodnego OUI)'
    db = _database()
    if not db:
        return 'Brak lokalnej bazy IEEE — uruchom update_oui.py'
    for width in (9, 7, 6):
        if normalized[:width] in db:
            return db[normalized[:width]]
    return 'Nieznany (brak wpisu w bazie IEEE)'

def database_info():
    return {'records': len(_database()), 'files': [name for name in FILES if (BASE / name).exists()]}
