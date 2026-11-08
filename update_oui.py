"""Pobiera oficjalne rejestry IEEE raz, do późniejszego użycia offline."""
import csv
import io
import urllib.request
from pathlib import Path

SOURCES = {
    'oui.csv': 'https://standards-oui.ieee.org/oui/oui.csv',
    'mam.csv': 'https://standards-oui.ieee.org/oui28/mam.csv',
    'oui36.csv': 'https://standards-oui.ieee.org/oui36/oui36.csv',
}
DEST = Path(__file__).resolve().parent / 'data' / 'ieee'
DEST.mkdir(parents=True, exist_ok=True)
failed = []
for filename, url in SOURCES.items():
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'NetMapper-IEEE-Database-Updater/5.0'})
        with urllib.request.urlopen(req, timeout=45) as response:
            data = response.read(35_000_000)
        rows = csv.DictReader(io.StringIO(data.decode('utf-8-sig')))
        if not {'Assignment', 'Organization Name'}.issubset(set(rows.fieldnames or [])):
            raise ValueError('Niepoprawny nagłówek pliku CSV')
        count = sum(1 for r in rows if r.get('Assignment') and r.get('Organization Name'))
        if count < 1:
            raise ValueError('Pusta baza')
        (DEST / (filename + '.tmp')).write_bytes(data)
        (DEST / (filename + '.tmp')).replace(DEST / filename)
        print(f'OK: {filename}: {count} rekordów')
    except Exception as exc:
        failed.append(filename)
        print(f'BŁĄD: {filename}: {exc} (dotychczasowa baza pozostaje bez zmian)')
if failed:
    raise SystemExit('Nie udało się pobrać: ' + ', '.join(failed))
print('Baza IEEE gotowa do użycia offline.')
