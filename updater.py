"""Local-only ZIP updater for NetMapper. Trusted releases only."""
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
MAX_ZIP_BYTES = 25 * 1024 * 1024
MAX_UNPACKED_BYTES = 80 * 1024 * 1024
ALLOWED_FILES = {'app.py', 'web_terminal.py', 'fingerprint.py', 'mac_vendors.py', 'vendor_ports.py', 'vendor_ports.csv', 'update_oui.py', 'updater.py', 'requirements.txt', 'README.md', 'README_CUSTOM_NETWORK.md', 'README_TERMINAL.md', 'README_TERMINAL_WEB.md', 'README_UPDATE.md', 'VERSION', 'release.json'}
ALLOWED_DIRS = {'static', 'templates'}
PROTECTED = {'data', 'results.json', '.venv', '__pycache__', '.git', 'backups', 'port.txt'}
UPDATE_LOCK = threading.Lock()


def installed_version():
    f = ROOT / 'VERSION'
    return f.read_text(encoding='utf-8').strip() if f.exists() else '8.8'


def inspect_package(data):
    if len(data) > MAX_ZIP_BYTES:
        raise ValueError('Paczka jest za duża (maksymalnie 25 MB).')
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        raise ValueError('Niepoprawny plik ZIP.')
    with zf:
        items = [i for i in zf.infolist() if not i.is_dir()]
        if len(items) > 150 or sum(i.file_size for i in items) > MAX_UNPACKED_BYTES:
            raise ValueError('Paczka przekracza limit liczby lub rozmiaru plików.')
        paths = [PurePosixPath(i.filename) for i in items]
        prefix = 'netmapper/' if paths and all(str(p).startswith('netmapper/') for p in paths) else ''
        extracted = {}
        for item in items:
            name = item.filename[len(prefix):]
            path = PurePosixPath(name)
            if not name or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
                raise ValueError('Niebezpieczna ścieżka w archiwum.')
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Archiwum zawiera niedozwolone dowiązanie symboliczne.')
            if path.parts[0] in PROTECTED or any(x.startswith('.') for x in path.parts):
                continue  # Nigdy nie aktualizuj danych lokalnych ani środowiska.
            if not (len(path.parts) == 1 and name in ALLOWED_FILES or len(path.parts) >= 2 and path.parts[0] in ALLOWED_DIRS and path.suffix in {'.js', '.css', '.html'}):
                raise ValueError(f'Niedozwolony plik: {name}')
            if name in extracted:
                raise ValueError('Powielona ścieżka w paczce.')
            extracted[name] = zf.read(item)
        if not {'app.py', 'requirements.txt', 'templates/index.html', 'static/app.js', 'static/style.css'}.issubset(extracted):
            raise ValueError('To nie jest kompletna paczka NetMapper.')
        version = extracted.get('VERSION', b'').decode('utf-8').strip()
        if not version:
            raise ValueError('Brak pliku VERSION. Wymagana paczka aktualizacyjna NetMapper 8.9+.')
        if len(version) > 40 or any(c not in '0123456789.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_+' for c in version):
            raise ValueError('Nieprawidłowy numer wersji.')
        for name, content in extracted.items():
            if name.endswith('.py'):
                try: compile(content, name, 'exec')
                except SyntaxError as e: raise ValueError(f'Błąd składni Python w {name}: {e}')
        return version, extracted


def install(data):
    version, files = inspect_package(data)
    if version == installed_version():
        raise ValueError('Ta wersja jest już zainstalowana.')
    previous_version = installed_version()
    with UPDATE_LOCK:
        backup_dir = ROOT / 'backups' / datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        backup_dir.mkdir(parents=True)
        written = []
        try:
            for name in files:
                target = ROOT / name
                if target.exists():
                    copy = backup_dir / name
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, copy)
            for name, content in files.items():
                target = ROOT / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
                    tmp.write(content)
                    tempname = tmp.name
                os.replace(tempname, target)
                written.append(name)
            (backup_dir / 'backup.json').write_text(json.dumps({'version_before': previous_version, 'installed': version, 'files': list(files)}, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception:
            for name in reversed(written):
                target = ROOT / name
                old = backup_dir / name
                if old.exists(): shutil.copy2(old, target)
                else: target.unlink(missing_ok=True)
            raise
    return {'ok': True, 'version': version, 'backup': backup_dir.name, 'restart': True}


def restart_later(delay=2.0):
    def restart():
        time.sleep(delay)
        os.execv(sys.executable, [sys.executable, str(ROOT / 'app.py')])
    threading.Thread(target=restart, daemon=True).start()
