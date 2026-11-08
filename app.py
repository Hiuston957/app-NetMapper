import concurrent.futures
import multiprocessing as mp
import queue
import csv
import io
import sqlite3
from flask import Response
import urllib.request
import ssl
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import psutil
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 26 * 1024 * 1024
LOCK = threading.Lock()
EVENTS = None
WORKER = None
HISTORY = Path(__file__).parent / 'data' / 'history.sqlite3'
MAX_WORKERS = max(2, min(32, int(os.getenv('SCAN_WORKERS', '16'))))
PORT_WORKERS = max(2, min(16, int(os.getenv('PORT_WORKERS', '8'))))
STATE = {'running': False, 'devices': [], 'edges': [], 'error': None, 'started': None, 'finished': None, 'progress': 0, 'total': 0, 'phase': 'idle', 'job_id': None}
DATA = Path(__file__).parent / 'results.json'
MAX_HOSTS = int(os.getenv('MAX_HOSTS', '1024'))
PORTS = {22:'SSH',23:'Telnet',53:'DNS',80:'HTTP',135:'RPC',139:'NetBIOS',443:'HTTPS',445:'SMB',548:'AFP',631:'IPP',1433:'MSSQL',1883:'MQTT',2049:'NFS',2375:'Docker',3000:'Web app',3306:'MySQL',3389:'RDP',5000:'Synology DSM / HTTP',5001:'Synology DSM / HTTPS',5432:'PostgreSQL',5900:'VNC',5985:'WinRM',5986:'WinRM TLS',8006:'Proxmox VE',8080:'HTTP-alt',8081:'HTTP-alt',8443:'HTTPS-alt',8888:'HTTP-alt',9000:'Web admin',9090:'Cockpit',9100:'JetDirect',9443:'HTTPS-alt'}
from mac_vendors import vendor, database_info
from vendor_ports import matching
from fingerprint import identify, HTTP_PORTS
WEB_PORTS = {80:'http',443:'https',5000:'http',5001:'https',8006:'https',8080:'http',8081:'http',8443:'https',8888:'http',9000:'http',9090:'https',9443:'https',3000:'http',631:'http'}


def web_panels(ip, ports):
    # URLs are built only from IPs found in the local scan and known HTTP(S) ports.
    return [{'port':p['port'], 'service':p['service'], 'url':f"{(p.get('web_scheme') or WEB_PORTS.get(p['port']))}://{ip}:{p['port']}/"}
            for p in ports if p['port'] in WEB_PORTS or p.get('web_scheme')] 


def tcp_ports(ip, portmap=None):
    opened = []
    def check(item):
        port, label = item
        try:
            with socket.create_connection((ip, port), timeout=0.35):
                return {'port': port, 'service': label}
        except OSError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_WORKERS) as pool:
        for result in pool.map(check, (portmap or PORTS).items()):
            if result:
                opened.append(result)
    return opened


def classify(ports):
    ps = {p['port'] for p in ports}
    if 8006 in ps: return 'Proxmox VE'
    if 5001 in ps or 5000 in ps: return 'NAS / Synology (prawdopodobne)'
    if 9100 in ps or 631 in ps: return 'Drukarka (prawdopodobne)'
    if 3389 in ps or 5985 in ps or 5986 in ps: return 'Windows / serwer (prawdopodobne)'
    if 445 in ps or 548 in ps: return 'NAS / Windows (prawdopodobne)'
    if 22 in ps: return 'Linux / urządzenie sieciowe (prawdopodobne)'
    if 443 in ps or 80 in ps: return 'Urządzenie z panelem WWW'
    return 'Nieustalony'



def local_networks():
    found = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and a.netmask and not a.address.startswith('127.'):
                try:
                    net = ipaddress.ip_network(f'{a.address}/{a.netmask}', strict=False)
                    if net.is_private and net.num_addresses <= MAX_HOSTS + 2:
                        found.append({'interface': name, 'address': a.address, 'cidr': str(net)})
                except ValueError:
                    pass
    return found


def ping(ip):
    if platform.system() == 'Windows':
        cmd = ['ping', '-n', '1', '-w', '800', ip]
    elif platform.system() == 'Darwin':
        cmd = ['ping', '-n', '-c', '1', '-W', '1000', ip]
    else:
        cmd = ['ping', '-n', '-c', '1', '-W', '1', ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def arp_table():
    commands = [['arp', '-an']] if platform.system() != 'Windows' else [['arp', '-a']]
    found = {}
    for cmd in commands:
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
            for line in output.splitlines():
                ips = re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', line)
                macs = re.findall(r'(?i)(?<![\da-f])(?:[\da-f]{1,2}[:-]){5}[\da-f]{1,2}(?![\da-f])', line)
                if ips and macs:
                    mac = ':'.join(f'{int(x, 16):02x}' for x in re.split('[:-]', macs[0]))
                    found[ips[0]] = mac
        except (OSError, subprocess.TimeoutExpired):
            pass
    return found


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def parse_scan_target(target):
    """Return (normalized label, list of IPv4 hosts) for CIDR or inclusive range."""
    target = str(target or '').strip()
    if '-' in target:
        parts = [p.strip() for p in target.split('-')]
        if len(parts) != 2:
            raise ValueError('Zakres musi mieć postać 192.168.45.34-192.168.45.124.')
        try:
            start, end = (ipaddress.IPv4Address(p) for p in parts)
        except ipaddress.AddressValueError:
            raise ValueError('Nieprawidłowy adres IP w zakresie. Podaj dwa pełne adresy IPv4, np. 192.168.45.34-192.168.45.124.')
        if int(start) > int(end):
            raise ValueError('Adres początkowy zakresu musi być mniejszy lub równy końcowemu.')
        count = int(end) - int(start) + 1
        if count > MAX_HOSTS:
            raise ValueError(f'Zakres przekracza limit {MAX_HOSTS} adresów (MAX_HOSTS).')
        if not all(ipaddress.IPv4Address(v).is_private and not ipaddress.IPv4Address(v).is_loopback and not ipaddress.IPv4Address(v).is_link_local for v in (int(start), int(end))):
            raise ValueError('Dozwolone są wyłącznie prywatne adresy IPv4 RFC1918.')
        # Ensure no public/reserved gap inside the range.
        allowed = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))
        if not any(start in block and end in block for block in allowed):
            raise ValueError('Cały zakres musi należeć do jednej prywatnej przestrzeni RFC1918.')
        return f'{start}-{end}', [str(ipaddress.IPv4Address(int(start) + i)) for i in range(count)]
    try:
        net = ipaddress.ip_network(target, strict=True)
    except ValueError:
        raise ValueError('Podaj poprawną podsieć CIDR (np. 192.168.45.0/24) albo zakres (np. 192.168.45.34-192.168.45.124).')
    if net.version != 4 or not any(net.subnet_of(block) for block in (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))):
        raise ValueError('Dozwolone są tylko prywatne podsieci IPv4 RFC1918.')
    host_count = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
    if host_count > MAX_HOSTS:
        raise ValueError(f'Zbyt duża podsieć. Limit: {MAX_HOSTS} hostów (MAX_HOSTS).')
    return str(net), [str(x) for x in net.hosts()]


def scan(cidr, events=None, job_id=None):
    def emit(**changes):
        if events is not None:
            events.put({"job_id": job_id, **changes})
        else:
            with LOCK: STATE.update(changes)
    def phase(name): emit(phase=name)
    try:
        cidr, hosts = parse_scan_target(cidr)
        emit(total=len(hosts), progress=0)
        phase('Wykrywanie hostów i portów TCP')
        discovered = {}
        def probe(ip):
            reachable = ping(ip)
            ports = tcp_ports(ip)
            return ip, reachable, ports
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(probe, ip) for ip in hosts]
            for future in concurrent.futures.as_completed(futures):
                ip, reachable, ports = future.result()
                if reachable or ports:
                    discovered[ip] = {'ping': reachable, 'ports': ports}
                if events is not None:
                    events.put({'job_id':job_id, 'increment':1})
                else:
                    with LOCK: STATE['progress'] += 1
        phase('ARP, DNS i identyfikacja MAC')
        arp = arp_table()
        host_set = set(hosts)
        for ip in arp:
            if ip in host_set and ip not in discovered:
                discovered[ip] = {'ping': False, 'ports': []}
        alive = sorted(discovered, key=ipaddress.ip_address)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            names = dict(zip(alive, pool.map(hostname, alive)))
        devices = []
        for ip in alive:
            mac = arp.get(ip, 'Nieznany')
            ports = discovered[ip]['ports']
            devices.append({'id': ip, 'ip': ip, 'hostname': names[ip] or 'Nieznany', 'mac': mac,
                            'vendor': None, 'type': classify(ports), 'ports': ports, 'web_panels': web_panels(ip, ports),
                            'status': 'Wykryty', 'ping': discovered[ip]['ping']})
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for device, name in zip(devices, pool.map(vendor, (d['mac'] for d in devices))):
                device['vendor'] = name
        phase('Analiza HTTP i banerów usług')
        # Read-only HTTP metadata and TCP greeting banners; no login or authentication attempts.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            fingerprints=list(pool.map(lambda d:identify(d['ip'],d['ports']),devices))
        for d,fp in zip(devices,fingerprints):
            d['fingerprint']=fp
            d['identified_vendor']=fp['matches'][0]['vendor'] if fp['matches'] else None
            d['identification_method']=fp['matches'][0]['method'] if fp['matches'] else ('MAC OUI' if d['vendor'] else 'brak')
            d['identification_confidence']=fp['matches'][0]['confidence'] if fp['matches'] else ('niska' if d['vendor'] else 'brak')
        phase('Porty specyficzne dla producentów')
        # Match BOTH hardware MAC OUI and independently detected HTTP/service signature.
        def vendor_probe(device):
            names=[device.get('vendor'),device.get('identified_vendor')]
            rules=[]
            for name in names:rules.extend(matching(name))
            already={x['port'] for x in device['ports']}
            metadata={int(r['port']):r for r in rules}
            candidates={int(r['port']):r['service'] for r in rules if int(r['port']) not in already}
            found=tcp_ports(device['ip'],candidates) if candidates else []
            for item in found:
                item['vendor_specific']=True
                item['web_scheme']=metadata[item['port']]['web_scheme']
            return found,len(candidates),sorted({r['vendor'] for r in rules})
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for device,(found,checked,matches) in zip(devices,pool.map(vendor_probe,devices)):
                device['ports']=sorted(device['ports']+found,key=lambda p:p['port'])
                device['vendor_ports_checked']=checked
                device['vendor_profiles']=matches
                device['web_panels']=web_panels(device['ip'],device['ports'])
                device['type']=classify(device['ports'])
        phase('Weryfikacja usług WWW')
        # Check additional discovered HTTP ports for stronger classification and verified URLs.
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            final=list(pool.map(lambda d:identify(d['ip'],d['ports']),devices))
        for d,fp in zip(devices,final):
            d['fingerprint']=fp
            if fp['matches']:
                d['identified_vendor']=fp['matches'][0]['vendor']
                d['identification_method']=fp['matches'][0]['method']
                d['identification_confidence']=fp['matches'][0]['confidence']
            d['web_panels']=[p for p in d['web_panels'] if any(h['port']==p['port'] for h in fp['http'])]
        # No invented physical links: an unauthenticated scan cannot confirm L2 connectivity.
        phase('Zapisywanie inwentarza')
        edges = []
        for d in devices:
            d['snmp'] = {'status':'niezweryfikowane', 'reason':'Bez danych uwierzytelniających nie wykonywano odczytu MIB'}
            d['topology_evidence'] = []
        result = {'cidr': cidr, 'devices': devices, 'edges': edges, 'hypotheses': [], 'topology_note': 'Widok logiczny: urządzenia należą do skanowanej podsieci. Fizyczne połączenia wymagają danych SNMP/LLDP ze switchy.', 'finished': datetime.now().isoformat(timespec='seconds')}
        DATA.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        save_history(result)
        emit(devices=devices, edges=edges, hypotheses=[], error=None, finished=result['finished'], phase='Gotowe')
    except Exception as e:
        emit(error=str(e), phase='Błąd')
    finally:
        emit(running=False)



def save_history(result):
    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(HISTORY, timeout=15) as db:
        db.execute('CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, finished TEXT, cidr TEXT, devices INTEGER, payload TEXT)')
        db.execute('INSERT INTO scans (finished,cidr,devices,payload) VALUES (?,?,?,?)',
                   (result['finished'],result['cidr'],len(result['devices']),json.dumps(result,ensure_ascii=False)))
        db.execute('DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT 50)')

def drain_events():
    global EVENTS, WORKER
    if EVENTS is None: return
    with LOCK:
        for _ in range(8192):
            try: event = EVENTS.get_nowait()
            except queue.Empty: break
            if event.pop('job_id',None) != STATE.get('job_id'): continue
            STATE['progress'] += event.pop('increment',0)
            STATE.update(event)
        if WORKER is not None and not WORKER.is_alive() and STATE['running']:
            # Multiprocessing queues can flush just after the child exits.
            try:
                while True:
                    event=EVENTS.get(timeout=.05)
                    if event.pop('job_id',None)==STATE.get('job_id'):
                        STATE['progress']+=event.pop('increment',0)
                        STATE.update(event)
            except queue.Empty: pass
            if STATE['running']:
                STATE.update(running=False,error='Proces skanowania zakończył się bez wyniku.',phase='Błąd')


# Web terminals: local-only, target must be present in the latest scan.
from flask_sock import Sock
from web_terminal import handle_terminal, inspect_ssh_key, is_scanned_service
sock = Sock(app)

@app.post('/api/terminal/ssh-key')
def terminal_ssh_key():
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'error': 'Terminal jest dostępny wyłącznie lokalnie.'}), 403
    data = request.get_json(silent=True) or {}
    ip, port = str(data.get('ip', '')), data.get('port', 22)
    if not is_scanned_service(DATA, ip, port, 'ssh'):
        return jsonify({'error': 'Nie wykryto SSH dla tego hosta i portu.'}), 400
    try:
        return jsonify(inspect_ssh_key(ip, int(port)))
    except Exception as exc:
        return jsonify({'error': str(exc)}), 502

@sock.route('/ws/terminal')
def terminal_websocket(ws):
    if request.remote_addr not in ('127.0.0.1', '::1'):
        ws.close()
        return
    handle_terminal(ws, DATA)

@app.get('/api/history')
def history():
    if not HISTORY.exists(): return jsonify([])
    with sqlite3.connect(HISTORY) as db:
        rows=db.execute('SELECT id,finished,cidr,devices FROM scans ORDER BY id DESC LIMIT 50').fetchall()
    return jsonify([dict(id=r[0],finished=r[1],cidr=r[2],devices=r[3]) for r in rows])

@app.get('/api/history/<int:scan_id>')
def history_item(scan_id):
    if not HISTORY.exists(): return jsonify({'error':'Brak historii'}),404
    with sqlite3.connect(HISTORY) as db:
        row=db.execute('SELECT payload FROM scans WHERE id=?',(scan_id,)).fetchone()
    return jsonify(json.loads(row[0])) if row else (jsonify({'error':'Nie znaleziono'}),404)

@app.get('/api/export.csv')
def export_csv():
    if not DATA.exists(): return Response('Brak wyników',status=404)
    result=json.loads(DATA.read_text(encoding='utf-8'))
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(['IP','Hostname','MAC','Producent MAC','Rozpoznany producent','Typ','Pewność','Porty TCP','Panele WWW','SNMP'])
    for d in result.get('devices',[]):
        writer.writerow([d.get('ip'),d.get('hostname'),d.get('mac'),d.get('vendor'),d.get('identified_vendor'),
                         d.get('type'),d.get('identification_confidence'),
                         ', '.join(str(p['port']) for p in d.get('ports',[])),
                         ', '.join(p['url'] for p in d.get('web_panels',[])),d.get('snmp',{}).get('status')])
    return Response('\ufeff'+output.getvalue(),mimetype='text/csv; charset=utf-8',
                    headers={'Content-Disposition':'attachment; filename=netmapper_inventory.csv'})

@app.get('/')
def index():
    return render_template('index.html')


@app.get('/api/vendor-database')
def vendor_database():
    return jsonify(database_info())


@app.get('/api/interfaces')
def interfaces():
    return jsonify(local_networks())


@app.post('/api/scan')
def start():
    cidr = (request.get_json(silent=True) or {}).get('cidr', '')
    try:
        normalized, _ = parse_scan_target(cidr)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    global EVENTS, WORKER
    with LOCK:
        if STATE['running']:
            return jsonify({'error': 'Skanowanie już trwa.'}), 409
        job_id = datetime.now().strftime('%Y%m%d%H%M%S%f')
        STATE.update(running=True, devices=[], edges=[], hypotheses=[], error=None, progress=0,
                     total=0, phase='Uruchamianie procesu', job_id=job_id,
                     started=datetime.now().isoformat(timespec='seconds'), finished=None)
        EVENTS = mp.get_context('spawn').Queue()
        WORKER = mp.get_context('spawn').Process(target=scan, args=(normalized, EVENTS, job_id), daemon=True)
        WORKER.start()
    return jsonify({'ok': True, 'job_id':job_id})


@app.post('/api/scan/stop')
def stop_scan():
    global WORKER, EVENTS
    drain_events()
    with LOCK:
        if not STATE['running']:
            return jsonify({'ok': True, 'stopped': False, 'message': 'Brak aktywnego skanowania.'})
        worker = WORKER
        # Invalidate queued events from the cancelled job.
        STATE.update(running=False, phase='Zatrzymano przez użytkownika', error=None,
                     finished=datetime.now().isoformat(timespec='seconds'), job_id=None)
        WORKER = None
        EVENTS = None
    if worker is not None and worker.is_alive():
        worker.terminate()
        worker.join(timeout=2)
        if worker.is_alive():
            worker.kill()
            worker.join(timeout=1)
    return jsonify({'ok': True, 'stopped': True})


# Aktualizacje wyłącznie z lokalnego panelu. ZIP to kod wykonywalny: instaluj zaufane paczki.
from updater import installed_version, inspect_package, install, restart_later, MAX_ZIP_BYTES

@app.get('/api/update/info')
def update_info():
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'error': 'Aktualizacje dostępne wyłącznie lokalnie.'}), 403
    return jsonify({'version': installed_version(), 'max_size_mb': 25})

@app.post('/api/update')
def update_upload():
    if request.remote_addr not in ('127.0.0.1', '::1'):
        return jsonify({'error': 'Aktualizacje dostępne wyłącznie lokalnie.'}), 403
    origin = request.headers.get('Origin')
    if origin:
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        if parsed.hostname not in ('127.0.0.1', 'localhost', '::1') or parsed.port != get_server_port():
            return jsonify({'error': 'Niedozwolone źródło żądania.'}), 403
    if request.headers.get('X-NetMapper-Update') != '1':
        return jsonify({'error': 'Brak nagłówka aktualizacji.'}), 403
    with LOCK:
        if STATE.get('running'):
            return jsonify({'error': 'Zatrzymaj skanowanie przed aktualizacją.'}), 409
    file = request.files.get('package')
    if not file or not file.filename.lower().endswith('.zip'):
        return jsonify({'error': 'Wybierz plik ZIP z aktualizacją.'}), 400
    try:
        payload = file.read(MAX_ZIP_BYTES + 1)
        result = install(payload)
    except (ValueError, OSError, RuntimeError) as exc:
        return jsonify({'error': str(exc)}), 400
    restart_later()
    return jsonify(result)

@app.get('/api/status')
def status():
    drain_events()
    with LOCK:
        return jsonify(dict(STATE))


@app.get('/api/results')
def results():
    drain_events()
    if not DATA.exists():
        return jsonify({'devices': [], 'edges': []})
    return jsonify(json.loads(DATA.read_text(encoding='utf-8')))



def get_server_port():
    """PORT environment variable > local port.txt > default 6969."""
    raw = os.environ.get('PORT')
    if raw is None:
        path = Path(__file__).resolve().parent / 'port.txt'
        raw = path.read_text(encoding='utf-8').strip() if path.exists() else '6969'
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValueError('Niepoprawny port: wpisz liczbę od 1 do 65535.')
    if not 1 <= port <= 65535:
        raise ValueError('Port musi być w zakresie 1–65535.')
    return port


if __name__ == '__main__':
    mp.freeze_support()
    app.run(host=os.getenv('HOST', '127.0.0.1'), port=get_server_port(), debug=False)
