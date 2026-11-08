"""Local-only, scan-bound interactive SSH/Telnet websocket sessions."""
import base64
import hashlib
import ipaddress
import json
import select
import socket
import threading
import time
from pathlib import Path

import paramiko

MAX_OUTPUT = 16384
MAX_INPUT = 4096


def is_scanned_service(data_path, ip, port, protocol):
    try:
        addr = ipaddress.ip_address(ip)
        port = int(port)
        if addr.version != 4 or not addr.is_private or not 1 <= port <= 65535:
            return False
        devices = json.loads(Path(data_path).read_text(encoding='utf-8')).get('devices', [])
        for d in devices:
            if d.get('ip') != ip:
                continue
            for p in d.get('ports', []):
                name = str(p.get('service', '')).lower()
                if int(p.get('port', -1)) == port and ((protocol == 'ssh' and (port == 22 or 'ssh' in name)) or (protocol == 'telnet' and (port == 23 or 'telnet' in name))):
                    return True
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return False


def inspect_ssh_key(ip, port):
    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=7)
        key = transport.get_remote_server_key()
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        return {'fingerprint': 'SHA256:' + fingerprint, 'key_type': key.get_name()}
    finally:
        if transport:
            transport.close()


def send(ws, kind, **kwargs):
    ws.send(json.dumps({'type': kind, **kwargs}, ensure_ascii=False))


def handle_terminal(ws, data_path):
    conn = None
    ssh = None
    stop = threading.Event()
    try:
        init = json.loads(ws.receive() or '{}')
        ip, port, proto = str(init.get('ip', '')), int(init.get('port', 0)), str(init.get('protocol', ''))
        if proto not in ('ssh', 'telnet') or not is_scanned_service(data_path, ip, port, proto):
            send(ws, 'error', message='Host lub usługa nie znajduje się w ostatnim skanie.')
            return
        if proto == 'ssh':
            username = str(init.get('username', ''))
            password = str(init.get('password', ''))
            expected = str(init.get('fingerprint', ''))
            if not username or not expected or len(username) > 128 or len(password) > 1024:
                send(ws, 'error', message='Podaj użytkownika i zaakceptowany odcisk klucza serwera.')
                return
            ssh = paramiko.SSHClient()
            class PinnedKey(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    actual = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
                    if actual != expected:
                        raise paramiko.SSHException('Klucz serwera zmienił się! Przerwano połączenie.')
                    client.get_host_keys().add(hostname, key.get_name(), key)
            ssh.set_missing_host_key_policy(PinnedKey())
            ssh.connect(ip, port=port, username=username, password=password, timeout=8, auth_timeout=10,
                        banner_timeout=8, allow_agent=False, look_for_keys=False)
            conn = ssh.invoke_shell(width=120, height=32)
            conn.settimeout(0.2)
        else:
            conn = socket.create_connection((ip, port), timeout=8)
            conn.settimeout(0.2)
        send(ws, 'connected')
        write_lock = threading.Lock()
        def reader():
            negotiation = bytearray()
            try:
                while not stop.is_set():
                    try:
                        data = conn.recv(MAX_OUTPUT)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    if proto == 'telnet':
                        data, responses = strip_telnet(data, negotiation)
                        for response in responses:
                            conn.sendall(response)
                    if data:
                        with write_lock:
                            send(ws, 'output', data=data.decode('utf-8', errors='replace'))
            except (OSError, EOFError, RuntimeError):
                pass
            finally:
                stop.set()
                try:
                    with write_lock:
                        send(ws, 'closed')
                except Exception:
                    pass
        threading.Thread(target=reader, daemon=True).start()
        while not stop.is_set():
            raw = ws.receive()
            if raw is None:
                break
            message = json.loads(raw)
            if message.get('type') == 'input':
                data = str(message.get('data', ''))
                if len(data) > MAX_INPUT:
                    continue
                payload = data.encode('utf-8')
                if proto == 'telnet':
                    payload = payload.replace(b'\xff', b'\xff\xff')
                    conn.sendall(payload)
                else:
                    conn.send(payload)
            elif message.get('type') == 'resize' and proto == 'ssh':
                cols = max(40, min(240, int(message.get('cols', 120))))
                rows = max(12, min(80, int(message.get('rows', 32))))
                conn.resize_pty(width=cols, height=rows)
    except Exception as exc:
        try:
            send(ws, 'error', message=f'Nie udało się nawiązać połączenia: {exc}')
        except Exception:
            pass
    finally:
        stop.set()
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        if ssh:
            ssh.close()


def strip_telnet(data, pending):
    """Minimal IAC negotiation: decline all options, preserve regular bytes."""
    pending.extend(data)
    output, responses = bytearray(), []
    i = 0
    while i < len(pending):
        if pending[i] != 255:
            output.append(pending[i]); i += 1; continue
        if i + 1 >= len(pending):
            break
        command = pending[i + 1]
        if command == 255:
            output.append(255); i += 2; continue
        if command in (251, 252, 253, 254):
            if i + 2 >= len(pending):
                break
            option = pending[i + 2]
            responses.append(bytes([255, 254 if command in (251, 252) else 252, option]))
            i += 3; continue
        if command == 250:  # subnegotiation, until IAC SE
            end = pending.find(b'\xff\xf0', i + 2)
            if end < 0:
                break
            i = end + 2; continue
        i += 2
    del pending[:i]
    if len(pending) > 4096:
        pending.clear()
    return bytes(output), responses
