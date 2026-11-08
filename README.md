# NetMapper

A local private IPv4 network scanner with a web interface. Version 8.11.

## Features

- Host discovery using ping, selected TCP ports, and the ARP table.
- CIDR subnet scanning or inclusive address ranges within private RFC1918 networks.
- Vendor identification using local IEEE registries, HTTP metadata, and service banners.
- Logical device map, searchable inventory, and links to detected web interfaces.
- Local SQLite history of the latest 50 scans; JSON and CSV export of the latest saved result.
- Browser-based SSH and Telnet sessions for services found in the latest scan.
- Local ZIP updates with backups of replaced files.

The map does not establish physical connections. This version does not query SNMP/LLDP or scan UDP. Port-based classification and signature matching are heuristic.

## Running on macOS

Run these commands from the directory containing `app.py`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python update_oui.py
python app.py
```

Open http://127.0.0.1:6969.

`update_oui.py` downloads the IEEE registries from the official server. They are stored locally and are not included in the repository. The application can run without them, but MAC vendor identification will be limited. Restart the application after updating the database.

The system commands `ping` and `arp` must be available. Python dependencies are listed in `requirements.txt`. The project does not declare a minimum Python version; use an interpreter supported by those dependencies.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| HOST | 127.0.0.1 | Web server bind address |
| PORT | 6969 | HTTP port |
| SCAN_WORKERS | 16 | Concurrent host workers, clamped to 2–32 |
| PORT_WORKERS | 8 | Concurrent port workers, clamped to 2–16 |
| MAX_HOSTS | 1024 | Maximum hosts per scan |

Port selection order: the `PORT` environment variable, the local `port.txt` file, then 6969. The application reads process environment variables; it does not automatically load a `.env` file.

To use another port:

```bash
PORT=7070 python app.py
```

To run NetMapper through PyHub, place the application folder in `projects/`, install its requirements, and start `python app.py`. Set the project URL to match the application's port.

## Scanning and terminal sessions

Select a detected local network or enter a CIDR subnet or two full IPv4 addresses separated by a hyphen. Scan only networks you are authorized to access. STOP terminates the scan worker and does not guarantee a complete partial result.

The terminal uses WebSocket, Paramiko for SSH, and TCP sockets for Telnet. SSH requires a username, password, and confirmation of the host key fingerprint. Verify the fingerprint through a trusted source. Telnet does not encrypt traffic. Terminal access is restricted to loopback clients and services listed in the latest saved scan.

## Local data

`results.json` stores the latest result, `data/history.sqlite3` stores scan history, and `data/ieee/` stores downloaded IEEE registries. These files are created during use and ignored by Git. Do not commit them: they may contain IP addresses, MAC addresses, hostnames, and HTTP response fragments.

Export uses the latest result on disk, even when an older scan is displayed in the interface.

## Updates

The update panel accepts trusted packages containing a `VERSION` file. Limits are 25 MiB compressed, 80 MiB unpacked, and 150 files. Stop scanning before updating. Restarting disconnects terminal sessions. Install new dependencies separately with pip.

GitHub's “Download ZIP” archive is not automatically compatible with the built-in updater. The updater accepts a restricted file list and an optional top-level directory named `netmapper`. This repository contains additional documentation intended for source publication.

## Security

The web interface has no authentication. Keep `HOST=127.0.0.1` and do not expose the application directly to the Internet. See [SECURITY.md](SECURITY.md) for limitations.

## Publishing the source

Publish the contents of this directory. Runtime files and network data are excluded by `.gitignore`. Review `git status` and `git diff --cached` before every commit. Do not force-add ignored files with `git add -f`.

No license is included. The project owner should choose a license before granting others permission to reuse the code.
