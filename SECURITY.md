# NetMapper security

## Access model

NetMapper is a local tool. It binds to 127.0.0.1 by default. The web interface has no authentication. Scan, result, and history endpoints do not check the client address. Changing HOST may expose them to other computers.

Terminal and update endpoints check for loopback clients. Updates require a custom header and validate Origin when present. The terminal WebSocket has no application-level Origin check. A local bind address should not be treated as complete protection against browser-originated requests.

## Credentials and results

SSH credentials are entered for a session and sent to the backend over WebSocket. The code does not save them to a configuration file. Do not publish terminal captures, diagnostic logs, or captured session traffic. Telnet transmits data without encryption.

The results.json file and history database contain network data, including IP addresses, MAC addresses, hostnames, and HTTP metadata. Do not attach them to public bug reports. Use anonymized data in examples.

## Identification and updates

HTTPS probes skip certificate validation when discovering internal web interfaces. A signature match does not establish a device's identity. SSH host key fingerprints require independent verification.

ZIP packages contain executable code. The updater validates paths, allowed files, and Python syntax, but does not verify release signatures. File backups and restoration after write errors do not replace a full backup or testing a new release.

## Reporting issues

Do not include secrets or real scan results in public issues. The repository owner should configure a private vulnerability reporting channel before publishing the project.
