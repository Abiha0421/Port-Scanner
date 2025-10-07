<br />

<!-- PROJECT INFO -->
<br />
<div align="center">

<h3 align="center"> TCP Port Scanner GUI </h3>
  <p align="center">
    An interactive Python-based TCP Port Scanner with a modern CustomTkinter GUI. This tool allows users to quickly scan hosts for open ports, grab banners, and visualize results in a clean and customizable interface.
</p>
<p align="center">
   <a href="https://www.linkedin.com/">
    <img src="https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&" alt="Logo">
     </a>
    <a href="https://github.com/">
    <img src="https://img.shields.io/badge/-github-black.svg?style=for-the-badge&logo=github&" alt="Logo">
     </a>
</p>
 <p>
<img alt="Release "  src="https://img.shields.io/badge/release-v1.0-blue">
<img alt="Author"  src="https://img.shields.io/badge/author-Abiha-green">
</p>

</div>

## Requirment

<p>
<img alt="npm version" 	src="https://img.shields.io/badge/python-3.10+-red">
</p>

## Features
- **Port scanning** — Scan a single host or hostname across a port range (e.g., 1-1024).
- **Banner grabbing** — Attempt to read an initial banner from an open TCP port to help identify the service.
- **Filter results** — Toggle between viewing all scanned ports or only open ports.
- **Customizable themes** — Light, Dark, and Neon UI themes.
- **Settings manager** — Tabs for Appearance, Scan options (timeouts, concurrency), and Reports.
- **Presets & history** — Save scan presets (e.g., "quick", "full"), and access recent targets.
- **Report export** — Save scan reports as PDF (via reportlab) or CSV for documentation.
- **Real-time UI** — Live results, progress bar, and scan status messages.
- **Safe defaults** — Conservative timeouts and limited concurrency to avoid accidental DoS.

## Install Dependencies

```bash
# use to install the required dependencies
pip install -r requirements.txt
```
## basic CLI usage

```bash
python3 tcp_port_scanner.py [-h] [--ports PORTS] [--top TOP] [--timeout TIMEOUT] [--threads THREADS] [--csv CSV] [--json JSON] [--pdf PDF] [--json-only] target
```
## Quickstart (GUI)

Launch the app using command:
```bash
python3 tcp_port_scanner_gui.py
```
#### In the GUI:

- Enter a target IP address or hostname (e.g., 192.168.1.10, example.local).
- Enter a port range (e.g., 1-1024 or 22,80,443).
- Choose a preset or open Settings to tune concurrency and timeouts.
- Click Start Scan and watch results appear in real time.
- Export the results using the Export button (PDF/CSV).

> Tip: use a small port range and low concurrency for initial tests.

## Security & Ethics
This repo is intended for educational and penetration testing lab purposes only. Do not use it against systems without explicit authorization.
