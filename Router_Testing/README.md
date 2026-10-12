# Router Testing Tool

A Flask web app for checking network routers over SSH. It collects interface status, SFP details, and TX/RX optical power, then exports scan results to CSV.

## Features
- Router checks using Netmiko/SSH
- Interface up/down and optical TX/RX power reporting
- SFP details and basic threshold checks
- CSV upload and report export
- Login, user approval, and admin panel

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Important
Configure a secure Flask secret key and change/remove the default admin credentials before deployment. Use only on routers you are authorized to access.
