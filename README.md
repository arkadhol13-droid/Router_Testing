#  Router Testing & Optical Power Monitoring Tool

**A Python Flask-based application for telecom network diagnostics, router interface monitoring, and SFP optical power analysis.**

This project simplifies router testing by collecting network interface status, SFP module information, and optical transmit/receive power readings through SSH-based automation. It helps network and telecom operations teams organize diagnostic results and generate structured reports efficiently.

##  Key Features

- **Router Connectivity Testing** — Connect to authorized network devices through SSH.
- **Interface Status Monitoring** — Identify interfaces that are UP or DOWN.
- **Optical Power Analysis** — Collect SFP TX/RX optical power readings.
- **SFP Information Extraction** — Retrieve available transceiver details.
- **Automated Diagnostics** — Execute supported router commands using Netmiko.
- **CSV Reporting** — Export collected diagnostic data for further analysis.
- **Web-Based Interface** — Access testing functionality through a Flask application.
- **User & Admin Management** — Includes login and administration functionality.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Flask | Web application framework |
| Netmiko | Network device SSH automation |
| Paramiko | SSH connectivity library |
| HTML & CSS | Web interface |
| CSV | Diagnostic report export |

##  How It Works

1. Open the web application and provide the required router connection details.
2. Connect to an authorized network device through SSH.
3. Execute supported interface and transceiver commands.
4. Collect interface status, SFP information, and available optical power readings.
5. Review the diagnostic results and export the report to CSV.

## ⚙️ Installation & Setup

**Prerequisites:** Python 3.10+ and authorized SSH access to the target network devices.

Clone the repository:

```bash
git clone https://github.com/arkadhol13-droid/Router_Testing
cd Router_Testing
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

On Windows:

```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
python app.py
```

Open your browser and visit:

`http://127.0.0.1:5000`

## 🎯 Project Objectives

- Reduce repetitive manual router diagnostic work.
- Improve visibility into interface and optical power status.
- Organize network troubleshooting information in structured reports.
- Support telecom operations through Python-based network automation.

## 🔮 Future Enhancements

- Real-time network health dashboards.
- Historical TX/RX power trend analysis.
- Configurable optical power thresholds and alerts.
- AI-assisted diagnostic summaries and troubleshooting recommendations.
- Automated scheduled testing and report generation.

## 🔐 Security

- Use authorized network devices and approved credentials only.
- Store passwords and Flask secret keys securely using environment variables.
- Do not commit credentials, local databases, or sensitive network information to GitHub.
- Configure production-grade authentication and access controls before deployment.

## 👨‍💻 Author

**Arka Dhol**

GitHub: [@arkadhol13-droid](https://github.com/arkadhol13-droid)

---

*Built with Python to simplify telecom network testing, diagnostics, and reporting.*
