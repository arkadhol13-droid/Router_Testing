
from flask import (
    Flask, render_template, request, send_file, jsonify,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import sqlite3
import re
import csv
import io
import os

app = Flask(__name__)
app.secret_key = "278ca2c1dc8cc449eb1dc7f59eb1bcb66c8a9dea3d6b41c271b9e617612d47f4"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

# Default admin account (pehli baar app chalne par ban jayega)
DEFAULT_ADMIN_EMAIL = "admin@company.com"
DEFAULT_ADMIN_PASSWORD = "Admin@123"      
MAX_WORKERS = 5

# Router commands 
COMMAND_POWER = "show interface transceiver"
COMMAND_STATUS = "show interface description"
COMMAND_CONTROLLER = "show interface controller"

# CSV / table columns 
FIELDNAMES = [
    "IP", "Device Name", "GP Site Name", "Interface", "Port Status",
    "TX Power (dBm)", "RX Power (dBm)",
    "Ethernet/Ext-Eth Compliance", "Length SMF", "Wavelength", "SFP Name",
    "Expected TX Range (dBm)", "Expected RX Sensitivity (dBm)",
    "TX Status", "RX Status", "Result",
]

# Last scan results dashboard + CSV 
LAST_RESULTS = []

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    admin = conn.execute(
        "SELECT id FROM users WHERE email = ?", (DEFAULT_ADMIN_EMAIL,)
    ).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (email, password_hash, role, status) "
            "VALUES (?, ?, 'admin', 'approved')",
            (DEFAULT_ADMIN_EMAIL, generate_password_hash(DEFAULT_ADMIN_PASSWORD)),
        )
        conn.commit()
    conn.close()

init_db()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or session.get("status") != "approved":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or session.get("role") != "admin":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

row_pattern = re.compile(
    r"^(\S+)\s+(Active|Inactive)\s+(\S+)\s+(\S+)\s+(\S+)\s+(On|Off)\s+(On|Off)"
    r"\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$",
    re.MULTILINE
)

# "show interface description
status_pattern = re.compile(
    r"^(\S+)[ \t]+(up|down)[ \t]+(up|down)(?:[ \t]+(\S.*?))?[ \t]*$",
    re.MULTILINE
)

SFP_THRESHOLDS = {
    "1G_SX": {
        "tx_min": -9.5, "tx_max": -3.0, "rx_floor": -18.0,
        "tx_text": "-9.5 to -3", "rx_text": "-18 to -20",
    },
    "1G_LX": {
        "tx_min": -9.5, "tx_max": -3.0, "rx_floor": -18.0,
        "tx_text": "-9.5 to -3", "rx_text": "-18 to -20",
    },
    "10G_SR": {
        "tx_min": -7.3, "tx_max": -1.0, "rx_floor": -11.0,
        "tx_text": "-7.3 to -1", "rx_text": "~ -11",
    },
    "10G_LR": {
        "tx_min": -8.2, "tx_max": 0.5, "rx_floor": -14.4,
        "tx_text": "-8.2 to +0.5", "rx_text": "~ -14.4",
    },
    "10G_ER": {
        "tx_min": -4.7, "tx_max": 4.0, "rx_floor": -15.8,
        "tx_text": "-4.7 to +4", "rx_text": "~ -15.8",
    },
    "25G_SRLR": {
        "tx_min": -8.0, "tx_max": 2.0, "rx_floor": -10.0,
        "tx_text": "-8 to +2", "rx_text": "-10 to -13",
    },
}

def classify_compliance(compliance_str):
    """Ethernet/Ext-Eth Compliance string se speed + optics type nikalta hai."""
    c = (compliance_str or "").upper()
    if "1000BASE-SX" in c:
        return "1G_SX"
    if "1000BASE-LX" in c:
        return "1G_LX"
    if "10GBASE-SR" in c:
        return "10G_SR"
    if "10GBASE-LR" in c:
        return "10G_LR"
    if "10GBASE-ER" in c:
        return "10G_ER"
    if "25GBASE-SR" in c or "25GBASE-LR" in c:
        return "25G_SRLR"
    return None

def _to_float(value_str):
    """'-6.178' / '+2.936' -> float. 'Router Down' / '--' -> None."""
    try:
        return float(str(value_str).strip())
    except (ValueError, TypeError, AttributeError):
        return None

def evaluate_tx(value_str, spec):
    """TX power band ke andar hona chahiye -> Good / Need Attention / Unknown."""
    val = _to_float(value_str)
    if val is None or not spec:
        return "Unknown"
    return "Good" if spec["tx_min"] <= val <= spec["tx_max"] else "Need Attention"

def evaluate_rx(value_str, spec):
    """RX signal sensitivity floor se strong (upar) hona chahiye."""
    val = _to_float(value_str)
    if val is None or not spec:
        return "Unknown"
    return "Good" if val >= spec["rx_floor"] else "Need Attention"

def parse_controller_output(output):
    """Controller output ko port-number-wise dictionary me todta hai."""
    blocks = re.split(r"^#+\s*$", output, flags=re.MULTILINE)
    port_data = {}
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        fields = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            label, _, value = line.partition(":")
            label = label.strip()
            value = value.strip()
            if label in fields:
                # "Length SMF" 
                if isinstance(fields[label], list):
                    fields[label].append(value)
                else:
                    fields[label] = [fields[label], value]
            else:
                fields[label] = value
        port_no = fields.get("Port Number")
        if port_no:
            port_data[str(port_no).strip()] = fields
    return port_data

def get_sfp_info(interface, port_data):
    """
    Interface (xe9 -> port 9) se SFP block match karta hai.
    Returns: (display_fields_dict, threshold_spec_or_None)
    """
    blank = {
        "Ethernet/Ext-Eth Compliance": "",
        "Length SMF": "",
        "Wavelength": "",
        "SFP Name": "",
        "Expected TX Range (dBm)": "N/A",
        "Expected RX Sensitivity (dBm)": "N/A",
    }

    m = re.search(r"(\d+)$", interface or "")
    if not m:
        return blank, None
    fields = port_data.get(m.group(1), {})
    if not fields:
        return blank, None

    length_smf = fields.get("Length SMF", "")
    if isinstance(length_smf, list):
        length_smf = " / ".join(length_smf)

    compliance = fields.get("Ethernet/Ext-Eth Compliance", "")
    spec = SFP_THRESHOLDS.get(classify_compliance(compliance))

    info = {
        "Ethernet/Ext-Eth Compliance": compliance,
        "Length SMF": length_smf,
        "Wavelength": fields.get("Wave Length", fields.get("Wavelength", "")),
        "SFP Name": fields.get("Name", ""),
        "Expected TX Range (dBm)": spec["tx_text"] if spec else "N/A",
        "Expected RX Sensitivity (dBm)": spec["rx_text"] if spec else "N/A",
    }
    return info, spec

def send_paged_command(conn, command, more_marker="--More--"):
    """Lamba output '--More--' pe rukta hai - space bhej ke pura collect karta hai."""
    output = conn.send_command_timing(
        command, strip_prompt=False, strip_command=False, read_timeout=15
    )
    full_output = output
    tries = 0
    while more_marker in output and tries < 80:
        output = conn.send_command_timing(
            " ", strip_prompt=False, strip_command=False, read_timeout=15
        )
        full_output += output
        tries += 1
    return full_output.replace(more_marker, "")

def error_row(ip, device_name, power_text, result_text):
    """Fail hone par ek consistent row banata hai (saare columns bharke)."""
    row = {k: "N/A" for k in FIELDNAMES}
    row.update({
        "IP": ip,
        "Device Name": device_name,
        "TX Power (dBm)": power_text,
        "RX Power (dBm)": power_text,
        "TX Status": "Unknown",
        "RX Status": "Unknown",
        "Result": result_text,
    })
    return row

def check_router(ip, username, password, port=22):
    """Ek router se connect karke power + status + SFP details nikalta hai."""
    try:
        conn = ConnectHandler(
            device_type="generic",
            ip=ip,
            username=username,
            password=password,
            timeout=10,
            port=port,
        )
        device_name = conn.find_prompt().strip()
        output_power = conn.send_command(COMMAND_POWER, expect_string=r"#|>")
        output_status = conn.send_command(COMMAND_STATUS, expect_string=r"#|>")

        # Controller command optional 
        try:
            port_data = parse_controller_output(
                send_paged_command(conn, COMMAND_CONTROLLER)
            )
        except Exception:
            port_data = {}

        conn.disconnect()

        status_map = {
            m.group(1): {
                "status": f"{m.group(2)}/{m.group(3)}",
                "gp_name": m.group(4) if m.group(4) else "N/A (Not Connected)",
            }
            for m in status_pattern.finditer(output_status)
        }

        matches = list(row_pattern.finditer(output_power))
        if not matches:
            return [error_row(
                ip, device_name, "Not Found",
                "Pattern not matched (check command output format)"
            )]

        rows = []
        for m in matches:
            interface = m.group(1)
            tx_power = m.group(10)
            rx_power = m.group(11)

            info = status_map.get(interface, {})
            sfp, spec = get_sfp_info(interface, port_data)

            row = {
                "IP": ip,
                "Device Name": device_name,
                "GP Site Name": info.get("gp_name", "Unknown"),
                "Interface": interface,
                "Port Status": info.get("status", "Unknown"),
                "TX Power (dBm)": tx_power,
                "RX Power (dBm)": rx_power,
                "TX Status": evaluate_tx(tx_power, spec),
                "RX Status": evaluate_rx(rx_power, spec),
                "Result": "OK",
            }
            row.update(sfp)
            rows.append(row)
        return rows

    except (NetmikoTimeoutException, TimeoutError):
        return [error_row(ip, "Unreachable", "Router Down",
                          "Router Down (Timeout/Unreachable)")]

    except NetmikoAuthenticationException:
        return [error_row(ip, "Unknown", "Auth Failed",
                          "Authentication Failed")]

    except (SSHException, EOFError, OSError) as e:
        # "Socket is closed" 
        return [error_row(ip, "Unknown", "Connection Lost",
                          f"Connection Lost (session closed mid-command: {e})")]

    except Exception as e:
        return [error_row(ip, "Unknown", "Error", f"Error: {e}")]

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("register"))

        conn = get_db()
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            conn.close()
            flash("An account with this email already exists.")
            return redirect(url_for("register"))

        conn.execute(
            "INSERT INTO users (email, password_hash, role, status) "
            "VALUES (?, ?, 'user', 'pending')",
            (email, generate_password_hash(password)),
        )
        conn.commit()
        conn.close()
        flash("Account created. Please wait for admin approval before logging in.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        if user["status"] == "pending":
            flash("Your account is awaiting admin approval.")
            return redirect(url_for("login"))

        if user["status"] == "rejected":
            flash("Your access has been revoked. Contact the admin.")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["role"] = user["role"]
        session["status"] = user["status"]

        if user["role"] == "admin":
            return redirect(url_for("admin_panel"))
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@admin_required
def admin_panel():
    conn = get_db()
    pending = conn.execute(
        "SELECT * FROM users WHERE status = 'pending' ORDER BY created_at DESC"
    ).fetchall()
    approved = conn.execute(
        "SELECT * FROM users WHERE status = 'approved' AND role != 'admin' "
        "ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template(
        "admin.html",
        pending=pending,
        approved=approved,
        admin_email=session.get("email"),
    )

@app.route("/admin/approve/<int:user_id>", methods=["POST"])
@admin_required
def approve_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET status = 'approved' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

@app.route("/admin/reject/<int:user_id>", methods=["POST"])
@admin_required
def reject_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET status = 'rejected' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

@app.route("/admin/kickout/<int:user_id>", methods=["POST"])
@admin_required
def kickout_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET status = 'rejected' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_panel"))

@app.route("/")
@login_required
def index():
    return render_template(
        "index.html", email=session.get("email"), role=session.get("role")
    )

@app.route("/dashboard")
@login_required
def dashboard():
    total_scanned_ips = len({r["IP"] for r in LAST_RESULTS}) if LAST_RESULTS else 0
    up_count = sum(
        1 for r in LAST_RESULTS
        if str(r.get("Port Status", "")).lower().split("/")[0] == "up"
    )
    down_count = sum(
        1 for r in LAST_RESULTS if str(r.get("Result", "")).startswith("Router Down")
    )
    ok_count = sum(1 for r in LAST_RESULTS if r.get("Result") == "OK")
    auth_fail_count = sum(
        1 for r in LAST_RESULTS if r.get("Result") == "Authentication Failed"
    )
    need_attention_count = sum(
        1 for r in LAST_RESULTS
        if r.get("TX Status") == "Need Attention" or r.get("RX Status") == "Need Attention"
    )

    return render_template(
        "dashboard.html",
        email=session.get("email"),
        role=session.get("role"),
        total_scanned_ips=total_scanned_ips,
        up_count=up_count,
        down_count=down_count,
        ok_count=ok_count,
        auth_fail_count=auth_fail_count,
        need_attention_count=need_attention_count,
        total_rows=len(LAST_RESULTS),
        recent=LAST_RESULTS[-10:][::-1],
    )

@app.route("/run", methods=["POST"])
@login_required
def run_check():
    global LAST_RESULTS

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    ip_text = request.form.get("ip_list", "").strip()

    # IPs textarea 
    ip_list = []
    if ip_text:
        ip_list.extend(p.strip() for p in re.split(r"[,\s]+", ip_text) if p.strip())

    # IPs CSV upload 
    csv_file = request.files.get("csv_file")
    if csv_file and csv_file.filename:
        content = csv_file.stream.read().decode("utf-8", errors="ignore")
        for line in content.splitlines():
            for cell in line.split(","):
                cell = cell.strip()
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", cell):
                    ip_list.append(cell)

    # Duplicates remove
    seen = set()
    ip_list = [ip for ip in ip_list if not (ip in seen or seen.add(ip))]

    if not ip_list:
        return jsonify({"results": [], "ip_count": 0})

    # Parallel scan 
    all_results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_router, ip, username, password): ip
            for ip in ip_list
        }
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as e:
                all_results.append(error_row(futures[future], "Unknown",
                                             "Error", f"Error: {e}"))

    # Results ko IP order me sort karo (jaise user ne daale the)
    order = {ip: i for i, ip in enumerate(ip_list)}
    all_results.sort(key=lambda r: order.get(r["IP"], 999999))

    LAST_RESULTS = all_results
    return jsonify({"results": all_results, "ip_count": len(ip_list)})

@app.route("/download_csv")
@login_required
def download_csv():
    if not LAST_RESULTS:
        return "No scan results yet. Run a check first.", 400

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(LAST_RESULTS)

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="optical_power_report.csv",
    )

if __name__ == "__main__":
    app.run(debug=False, use_reloader=False, threaded=True, host="0.0.0.0", port=5000)
