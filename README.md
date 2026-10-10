# FirewallGuard: Web-Based Windows Firewall Rule Management & Network Traffic Filtering System (Alpha Development Phase)

> **Course**: INFORMATION ASSURANCE AND SECURITY 2 (IAS 2)  
> **Topic**: #19 Firewall Rule Management System  
> **Technologies**: Python (Flask, Werkzeug), PowerShell (NetSecurity Subprocess), SQLite, HTML5/CSS3, JavaScript, Bootstrap 5, Chart.js

---

## 🛡️ Executive System Overview

**FirewallGuard** is a centralized, robust web-based management system designed to administer **Windows Defender Firewall** policies, perform packet filtering, inspect live host sockets, and record security logs.

The system transitions Windows Firewall administration from command-line friction (`netsh advfirewall` and PowerShell) to an interactive, role-controlled web application.

```
User Login (Validation & Hashing)
  │
  ▼
Dashboard (KPIs, Profile Toggles, Throughput Chart)
  │
  ├─► Firewall Rule Management (Validation, Conflicts, CRUD, PowerShell Sync)
  │
  ├─► Live Traffic & Sockets (Subprocess netstat / sockets, Threat Simulator, Quick Block)
  │
  ├─► Security Event Logs (Filterable, CSV/JSON Export, Admin Purge)
  │
  └─► System Settings (Windows Profile Scopes, Audit Logs, RBAC User Management)
```

---

## 🌟 Functional Upgrades (Alpha Phase)

### 1. Authentication & Security Hardening
- **Password Hashing**: User passwords stored with Werkzeug's secure hashing algorithms (`scrypt` / `pbkdf2:sha256`).
- **Input Validation**: Strict login input validation (username formatting, minimum password length, sanitized inputs).
- **Session Protection**: Real session management with `@login_required` decorator guarding all protected views and REST APIs.

### 2. Strict Role-Based Access Control (RBAC)
- **Roles & Permissions Matrix**:
  | Action / Capability | Administrator | Security Operator | Viewer |
  |---|:---:|:---:|:---:|
  | View Dashboard, Rule Inventory, Traffic & Logs | ✅ | ✅ | ✅ |
  | Export Security Logs (CSV / JSON) | ✅ | ✅ | ✅ |
  | Enable / Disable Existing Firewall Rules | ✅ | ✅ | ❌ |
  | Synchronize Active Rules to Windows Firewall | ✅ | ✅ | ❌ |
  | Simulate Port Scan / Packet Threat Test | ✅ | ✅ | ❌ |
  | Create & Edit Firewall Rules | ✅ | ❌ | ❌ |
  | Delete Firewall Rules | ✅ | ❌ | ❌ |
  | Toggle Windows Defender Profiles (Domain/Private/Public) | ✅ | ❌ | ❌ |
  | User Management (CRUD Users, Password Resets) | ✅ | ❌ | ❌ |
  | Purge & Clear Security Event Logs | ✅ | ❌ | ❌ |
- **Server Enforcement**: `@role_required(['Administrator', ...])` returns HTTP 403 Forbidden with clean error pages and JSON responses if unauthorized.

### 3. Windows Defender Subprocess Execution Engine (`firewall_engine.py`)
- Executes PowerShell NetSecurity cmdlets (`New-NetFirewallRule`, `Set-NetFirewallRule`, `Remove-NetFirewallRule`, `Set-NetFirewallProfile`) and `netsh advfirewall` via Python `subprocess.run`.
- **Privilege Detection**: Detects whether the server is running with Windows Administrator elevation (`IsUserAnAdmin`).
- **Command History Audit**: Every dispatched command is recorded in SQLite `command_history` with execution operator, timestamp, and subsystem response.

### 4. Live Host Socket & Traffic Telemetry (`traffic_monitor.py`)
- Discovers live host TCP/UDP connections via `netstat -ano` and Python `socket`.
- Evaluates active network connections against configured firewall rules to classify flows as **Allowed** or **Blocked**.
- **Interactive Threat Simulator**: Operators/Admins can simulate malicious port probes (e.g. unauthorized SMB port 445 or RDP port 3389 scans) to verify live rule blocking in the UI.
- **Quick Block IP Action**: Allows instant drafting of a firewall containment rule from any active network connection.

### 5. Input Validation & Conflict Engine (`validators.py`)
- **IP / Subnet Validation**: Accepts IPv4, CIDR notation (e.g. `192.168.1.0/24`), comma-separated IPs, or `Any`.
- **Port Validation**: Validates single integer ports (`1-65535`), port ranges (e.g. `8080-8090`), comma lists (`80,443`), and enforces `N/A` for ICMP protocol.
- **Duplicate Prevention**: Rejects duplicate rule names and conflicting configurations.

### 6. User Management & Self-Service Password Change
- Administrators can create, edit, reset passwords, and delete system users.
- Authenticated users can change their own password from the top-right user menu.

---

## 🚀 How to Run the Application

### 1. Prerequisites
- Python 3.8+ on Windows (or Linux/macOS).

### 2. Run as a Windows application

The project includes a PyInstaller build script for creating a Windows executable.
From an elevated PowerShell window in the project directory, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build.ps1
```

The packaged application is created at:

```text
dist\FirewallGuard\FirewallGuard.exe
```

The executable uses Waitress, requests administrator elevation through Windows UAC,
opens the local panel automatically, and listens only on `127.0.0.1`. The database
is kept beside the executable so changes persist across restarts. To use a different
data directory, set `FIREWALLGUARD_DATA_DIR` before starting the executable.

For development, run `python app.py` as usual. The application uses the same
Waitress server and local browser startup instead of Flask's development server.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start FirewallGuard
```bash
python app.py
```
> **Tip for Full Windows Defender Commits**: Run your terminal / PowerShell as **Administrator** before launching `python app.py` to allow direct elevation for Windows Defender firewall updates. The application starts with debug mode disabled.

For a stable local deployment, configure a unique session secret before starting:

```powershell
$env:FIREWALLGUARD_SECRET = "replace-with-a-long-random-secret"
python app.py
```

The application also supports `FIREWALLGUARD_HTTPS=true` when HTTPS is configured, which enables secure session cookies. Keep the server bound to `127.0.0.1` for a single-machine defense demonstration.

### 4. Access Web Interface
Open your browser to:
```
http://127.0.0.1:5000
```

### 5. First-Run User Accounts

On a new database, set bootstrap passwords before the first start:

```powershell
$env:FIREWALLGUARD_ADMIN_PASSWORD = "use-a-strong-admin-password"
$env:FIREWALLGUARD_OPERATOR_PASSWORD = "use-a-strong-operator-password"
$env:FIREWALLGUARD_VIEWER_PASSWORD = "use-a-strong-viewer-password"
python app.py
```

If these variables are not set, FirewallGuard generates random one-time bootstrap passwords and prints them to the startup console. Existing databases are not reseeded. Change any legacy demonstration credentials before presenting the system.

The original development credentials are not safe for deployment and should not be reused.

### 6. Access Control and Defense Demonstration

The application uses role-based access control:

- **Administrator**: manage users, create/edit/delete rules, change profiles, and synchronize firewall rules.
- **Security Operator**: inspect traffic and logs, simulate threats, toggle existing rules, and synchronize active rules.
- **Viewer**: read-only dashboard, traffic, rules, and log access.

State-changing browser requests include CSRF protection, and the server rejects requests without a valid same-origin token. Test firewall changes from an elevated PowerShell window and verify the resulting rule with `Get-NetFirewallRule`.

### 7. Legacy Development Accounts

Older development databases may contain the usernames `admin`, `operator`, and `viewer` with previously configured passwords. Those credentials are not documented here and must be changed or removed before a defense demonstration.
