import sqlite3
import os
import secrets
import sys
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash


def _get_data_directory():
    configured_directory = os.environ.get('FIREWALLGUARD_DATA_DIR')
    if configured_directory:
        return os.path.abspath(configured_directory)

    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)

    return os.path.dirname(os.path.abspath(__file__))


DATA_DIR = _get_data_directory()
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'firewallguard.db')

def local_timestamp():
    """Return a local machine timestamp for display and audit records."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table with RBAC constraints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Administrator', 'Security Operator', 'Viewer')),
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
        )
    ''')

    # Firewall Rules Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            direction TEXT NOT NULL CHECK(direction IN ('Inbound', 'Outbound')),
            action TEXT NOT NULL CHECK(action IN ('Allow', 'Block')),
            protocol TEXT NOT NULL CHECK(protocol IN ('TCP', 'UDP', 'ICMP', 'Any')),
            source_ip TEXT DEFAULT 'Any',
            dest_ip TEXT DEFAULT 'Any',
            source_port TEXT DEFAULT 'Any',
            dest_port TEXT DEFAULT 'Any',
            profile TEXT NOT NULL CHECK(profile IN ('Domain', 'Private', 'Public', 'Any')),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
        )
    ''')

    # Traffic Logs Table with indexes for fast querying
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            source_port TEXT NOT NULL,
            dest_port TEXT NOT NULL,
            protocol TEXT NOT NULL,
            direction TEXT NOT NULL,
            action TEXT NOT NULL,
            rule_name TEXT,
            reason TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON traffic_logs(timestamp DESC)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_action ON traffic_logs(action)')

    # Windows Firewall Profiles Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewall_profiles (
            profile_name TEXT PRIMARY KEY,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            default_inbound TEXT NOT NULL DEFAULT 'Block',
            default_outbound TEXT NOT NULL DEFAULT 'Allow',
            updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
        )
    ''')

    # Ensure updated_at column exists in users table
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [row[1] for row in cursor.fetchall()]
    if 'updated_at' not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP")

    # Command History / Audit Log Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            command TEXT NOT NULL,
            executed_by TEXT NOT NULL,
            status TEXT NOT NULL,
            output TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cmd_timestamp ON command_history(timestamp DESC)')

    conn.commit()
    seed_initial_data(conn)
    conn.close()

def seed_initial_data(conn):
    cursor = conn.cursor()

    # Seed Default Users if table is empty
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        bootstrap_passwords = {
            'admin': os.environ.get('FIREWALLGUARD_ADMIN_PASSWORD') or secrets.token_urlsafe(12),
            'operator': os.environ.get('FIREWALLGUARD_OPERATOR_PASSWORD') or secrets.token_urlsafe(12),
            'viewer': os.environ.get('FIREWALLGUARD_VIEWER_PASSWORD') or secrets.token_urlsafe(12)
        }
        users = [
            ('admin', generate_password_hash(bootstrap_passwords['admin']), 'Administrator', 'Patrick Robles (Admin)', 'admin@firewallguard.local'),
            ('operator', generate_password_hash(bootstrap_passwords['operator']), 'Security Operator', 'Boss Atan (SecOps)', 'operator@firewallguard.local'),
            ('viewer', generate_password_hash(bootstrap_passwords['viewer']), 'Viewer', 'Lebron (Auditor)', 'viewer@firewallguard.local')
        ]
        cursor.executemany('''
            INSERT INTO users (username, password_hash, role, full_name, email)
            VALUES (?, ?, ?, ?, ?)
        ''', users)
        generated_users = [
            username for username, env_name in [
                ('admin', 'FIREWALLGUARD_ADMIN_PASSWORD'),
                ('operator', 'FIREWALLGUARD_OPERATOR_PASSWORD'),
                ('viewer', 'FIREWALLGUARD_VIEWER_PASSWORD')
            ] if not os.environ.get(env_name)
        ]
        if generated_users:
            print('Generated bootstrap credentials for this new database:')
            for username in generated_users:
                print(f'  {username}: {bootstrap_passwords[username]}')

    # Seed Firewall Profiles
    cursor.execute('SELECT COUNT(*) FROM firewall_profiles')
    if cursor.fetchone()[0] == 0:
        profiles = [
            ('Domain', 1, 'Block', 'Allow'),
            ('Private', 1, 'Block', 'Allow'),
            ('Public', 1, 'Block', 'Allow')
        ]
        cursor.executemany('''
            INSERT INTO firewall_profiles (profile_name, is_enabled, default_inbound, default_outbound)
            VALUES (?, ?, ?, ?)
        ''', profiles)

    # Seed a small, defense-ready rule set with one disabled live-demo rule.
    cursor.execute('SELECT COUNT(*) FROM firewall_rules')
    if cursor.fetchone()[0] == 0:
        rules = [
            ('Block-SMB-Inbound', 'Block dangerous SMB port 445 against network ransomware and exploit attempts', 'Inbound', 'Block', 'TCP', 'Any', 'Any', 'Any', '445', 'Public', 1),
            ('Allow-DNS-Outbound', 'Permit outbound Domain Name Resolution requests to trusted DNS resolvers', 'Outbound', 'Allow', 'UDP', '192.168.1.100', '8.8.8.8, 1.1.1.1', 'Any', '53', 'Any', 1),
            ('Allow-ICMP-Ping-Internal', 'Allow ICMP Echo Request for internal network connectivity diagnostics', 'Inbound', 'Allow', 'ICMP', '192.168.1.0/24', 'Any', 'N/A', 'N/A', 'Private', 1),
            ('Defense-Demo-Block-HTTPS', 'Prepared presentation rule; enable during the live firewall test', 'Outbound', 'Block', 'TCP', 'Any', '1.1.1.1', 'Any', '443', 'Any', 0)
        ]
        cursor.executemany('''
            INSERT INTO firewall_rules (name, description, direction, action, protocol, source_ip, dest_ip, source_port, dest_port, profile, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', rules)

    # Seed Traffic Logs (Decluttered: 1 per rule category)
    cursor.execute('SELECT COUNT(*) FROM traffic_logs')
    if cursor.fetchone()[0] == 0:
        base_time = datetime.now()
        logs = [
            ((base_time - timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S'), '203.0.113.45', '192.168.1.100', '49152', '445', 'TCP', 'Inbound', 'Block', 'Block-SMB-Inbound', 'Unsolicited SMB probe detected and dropped'),
            ((base_time - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), '192.168.1.100', '8.8.8.8', '54321', '53', 'UDP', 'Outbound', 'Allow', 'Allow-DNS-Outbound', 'Standard DNS resolution permitted'),
            ((base_time - timedelta(minutes=8)).strftime('%Y-%m-%d %H:%M:%S'), '192.168.1.15', '192.168.1.100', 'N/A', 'N/A', 'ICMP', 'Inbound', 'Allow', 'Allow-ICMP-Ping-Internal', 'Diagnostic Echo Request permitted')
        ]
        cursor.executemany('''
            INSERT INTO traffic_logs (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, direction, action, rule_name, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', logs)

    # Seed Sample Command History
    cursor.execute('SELECT COUNT(*) FROM command_history')
    if cursor.fetchone()[0] == 0:
        commands = [
            ('New-NetFirewallRule -DisplayName "Block-SMB-Inbound" -Direction Inbound -Action Block -Protocol TCP -LocalPort 445 -Profile Public', 'Patrick Robles (Admin)', 'Success', 'Rule successfully created and committed to Windows Defender Firewall.'),
            ('New-NetFirewallRule -DisplayName "Allow-DNS-Outbound" -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress 8.8.8.8,1.1.1.1 -RemotePort 53 -Profile Any', 'Patrick Robles (Admin)', 'Success', 'Rule registered successfully.'),
            ('New-NetFirewallRule -DisplayName "Allow-ICMP-Ping-Internal" -Direction Inbound -Action Allow -Protocol ICMP -RemoteAddress 192.168.1.0/24 -Profile Private', 'Patrick Robles (Admin)', 'Success', 'Rule registered successfully.')
        ]
        cursor.executemany('''
            INSERT INTO command_history (command, executed_by, status, output)
            VALUES (?, ?, ?, ?)
        ''', commands)

    conn.commit()

def reset_db_to_clean_state():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM firewall_rules')
    cursor.execute('DELETE FROM traffic_logs')
    cursor.execute('DELETE FROM command_history')
    conn.commit()
    seed_initial_data(conn)
    conn.close()

# User CRUD Helpers
def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(user) if user else None

def purge_logs(purge_all=False, days_old=30):
    conn = get_db_connection()
    if purge_all:
        conn.execute('DELETE FROM traffic_logs')
    else:
        cutoff = (datetime.now() - timedelta(days=days_old)).strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('DELETE FROM traffic_logs WHERE timestamp < ?', (cutoff,))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database schema and seed verified.")
