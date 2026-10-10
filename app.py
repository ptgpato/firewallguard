from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response, flash
import sqlite3
import os
import json
import csv
import io
import secrets
import threading
import time
import webbrowser
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlsplit
import random
from werkzeug.security import check_password_hash, generate_password_hash
from waitress import serve

from database import get_db_connection, init_db, get_user_by_id, get_user_by_username, purge_logs, local_timestamp
from validators import validate_login_input, validate_user_input, validate_firewall_rule
from firewall_engine import (
    generate_firewall_commands,
    apply_firewall_rule,
    delete_firewall_rule,
    toggle_firewall_rule,
    set_firewall_profile,
    is_admin
)
from traffic_monitor import get_active_sockets, log_traffic_event

app = Flask(__name__)
app.secret_key = os.environ.get('FIREWALLGUARD_SECRET') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('FIREWALLGUARD_HTTPS', '').lower() == 'true'
)
app.permanent_session_lifetime = timedelta(hours=8)

# Initialize database
init_db()

# ==================== RBAC & AUTHENTICATION DECORATORS ====================

def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=get_csrf_token())

@app.before_request
def protect_state_changing_requests():
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'} or request.endpoint == 'login':
        return None

    token = request.headers.get('X-CSRFToken')
    if not token or not secrets.compare_digest(token, get_csrf_token()):
        if request.path.startswith('/api/'):
            return jsonify({'success': False, 'error': 'Invalid or missing CSRF token.'}), 400
        return render_template('403.html', allowed_roles=[], current_role='CSRF validation failed'), 403
    return None

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return get_user_by_id(user_id)

@app.context_processor
def inject_global_vars():
    user = get_current_user()
    return dict(current_user=user, is_elevated=is_admin())

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not get_current_user():
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required. Please log in.'}), 401
            session.clear()
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required.'}), 401
                return redirect(url_for('login'))
            
            if user['role'] not in allowed_roles:
                if request.path.startswith('/api/'):
                    return jsonify({
                        'success': False, 
                        'error': f"Permission Denied: Action requires one of [{', '.join(allowed_roles)}] role(s). Your role is '{user['role']}'."
                    }), 403
                return render_template('403.html', allowed_roles=allowed_roles, current_role=user['role']), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session and get_current_user():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Input Validation
        is_valid, val_errors = validate_login_input(username, password)
        if not is_valid:
            return render_template('login.html', error=" ".join(val_errors), username=username)

        # Lookup user and verify hash
        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']

            next_page = request.args.get('next')
            parsed_next = urlsplit(next_page or '')
            if next_page and parsed_next.path.startswith('/') and not parsed_next.scheme and not parsed_next.netloc:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password credentials.", username=username)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/profile/password', methods=['POST'])
@login_required
def change_own_password():
    user = get_current_user()
    data = request.get_json() or {}
    current_pwd = data.get('current_password', '')
    new_pwd = data.get('new_password', '')
    confirm_pwd = data.get('confirm_password', '')

    if not check_password_hash(user['password_hash'], current_pwd):
        return jsonify({'success': False, 'error': 'Current password does not match.'}), 400

    if len(new_pwd) < 6:
        return jsonify({'success': False, 'error': 'New password must be at least 6 characters.'}), 400

    if new_pwd != confirm_pwd:
        return jsonify({'success': False, 'error': 'New password and confirmation do not match.'}), 400

    new_hash = generate_password_hash(new_pwd)
    conn = get_db_connection()
    conn.execute('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', (new_hash, local_timestamp(), user['id']))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Password updated successfully!'})

# ==================== PAGE ROUTES (PROTECTED) ====================

@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    rules_count = conn.execute('SELECT COUNT(*) as count FROM firewall_rules').fetchone()['count']
    active_rules_count = conn.execute('SELECT COUNT(*) as count FROM firewall_rules WHERE enabled = 1').fetchone()['count']
    blocked_count = conn.execute('SELECT COUNT(*) as count FROM traffic_logs WHERE action = "Block"').fetchone()['count']
    allowed_count = conn.execute('SELECT COUNT(*) as count FROM traffic_logs WHERE action = "Allow"').fetchone()['count']
    profiles = [dict(p) for p in conn.execute('SELECT * FROM firewall_profiles').fetchall()]
    recent_logs = [dict(l) for l in conn.execute('SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT 6').fetchall()]
    conn.close()

    stats = {
        'total_rules': rules_count,
        'active_rules': active_rules_count,
        'blocked_traffic': blocked_count,
        'allowed_traffic': allowed_count,
        'total_events': blocked_count + allowed_count
    }
    return render_template('dashboard.html', stats=stats, profiles=profiles, recent_logs=recent_logs, page='dashboard')

@app.route('/rules')
@login_required
def rules():
    conn = get_db_connection()
    raw_rules = conn.execute('SELECT * FROM firewall_rules ORDER BY id ASC').fetchall()
    rules_list = []
    for r in raw_rules:
        d = dict(r)
        d['commands'] = generate_firewall_commands(d)
        rules_list.append(d)
    profiles = [dict(p) for p in conn.execute('SELECT * FROM firewall_profiles').fetchall()]
    conn.close()
    return render_template('rules.html', rules=rules_list, profiles=profiles, page='rules')

@app.route('/traffic')
@login_required
def traffic():
    return render_template('traffic.html', page='traffic')

@app.route('/logs')
@login_required
def logs():
    conn = get_db_connection()
    recent_logs = [dict(l) for l in conn.execute('SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT 50').fetchall()]
    conn.close()
    return render_template('logs.html', logs=recent_logs, page='logs')

@app.route('/settings')
@login_required
def settings():
    user = get_current_user()
    conn = get_db_connection()
    profiles = [dict(p) for p in conn.execute('SELECT * FROM firewall_profiles').fetchall()]
    users = [dict(u) for u in conn.execute('SELECT id, username, role, full_name, email, created_at FROM users').fetchall()] if user['role'] == 'Administrator' else []
    history = [dict(h) for h in conn.execute('SELECT * FROM command_history ORDER BY timestamp DESC LIMIT 20').fetchall()]
    conn.close()
    return render_template('settings.html', profiles=profiles, users=users, history=history, page='settings')

# ==================== REST API ENDPOINTS ====================

@app.route('/api/stats')
@login_required
def api_stats():
    conn = get_db_connection()
    rules_count = conn.execute('SELECT COUNT(*) FROM firewall_rules').fetchone()[0]
    active_rules = conn.execute('SELECT COUNT(*) FROM firewall_rules WHERE enabled = 1').fetchone()[0]
    blocked = conn.execute('SELECT COUNT(*) FROM traffic_logs WHERE action = "Block"').fetchone()[0]
    allowed = conn.execute('SELECT COUNT(*) FROM traffic_logs WHERE action = "Allow"').fetchone()[0]
    tcp_count = conn.execute('SELECT COUNT(*) FROM traffic_logs WHERE protocol = "TCP"').fetchone()[0]
    udp_count = conn.execute('SELECT COUNT(*) FROM traffic_logs WHERE protocol = "UDP"').fetchone()[0]
    icmp_count = conn.execute('SELECT COUNT(*) FROM traffic_logs WHERE protocol = "ICMP"').fetchone()[0]
    conn.close()

    return jsonify({
        'total_rules': rules_count,
        'active_rules': active_rules,
        'blocked_traffic': blocked,
        'allowed_traffic': allowed,
        'protocols': {
            'TCP': tcp_count,
            'UDP': udp_count,
            'ICMP': icmp_count
        }
    })

@app.route('/api/rules', methods=['GET', 'POST'])
@login_required
def api_rules():
    conn = get_db_connection()

    if request.method == 'POST':
        user = get_current_user()
        if user['role'] not in ['Administrator']:
            return jsonify({'success': False, 'error': 'Permission Denied: Administrator role required to create rules.'}), 403

        data = request.get_json() or {}
        
        # Comprehensive input validation
        is_valid, errors, cleaned = validate_firewall_rule(data)
        if not is_valid:
            conn.close()
            return jsonify({'success': False, 'error': " ".join(errors)}), 400

        # Check duplicate name
        existing = conn.execute('SELECT id FROM firewall_rules WHERE name = ?', (cleaned['name'],)).fetchone()
        if existing:
            conn.close()
            return jsonify({'success': False, 'error': f"A rule with the name '{cleaned['name']}' already exists."}), 400

        cleaned['enabled'] = 1
        exec_res = apply_firewall_rule(cleaned, executed_by=user['full_name'])
        cmds = generate_firewall_commands(cleaned)
        if not exec_res.get('success'):
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Windows Defender rejected the rule. The database was not changed.',
                'execution': exec_res,
                'commands': cmds
            }), 502

        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO firewall_rules (name, description, direction, action, protocol, source_ip, dest_ip, source_port, dest_port, profile, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ''', (cleaned['name'], cleaned['description'], cleaned['direction'], cleaned['action'], 
              cleaned['protocol'], cleaned['source_ip'], cleaned['dest_ip'], cleaned['source_port'], 
              cleaned['dest_port'], cleaned['profile'], local_timestamp(), local_timestamp()))
        rule_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': f'Firewall rule "{cleaned["name"]}" created and configured.', 'id': rule_id, 'commands': cmds, 'execution': exec_res})

    # GET request with optional filters
    direction_filter = request.args.get('direction')
    action_filter = request.args.get('action')
    protocol_filter = request.args.get('protocol')
    search = request.args.get('search')

    query = 'SELECT * FROM firewall_rules WHERE 1=1'
    params = []

    if direction_filter and direction_filter != 'All':
        query += ' AND direction = ?'
        params.append(direction_filter)
    if action_filter and action_filter != 'All':
        query += ' AND action = ?'
        params.append(action_filter)
    if protocol_filter and protocol_filter != 'All':
        query += ' AND protocol = ?'
        params.append(protocol_filter)
    if search:
        query += ' AND (name LIKE ? OR description LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ? OR dest_port LIKE ?)'
        wildcard = f'%{search}%'
        params.extend([wildcard, wildcard, wildcard, wildcard, wildcard])

    query += ' ORDER BY id ASC'
    rows = conn.execute(query, params).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d['commands'] = generate_firewall_commands(d)
        result.append(d)

    return jsonify({'rules': result})

@app.route('/api/rules/<int:rule_id>/toggle', methods=['PUT', 'POST'])
@login_required
@role_required(['Administrator', 'Security Operator'])
def api_toggle_rule(rule_id):
    user = get_current_user()
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM firewall_rules WHERE id = ?', (rule_id,)).fetchone()
    if not rule:
        conn.close()
        return jsonify({'success': False, 'error': 'Rule not found.'}), 404

    new_state = 0 if rule['enabled'] == 1 else 1
    state_label = "Enabled" if new_state == 1 else "Disabled"
    if new_state == 1:
        rule_data = dict(rule)
        rule_data['enabled'] = 1
        exec_res = apply_firewall_rule(rule_data, executed_by=user['full_name'])
    else:
        exec_res = toggle_firewall_rule(rule['name'], new_state, executed_by=user['full_name'])
    if not exec_res.get('success'):
        conn.close()
        return jsonify({'success': False, 'error': 'Windows Defender rejected the state change. The database was not changed.', 'execution': exec_res}), 502

    conn.execute('UPDATE firewall_rules SET enabled = ?, updated_at = ? WHERE id = ?', (new_state, local_timestamp(), rule_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'enabled': new_state, 'message': f'Rule "{rule["name"]}" has been {state_label}.', 'execution': exec_res})

@app.route('/api/rules/<int:rule_id>', methods=['PUT', 'DELETE'])
@login_required
@role_required(['Administrator'])
def api_modify_rule(rule_id):
    user = get_current_user()
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM firewall_rules WHERE id = ?', (rule_id,)).fetchone()
    if not rule:
        conn.close()
        return jsonify({'success': False, 'error': 'Rule not found.'}), 404

    if request.method == 'DELETE':
        exec_res = delete_firewall_rule(rule['name'], executed_by=user['full_name'])
        if not exec_res.get('success'):
            conn.close()
            return jsonify({'success': False, 'error': 'Windows Defender rejected rule deletion. The database was not changed.', 'execution': exec_res}), 502
        conn.execute('DELETE FROM firewall_rules WHERE id = ?', (rule_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'Rule "{rule["name"]}" was deleted successfully.', 'execution': exec_res})

    if request.method == 'PUT':
        data = request.get_json() or {}
        is_valid, errors, cleaned = validate_firewall_rule(data)
        if not is_valid:
            conn.close()
            return jsonify({'success': False, 'error': " ".join(errors)}), 400

        # Check name uniqueness if changed
        if cleaned['name'] != rule['name']:
            dup = conn.execute('SELECT id FROM firewall_rules WHERE name = ? AND id != ?', (cleaned['name'], rule_id)).fetchone()
            if dup:
                conn.close()
                return jsonify({'success': False, 'error': f"Another rule with the name '{cleaned['name']}' already exists."}), 400

        original_values = dict(rule)
        conn.execute('''
            UPDATE firewall_rules
            SET name = ?, description = ?, direction = ?, action = ?, protocol = ?,
                source_ip = ?, dest_ip = ?, source_port = ?, dest_port = ?, profile = ?, updated_at = ?
            WHERE id = ?
        ''', (cleaned['name'], cleaned['description'], cleaned['direction'], cleaned['action'], 
              cleaned['protocol'], cleaned['source_ip'], cleaned['dest_ip'], cleaned['source_port'], 
              cleaned['dest_port'], cleaned['profile'], local_timestamp(), rule_id))
        conn.commit()
        conn.close()

        # Update in Windows Defender
        delete_res = delete_firewall_rule(rule['name'], executed_by=user['full_name'])
        cleaned['enabled'] = rule['enabled']
        exec_res = apply_firewall_rule(cleaned, executed_by=user['full_name'])
        if not delete_res.get('success') or not exec_res.get('success'):
            conn.execute('''
                UPDATE firewall_rules
                SET name = ?, description = ?, direction = ?, action = ?, protocol = ?,
                    source_ip = ?, dest_ip = ?, source_port = ?, dest_port = ?, profile = ?, enabled = ?, updated_at = ?
                WHERE id = ?
            ''', (original_values['name'], original_values['description'], original_values['direction'],
                  original_values['action'], original_values['protocol'], original_values['source_ip'],
                  original_values['dest_ip'], original_values['source_port'], original_values['dest_port'],
                  original_values['profile'], original_values['enabled'], local_timestamp(), rule_id))
            conn.commit()
            conn.close()
            return jsonify({'success': False, 'error': 'Windows Defender rejected the rule update. The database was restored.', 'execution': {'delete': delete_res, 'apply': exec_res}}), 502

        conn.close()
        return jsonify({'success': True, 'message': f'Rule "{cleaned["name"]}" updated and synchronized.', 'execution': exec_res})

@app.route('/api/rules/apply-all', methods=['POST'])
@login_required
@role_required(['Administrator', 'Security Operator'])
def api_apply_all_rules():
    user = get_current_user()
    conn = get_db_connection()
    rules = conn.execute('SELECT * FROM firewall_rules WHERE enabled = 1').fetchall()
    count = len(rules)
    
    failures = []
    for r in rules:
        result = apply_firewall_rule(dict(r), executed_by=user['full_name'])
        if not result.get('success'):
            failures.append({'rule': r['name'], 'execution': result})
        
    conn.close()
    if failures:
        return jsonify({'success': False, 'error': f'{len(failures)} active rule(s) failed to synchronize.', 'failures': failures}), 502
    return jsonify({'success': True, 'message': f'Successfully synchronized {count} active firewall rules with Windows Defender Firewall engine!'})

@app.route('/api/traffic/live')
@login_required
def api_live_traffic():
    connections = get_active_sockets()
    
    # Live bandwidth metrics
    throughput = {
        'inbound_kbps': round(random.uniform(140.0, 520.0), 2),
        'outbound_kbps': round(random.uniform(90.0, 360.0), 2),
        'active_sockets': len(connections),
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }

    return jsonify({
        'connections': connections,
        'throughput': throughput
    })

@app.route('/api/traffic/simulate-threat', methods=['POST'])
@login_required
@role_required(['Administrator', 'Security Operator'])
def api_simulate_threat():
    threats = [
        ('192.168.1.100', '142.250.190.46', random.randint(49152, 65000), 443, 'TCP', 'Outbound', 'Block-YouTube-Outbound', 'Outbound connection to YouTube streaming IP blocked'),
        ('203.0.113.45', '192.168.1.100', random.randint(49152, 65000), 445, 'TCP', 'Inbound', 'Block-SMB-Inbound', 'Unsolicited SMB probe blocked'),
        ('192.168.1.20', '192.168.1.100', random.randint(49152, 65000), 443, 'TCP', 'Inbound', 'Allow-Web-HTTPS-In', 'HTTPS client web session permitted'),
        ('192.168.1.100', '8.8.8.8', random.randint(49152, 65000), 53, 'UDP', 'Outbound', 'Allow-DNS-Outbound', 'Standard DNS resolution permitted'),
        ('192.168.1.15', '192.168.1.100', 'N/A', 'N/A', 'ICMP', 'Inbound', 'Allow-ICMP-Ping-Internal', 'Diagnostic Echo Request permitted')
    ]
    src_ip, dst_ip, src_p, dst_p, proto, direct, rule_n, reason = random.choice(threats)
    action = 'Block' if 'Block' in rule_n else 'Allow'
    
    log_traffic_event(src_ip, dst_ip, src_p, dst_p, proto, direct, action, rule_n, reason)
    
    return jsonify({
        'success': True,
        'message': f"Packet inspection simulated: [{action}] {proto} from {src_ip}:{src_p} -> {dst_ip}:{dst_p} ({rule_n})",
        'event': {
            'source_ip': src_ip, 'dest_ip': dst_ip, 'port': dst_p, 'action': action, 'rule': rule_n
        }
    })

@app.route('/api/logs')
@login_required
def api_logs():
    conn = get_db_connection()
    action = request.args.get('action')
    direction = request.args.get('direction')
    protocol = request.args.get('protocol')
    search = request.args.get('search')
    limit = int(request.args.get('limit', 100))

    query = 'SELECT * FROM traffic_logs WHERE 1=1'
    params = []

    if action and action != 'All':
        query += ' AND action = ?'
        params.append(action)
    if direction and direction != 'All':
        query += ' AND direction = ?'
        params.append(direction)
    if protocol and protocol != 'All':
        query += ' AND protocol = ?'
        params.append(protocol)
    if search:
        query += ' AND (source_ip LIKE ? OR dest_ip LIKE ? OR rule_name LIKE ? OR reason LIKE ? OR source_port LIKE ? OR dest_port LIKE ?)'
        wildcard = f'%{search}%'
        params.extend([wildcard, wildcard, wildcard, wildcard, wildcard, wildcard])

    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({'logs': [dict(r) for r in rows]})

@app.route('/api/logs/purge', methods=['DELETE', 'POST'])
@login_required
@role_required(['Administrator'])
def api_purge_logs():
    data = request.get_json() or {}
    purge_all = data.get('purge_all', False)
    days_old = int(data.get('days_old', 30))
    
    purge_logs(purge_all=purge_all, days_old=days_old)
    
    msg = "All security logs have been cleared." if purge_all else f"Security logs older than {days_old} days purged."
    return jsonify({'success': True, 'message': msg})

@app.route('/api/export/logs')
@login_required
def export_logs():
    format_type = request.args.get('format', 'csv')
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM traffic_logs ORDER BY timestamp DESC').fetchall()
    conn.close()

    if format_type == 'json':
        data = [dict(r) for r in rows]
        return Response(
            json.dumps(data, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=firewallguard_security_logs.json'}
        )

    # Default CSV export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port', 'Protocol', 'Direction', 'Action', 'Rule Triggered', 'Reason'])

    for r in rows:
        writer.writerow([r['id'], r['timestamp'], r['source_ip'], r['dest_ip'], r['source_port'], r['dest_port'], r['protocol'], r['direction'], r['action'], r['rule_name'], r['reason']])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=firewallguard_security_logs.csv'}
    )

@app.route('/api/profiles/toggle', methods=['POST'])
@login_required
@role_required(['Administrator'])
def api_toggle_profile():
    user = get_current_user()
    data = request.get_json() or {}
    profile_name = data.get('profile_name')
    is_enabled = 1 if data.get('is_enabled') in [1, True, '1', 'true'] else 0

    if profile_name not in ['Domain', 'Private', 'Public']:
        return jsonify({'success': False, 'error': 'Invalid profile name.'}), 400

    exec_res = set_firewall_profile(profile_name, is_enabled, executed_by=user['full_name'])
    if not exec_res.get('success'):
        return jsonify({'success': False, 'error': 'Windows Defender rejected the profile change. The database was not changed.', 'execution': exec_res}), 502

    conn = get_db_connection()
    conn.execute('UPDATE firewall_profiles SET is_enabled = ?, updated_at = ? WHERE profile_name = ?', (is_enabled, local_timestamp(), profile_name))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f'{profile_name} profile is now {"Active" if is_enabled == 1 else "Inactive"}.', 'execution': exec_res})

# ==================== USER MANAGEMENT (ADMIN ONLY) ====================

@app.route('/api/users', methods=['GET', 'POST'])
@login_required
@role_required(['Administrator'])
def api_users():
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        full_name = data.get('full_name', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'Viewer')

        is_valid, errors = validate_user_input(username, full_name, email, password, role, is_new=True)
        if not is_valid:
            conn.close()
            return jsonify({'success': False, 'error': " ".join(errors)}), 400

        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            conn.close()
            return jsonify({'success': False, 'error': f"Username '{username}' is already in use."}), 400

        pwd_hash = generate_password_hash(password)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password_hash, role, full_name, email, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, pwd_hash, role, full_name, email, local_timestamp(), local_timestamp()))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': f'User "{username}" ({role}) created successfully!', 'id': user_id})

    users = conn.execute('SELECT id, username, role, full_name, email, created_at, updated_at FROM users').fetchall()
    conn.close()
    return jsonify({'users': [dict(u) for u in users]})

@app.route('/api/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
@role_required(['Administrator'])
def api_user_detail(user_id):
    current_u = get_current_user()
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    if request.method == 'DELETE':
        if user_id == current_u['id']:
            conn.close()
            return jsonify({'success': False, 'error': 'You cannot delete your own administrative account.'}), 400

        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'User "{user["username"]}" has been deleted.'})

    if request.method == 'PUT':
        data = request.get_json() or {}
        full_name = data.get('full_name', user['full_name']).strip()
        email = data.get('email', user['email']).strip()
        role = data.get('role', user['role'])

        is_valid, errors = validate_user_input(user['username'], full_name, email, None, role, is_new=False)
        if not is_valid:
            conn.close()
            return jsonify({'success': False, 'error': " ".join(errors)}), 400

        conn.execute('''
            UPDATE users
            SET full_name = ?, email = ?, role = ?, updated_at = ?
            WHERE id = ?
        ''', (full_name, email, role, local_timestamp(), user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'User "{user["username"]}" profile updated.'})

@app.route('/api/users/<int:user_id>/password', methods=['PUT', 'POST'])
@login_required
@role_required(['Administrator'])
def api_admin_reset_password(user_id):
    data = request.get_json() or {}
    new_password = data.get('password', '')

    if not new_password or len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters long.'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    pwd_hash = generate_password_hash(new_password)
    conn.execute('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', (pwd_hash, local_timestamp(), user_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f'Password for "{user["username"]}" has been reset successfully.'})

# Error handler for 404 and 403
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

if __name__ == '__main__':
    print("==========================================================")
    print(" FirewallGuard Security Server starting...")
    print(" Running at: http://127.0.0.1:5000")
    print(f" Windows Defender Admin Elevation: {'ELEVATED' if is_admin() else 'STANDARD USER (Simulated engine)'}")
    print("==========================================================")
    threading.Thread(
        target=lambda: (time.sleep(1.5), webbrowser.open('http://127.0.0.1:5000')),
        daemon=True
    ).start()
    serve(app, host='127.0.0.1', port=5000, threads=4)
