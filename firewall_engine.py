import os
import sys
import subprocess
import platform
import ctypes
from datetime import datetime
from database import get_db_connection, local_timestamp

def is_windows():
    return platform.system().lower() == 'windows'

def is_admin():
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def generate_firewall_commands(rule):
    name = rule.get('name', 'CustomRule').strip().replace('"', '')
    direction = rule.get('direction', 'Inbound')
    action = rule.get('action', 'Allow')
    protocol = rule.get('protocol', 'TCP')
    powershell_protocol = 'ICMPv4' if protocol == 'ICMP' else protocol
    source_ip = rule.get('source_ip', 'Any')
    dest_ip = rule.get('dest_ip', 'Any')
    source_port = rule.get('source_port', 'Any')
    dest_port = rule.get('dest_port', 'Any')
    profile = rule.get('profile', 'Any')
    enabled = 'True' if str(rule.get('enabled', 1)) in ['1', 'True', 'true'] else 'False'

    is_outbound = direction.lower() == 'outbound'

    # Determine PowerShell and Netsh parameter mappings based on Direction:
    # Inbound:  Source = Remote Client (-RemoteAddress, -RemotePort), Dest = Local Server (-LocalAddress, -LocalPort)
    # Outbound: Source = Local Machine (-LocalAddress, -LocalPort),   Dest = Remote Website/Service (-RemoteAddress, -RemotePort)
    local_port = source_port if is_outbound else dest_port
    remote_port = dest_port if is_outbound else source_port
    local_ip = source_ip if is_outbound else dest_ip
    remote_ip = dest_ip if is_outbound else source_ip

    # PowerShell NetSecurity command
    ps_parts = [
        f'New-NetFirewallRule -DisplayName "{name}"',
        f'-Direction {direction}',
        f'-Action {action}',
        f'-Enabled {enabled}'
    ]
    if protocol != 'Any':
        ps_parts.append(f'-Protocol {powershell_protocol}')
        if protocol == 'ICMP':
            ps_parts.append('-IcmpType 8')
    if local_port not in ['Any', 'N/A', ''] and protocol in ['TCP', 'UDP']:
        ps_parts.append(f'-LocalPort {local_port}')
    if remote_port not in ['Any', 'N/A', ''] and protocol in ['TCP', 'UDP']:
        ps_parts.append(f'-RemotePort {remote_port}')
    if local_ip not in ['Any', '']:
        ps_parts.append(f'-LocalAddress {local_ip}')
    if remote_ip not in ['Any', '']:
        ps_parts.append(f'-RemoteAddress {remote_ip}')
    if profile not in ['Any', '']:
        ps_parts.append(f'-Profile {profile}')

    powershell_cmd = " ".join(ps_parts)

    # Legacy Netsh command
    netsh_dir = 'out' if is_outbound else 'in'
    netsh_act = 'allow' if action.lower() == 'allow' else 'block'
    netsh_parts = [
        f'netsh advfirewall firewall add rule name="{name}"',
        f'dir={netsh_dir}',
        f'action={netsh_act}',
        f'enable={"yes" if enabled == "True" else "no"}'
    ]
    if protocol != 'Any':
        netsh_protocol = 'icmpv4' if protocol == 'ICMP' else protocol.lower()
        netsh_parts.append(f'protocol={netsh_protocol}')
    if local_port not in ['Any', 'N/A', ''] and protocol in ['TCP', 'UDP']:
        netsh_parts.append(f'localport={local_port}')
    if remote_port not in ['Any', 'N/A', ''] and protocol in ['TCP', 'UDP']:
        netsh_parts.append(f'remoteport={remote_port}')
    if local_ip not in ['Any', '']:
        netsh_parts.append(f'localip={local_ip}')
    if remote_ip not in ['Any', '']:
        netsh_parts.append(f'remoteip={remote_ip}')
    if profile not in ['Any', '']:
        netsh_parts.append(f'profile={profile.lower()}')

    netsh_cmd = " ".join(netsh_parts)

    return {
        'powershell': powershell_cmd,
        'netsh': netsh_cmd
    }

def record_command_history(command, executed_by, status, output):
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO command_history (timestamp, command, executed_by, status, output)
            VALUES (?, ?, ?, ?, ?)
        ''', (local_timestamp(), command, executed_by, status, output))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging command history: {e}")

def execute_powershell(command_str, executed_by="System"):
    """
    Executes a PowerShell command using Python subprocess.
    If not running as Windows Administrator, records execution and returns status.
    """
    if not is_windows():
        status = "Simulated (Non-Windows)"
        output = "PowerShell command formatted and simulated on current non-Windows platform."
        record_command_history(command_str, executed_by, status, output)
        return {'success': True, 'simulated': True, 'status': status, 'output': output}

    admin_priv = is_admin()
    
    try:
        process = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command_str],
            capture_output=True,
            text=True,
            timeout=12
        )

        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        if process.returncode == 0:
            status = "Success"
            output = stdout if stdout else "Command executed successfully in Windows Defender subsystem."
            record_command_history(command_str, executed_by, status, output)
            return {'success': True, 'status': status, 'output': output, 'is_admin': admin_priv}
        else:
            status = "Elevation Warning" if "Access is denied" in stderr or not admin_priv else "Execution Error"
            msg = stderr if stderr else f"PowerShell exited with code {process.returncode}."
            if not admin_priv:
                msg += " (Note: Web server is running without Administrator UAC elevation. Run web server as Administrator for direct Windows Defender firewall commits)."
            record_command_history(command_str, executed_by, status, msg)
            return {'success': False, 'warning': True, 'status': status, 'output': msg, 'is_admin': admin_priv}

    except subprocess.TimeoutExpired:
        msg = "PowerShell execution timed out after 12 seconds."
        record_command_history(command_str, executed_by, "Timeout", msg)
        return {'success': False, 'error': msg}
    except Exception as ex:
        msg = f"Subprocess invocation error: {str(ex)}"
        record_command_history(command_str, executed_by, "Error", msg)
        return {'success': False, 'error': msg}

def apply_firewall_rule(rule_dict, executed_by="Administrator"):
    cmds = generate_firewall_commands(rule_dict)
    ps_cmd = cmds['powershell']
    res = execute_powershell(ps_cmd, executed_by=executed_by)
    return res

def delete_firewall_rule(rule_name, executed_by="Administrator"):
    safe_name = rule_name.replace('"', '')
    ps_cmd = (
        f'$rule = Get-NetFirewallRule -DisplayName "{safe_name}" '
        f'-ErrorAction SilentlyContinue; '
        f'if ($null -eq $rule) {{ exit 0 }}; '
        f'try {{ $rule | Remove-NetFirewallRule -ErrorAction Stop; exit 0 }} '
        f'catch {{ Write-Error $_; exit 1 }}'
    )
    return execute_powershell(ps_cmd, executed_by=executed_by)

def toggle_firewall_rule(rule_name, enabled, executed_by="Operator"):
    state_str = "True" if enabled in [1, True, '1', 'True'] else "False"
    safe_name = rule_name.replace('"', '')
    ps_cmd = (
        f'$rule = Get-NetFirewallRule -DisplayName "{safe_name}" '
        f'-ErrorAction SilentlyContinue; '
        f'if ($null -eq $rule) {{ exit 0 }}; '
        f'try {{ $rule | Set-NetFirewallRule -Enabled {state_str} -ErrorAction Stop; exit 0 }} '
        f'catch {{ Write-Error $_; exit 1 }}'
    )
    return execute_powershell(ps_cmd, executed_by=executed_by)

def set_firewall_profile(profile_name, is_enabled, default_inbound="Block", default_outbound="Allow", executed_by="Administrator"):
    state_str = "True" if is_enabled in [1, True, '1', 'True'] else "False"
    ps_cmd = f'Set-NetFirewallProfile -Profile {profile_name} -Enabled {state_str} -DefaultInboundAction {default_inbound} -DefaultOutboundAction {default_outbound}'
    return execute_powershell(ps_cmd, executed_by=executed_by)
