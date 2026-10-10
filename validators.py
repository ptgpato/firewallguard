import re
import ipaddress

# Username regex: 3-30 chars, alphanumeric, underscores, hyphens, dots
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_.-]{3,30}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
RULE_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_.\-\s]{3,64}$')

def validate_login_input(username, password):
    errors = []
    if not username or not username.strip():
        errors.append("Username is required.")
    elif len(username.strip()) < 3 or len(username.strip()) > 30:
        errors.append("Username must be between 3 and 30 characters.")
    
    if not password:
        errors.append("Password is required.")
    elif len(password) < 4:
        errors.append("Password must be at least 4 characters.")
        
    return len(errors) == 0, errors

def validate_user_input(username, full_name, email, password=None, role='Viewer', is_new=True):
    errors = []
    
    if not username or not USERNAME_REGEX.match(username.strip()):
        errors.append("Username must be 3-30 characters long and contain only letters, numbers, dots, underscores, or hyphens.")
        
    if not full_name or len(full_name.strip()) < 2 or len(full_name.strip()) > 60:
        errors.append("Full Name must be between 2 and 60 characters.")
        
    if not email or not EMAIL_REGEX.match(email.strip()):
        errors.append("Please provide a valid email address.")
        
    if is_new or password:
        if not password or len(password) < 6:
            errors.append("Password must be at least 6 characters long.")
            
    valid_roles = ['Administrator', 'Security Operator', 'Viewer']
    if role not in valid_roles:
        errors.append(f"Invalid role selected. Must be one of: {', '.join(valid_roles)}.")
        
    return len(errors) == 0, errors

def validate_ip_endpoint(ip_str):
    """
    Validates IP endpoint: allows 'Any', single IPv4, CIDR (e.g. 192.168.1.0/24),
    or comma-separated IPv4 list.
    """
    if not ip_str or ip_str.strip().lower() in ['any', '*']:
        return True, "Any"
        
    parts = [p.strip() for p in ip_str.split(',') if p.strip()]
    validated_parts = []
    
    for part in parts:
        # Check single IPv4 or CIDR
        try:
            # Handles IPv4 and IPv4Network like 192.168.1.0/24
            if '/' in part:
                ipaddress.IPv4Network(part, strict=False)
            else:
                ipaddress.IPv4Address(part)
            validated_parts.append(part)
        except ValueError:
            # Check if domain name or hostname (e.g. time.windows.com)
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', part):
                validated_parts.append(part)
            else:
                return False, f"Invalid IP address, CIDR, or hostname: '{part}'."
                
    return True, ", ".join(validated_parts)

def validate_port_endpoint(port_str, protocol='TCP'):
    """
    Validates port endpoint: allows 'Any', 'N/A', single port 1-65535,
    ranges like 8000-8080, or comma-separated list like 80,443.
    For ICMP protocol, port is always N/A.
    """
    if protocol.upper() == 'ICMP':
        return True, "N/A"
        
    if not port_str or port_str.strip().lower() in ['any', '*', 'n/a', '']:
        return True, "Any"
        
    parts = [p.strip() for p in port_str.split(',') if p.strip()]
    validated_parts = []
    
    for part in parts:
        # Check port range e.g. 8000-8080
        if '-' in part:
            range_split = part.split('-')
            if len(range_split) != 2:
                return False, f"Invalid port range format: '{part}'. Expected start-end (e.g. 8080-8090)."
            try:
                start_p = int(range_split[0].strip())
                end_p = int(range_split[1].strip())
                if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535):
                    return False, f"Port numbers in range '{part}' must be between 1 and 65535."
                if start_p >= end_p:
                    return False, f"Range start port ({start_p}) must be less than end port ({end_p})."
                validated_parts.append(f"{start_p}-{end_p}")
            except ValueError:
                return False, f"Port range values must be valid integers in '{part}'."
        else:
            try:
                port_num = int(part)
                if not (1 <= port_num <= 65535):
                    return False, f"Port number {port_num} must be between 1 and 65535."
                validated_parts.append(str(port_num))
            except ValueError:
                return False, f"Invalid port value: '{part}'. Must be an integer between 1 and 65535."
                
    return True, ", ".join(validated_parts)

def validate_firewall_rule(rule_data):
    """
    Comprehensive firewall rule input validation.
    """
    errors = []
    
    # 1. Rule Name
    name = rule_data.get('name', '').strip()
    if not name:
        errors.append("Rule Display Name is required.")
    elif not RULE_NAME_REGEX.match(name):
        errors.append("Rule name must be 3-64 characters and contain only alphanumeric characters, dashes, underscores, and spaces.")
        
    # 2. Direction
    direction = rule_data.get('direction', 'Inbound')
    if direction not in ['Inbound', 'Outbound']:
        errors.append("Direction must be either 'Inbound' or 'Outbound'.")
        
    # 3. Action
    action = rule_data.get('action', 'Allow')
    if action not in ['Allow', 'Block']:
        errors.append("Action must be either 'Allow' or 'Block'.")
        
    # 4. Protocol
    protocol = rule_data.get('protocol', 'TCP')
    if protocol not in ['TCP', 'UDP', 'ICMP', 'Any']:
        errors.append("Protocol must be TCP, UDP, ICMP, or Any.")
        
    # 5. IP Validation
    src_ip_ok, src_ip_res = validate_ip_endpoint(rule_data.get('source_ip', 'Any'))
    if not src_ip_ok:
        errors.append(f"Source IP Error: {src_ip_res}")
        
    dst_ip_ok, dst_ip_res = validate_ip_endpoint(rule_data.get('dest_ip', 'Any'))
    if not dst_ip_ok:
        errors.append(f"Destination IP Error: {dst_ip_res}")
        
    # 6. Port Validation
    src_port_ok, src_port_res = validate_port_endpoint(rule_data.get('source_port', 'Any'), protocol)
    if not src_port_ok:
        errors.append(f"Source Port Error: {src_port_res}")
        
    dst_port_ok, dst_port_res = validate_port_endpoint(rule_data.get('dest_port', 'Any'), protocol)
    if not dst_port_ok:
        errors.append(f"Destination Port Error: {dst_port_res}")
        
    # 7. Profile
    profile = rule_data.get('profile', 'Any')
    if profile not in ['Domain', 'Private', 'Public', 'Any']:
        errors.append("Profile must be Domain, Private, Public, or Any.")
        
    cleaned_data = {
        'name': name,
        'description': rule_data.get('description', '').strip(),
        'direction': direction,
        'action': action,
        'protocol': protocol,
        'source_ip': src_ip_res if src_ip_ok else 'Any',
        'dest_ip': dst_ip_res if dst_ip_ok else 'Any',
        'source_port': src_port_res if src_port_ok else 'Any',
        'dest_port': dst_port_res if dst_port_ok else 'Any',
        'profile': profile
    }
    
    return len(errors) == 0, errors, cleaned_data
