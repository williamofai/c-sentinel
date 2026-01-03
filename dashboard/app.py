#!/usr/bin/env python3
"""
C-Sentinel Dashboard
A web interface for viewing system fingerprints across multiple hosts.
"""

import os
import io
import json
import hashlib
import secrets
import smtplib
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
import psycopg2
from psycopg2.extras import RealDictCursor

# Optional TOTP support
try:
    import pyotp
    import qrcode
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-in-production')

# Session configuration
SESSION_LIFETIME_DAYS = int(os.environ.get('SESSION_LIFETIME_DAYS', '7'))

# App configuration for templates
app.config['VERSION'] = '0.6.0'
app.config['ANALYTICS_SCRIPT'] = os.environ.get('ANALYTICS_SCRIPT', '')


def get_client_ip():
    """Get real client IP, handling reverse proxy headers."""
    # Check X-Forwarded-For first (set by reverse proxies)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
        # The first one is the original client
        return forwarded_for.split(',')[0].strip()
    
    # Check X-Real-IP (nginx)
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct connection IP
    return request.remote_addr


# Database configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432'),
    'database': os.environ.get('DB_NAME', 'sentinel'),
    'user': os.environ.get('DB_USER', 'sentinel'),
    'password': os.environ.get('DB_PASSWORD', ''),
}

API_KEY = os.environ.get('SENTINEL_API_KEY', 'change-me-in-production')

# Dashboard authentication
ADMIN_PASSWORD_HASH = os.environ.get('SENTINEL_ADMIN_PASSWORD_HASH', '')

# Email alerting configuration
EMAIL_CONFIG = {
    'enabled': os.environ.get('ALERT_EMAIL_ENABLED', 'false').lower() == 'true',
    'smtp_host': os.environ.get('ALERT_SMTP_HOST', 'smtp.gmail.com'),
    'smtp_port': int(os.environ.get('ALERT_SMTP_PORT', '587')),
    'smtp_user': os.environ.get('ALERT_SMTP_USER', ''),
    'smtp_pass': os.environ.get('ALERT_SMTP_PASS', ''),
    'from_addr': os.environ.get('ALERT_FROM', ''),
    'to_addr': os.environ.get('ALERT_TO', ''),
    'cooldown_minutes': int(os.environ.get('ALERT_COOLDOWN_MINS', '60')),
}

# Track last alert time per host to avoid spam
_last_alert = {}


def send_alert_email(hostname, subject, body):
    """Send an alert email."""
    if not EMAIL_CONFIG['enabled']:
        return False
    
    if not EMAIL_CONFIG['smtp_user'] or not EMAIL_CONFIG['to_addr']:
        app.logger.warning("Email alerting not configured")
        return False
    
    # Check cooldown
    now = datetime.now()
    last = _last_alert.get(hostname)
    if last and (now - last).total_seconds() < EMAIL_CONFIG['cooldown_minutes'] * 60:
        app.logger.info(f"Alert cooldown active for {hostname}")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['from_addr']
        msg['To'] = EMAIL_CONFIG['to_addr']
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_host'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_pass'])
            server.send_message(msg)
        
        _last_alert[hostname] = now
        app.logger.info(f"Alert email sent for {hostname}")
        return True
        
    except Exception as e:
        app.logger.error(f"Failed to send alert email: {e}")
        return False


def send_user_notification(to_email, subject, body):
    """Send a notification email to a user."""
    if not EMAIL_CONFIG['enabled']:
        app.logger.debug("Email not enabled, skipping user notification")
        return False
    
    if not to_email:
        app.logger.debug("No email address provided, skipping notification")
        return False
    
    if not EMAIL_CONFIG['smtp_user']:
        app.logger.warning("SMTP not configured, skipping user notification")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['from_addr']
        msg['To'] = to_email
        msg['Subject'] = f"[C-Sentinel] {subject}"
        
        # Add footer to body
        full_body = f"""{body}

---
This is an automated notification from C-Sentinel.
If you did not perform this action, please contact your administrator immediately.

Dashboard: {os.environ.get('DASHBOARD_URL', 'https://sentinel.speytech.com')}
"""
        
        msg.attach(MIMEText(full_body, 'plain'))
        
        with smtplib.SMTP(EMAIL_CONFIG['smtp_host'], EMAIL_CONFIG['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_pass'])
            server.send_message(msg)
        
        app.logger.info(f"User notification sent to {to_email}: {subject}")
        return True
        
    except Exception as e:
        app.logger.error(f"Failed to send user notification to {to_email}: {e}")
        return False


def notify_password_changed(user):
    """Notify user their password was changed."""
    if not user.get('email'):
        return
    
    send_user_notification(
        user['email'],
        "Your password was changed",
        f"""Hello {user['username']},

Your C-Sentinel dashboard password was changed on {datetime.now().strftime('%d %B %Y at %H:%M')}.

If you made this change, no action is needed.

If you did NOT change your password, your account may be compromised. 
Please contact your administrator immediately to secure your account."""
    )


def notify_new_login(user, ip_address, user_agent):
    """Notify user of a new login."""
    if not user.get('email'):
        return
    
    # Parse user agent for friendlier display
    browser = "Unknown browser"
    if "Chrome" in (user_agent or "") and "Edg" not in user_agent:
        browser = "Chrome"
    elif "Firefox" in (user_agent or ""):
        browser = "Firefox"
    elif "Safari" in (user_agent or "") and "Chrome" not in user_agent:
        browser = "Safari"
    elif "Edg" in (user_agent or ""):
        browser = "Microsoft Edge"
    
    send_user_notification(
        user['email'],
        f"New login from {ip_address}",
        f"""Hello {user['username']},

A new login to your C-Sentinel account was detected:

  Time: {datetime.now().strftime('%d %B %Y at %H:%M')}
  IP Address: {ip_address}
  Browser: {browser}

If this was you, no action is needed.

If you did NOT log in, someone may have access to your account.
Please change your password immediately and contact your administrator."""
    )


def notify_account_created(user, temp_password=None):
    """Notify user their account was created."""
    if not user.get('email'):
        return
    
    password_info = ""
    if temp_password:
        password_info = f"""
Your temporary password is: {temp_password}

Please log in and change your password immediately.
"""
    else:
        password_info = """
Please contact your administrator for your login credentials.
"""
    
    send_user_notification(
        user['email'],
        "Your account has been created",
        f"""Hello {user['username']},

An account has been created for you on the C-Sentinel dashboard.

Username: {user['username']}
Role: {user['role']}
{password_info}
You can log in at the dashboard URL below."""
    )


def notify_role_changed(user, old_role, new_role):
    """Notify user their role was changed."""
    if not user.get('email'):
        return
    
    send_user_notification(
        user['email'],
        f"Your role was changed to {new_role}",
        f"""Hello {user['username']},

Your C-Sentinel dashboard role has been changed:

  Previous role: {old_role}
  New role: {new_role}

This change was made by an administrator on {datetime.now().strftime('%d %B %Y at %H:%M')}.

If you have questions about this change, please contact your administrator."""
    )


def check_and_send_alerts(hostname, audit_data):
    """Check alert conditions and send email if triggered."""
    if not audit_data or not audit_data.get('enabled'):
        return
    
    risk_score = audit_data.get('risk_score', 0)
    risk_level = audit_data.get('risk_level', 'low')
    brute_force = audit_data.get('authentication', {}).get('brute_force_detected', False)
    tmp_execs = audit_data.get('process_activity', {}).get('tmp_executions', 0)
    devshm_execs = audit_data.get('process_activity', {}).get('devshm_executions', 0)
    risk_factors = audit_data.get('risk_factors', [])
    
    alerts = []
    
    # Check conditions
    if risk_score >= 16:
        alerts.append(f"Risk score is {risk_level.upper()} ({risk_score})")
    
    if brute_force:
        alerts.append("Brute force attack pattern detected")
    
    if tmp_execs > 0:
        alerts.append(f"{tmp_execs} execution(s) from /tmp")
    
    if devshm_execs > 0:
        alerts.append(f"{devshm_execs} execution(s) from /dev/shm")
    
    if not alerts:
        return
    
    # Build email
    subject = f"🚨 C-Sentinel Alert: {hostname} - {risk_level.upper()}"
    
    body = f"""C-Sentinel Security Alert
========================

Host: {hostname}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Score: {risk_score} ({risk_level.upper()})

Alerts Triggered:
{chr(10).join('  • ' + a for a in alerts)}

Risk Factors:
{chr(10).join('  • ' + f['reason'] + ' (+' + str(f['weight']) + ')' for f in risk_factors) if risk_factors else '  None'}

Dashboard: {os.environ.get('DASHBOARD_URL', 'https://your-dashboard.com')}/host/{hostname}

---
This is an automated alert from C-Sentinel.
"""
    
    send_alert_email(hostname, subject, body)


def get_db():
    """Get database connection."""
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)


def require_api_key(f):
    """Decorator to require API key for endpoints. Supports both global and user API keys."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not key:
            return jsonify({'error': 'API key required'}), 401
        
        # Check global API key first (backward compatible)
        if key == API_KEY:
            return f(*args, **kwargs)
        
        # Check user API keys
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('''
                SELECT k.id, k.user_id, k.expires_at, u.username, u.role, u.active as user_active
                FROM user_api_keys k
                JOIN users u ON k.user_id = u.id
                WHERE k.key_hash = %s AND k.active = true
            ''', (key_hash,))
            api_key = cur.fetchone()
            
            if api_key:
                # Check if key is expired
                if api_key['expires_at'] and api_key['expires_at'] < datetime.now():
                    cur.close()
                    conn.close()
                    return jsonify({'error': 'API key expired'}), 401
                
                # Check if user is still active
                if not api_key['user_active']:
                    cur.close()
                    conn.close()
                    return jsonify({'error': 'User account disabled'}), 401
                
                # Update last_used timestamp
                cur.execute('UPDATE user_api_keys SET last_used = NOW() WHERE id = %s', (api_key['id'],))
                conn.commit()
                cur.close()
                conn.close()
                
                # Store user info in request context for logging
                request.api_key_user = {
                    'user_id': api_key['user_id'],
                    'username': api_key['username'],
                    'role': api_key['role']
                }
                
                return f(*args, **kwargs)
            
            cur.close()
            conn.close()
        except Exception as e:
            app.logger.error(f"API key validation error: {e}")
        
        return jsonify({'error': 'Invalid API key'}), 401
    return decorated


def validate_session():
    """Validate the current session against the database. Returns user dict or None."""
    session_token = session.get('session_token')
    if not session_token:
        return None
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Get session and user info
        cur.execute('''
            SELECT s.id, s.user_id, s.expires_at, u.username, u.role, u.active
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %s
        ''', (session_token,))
        
        result = cur.fetchone()
        
        if not result:
            cur.close()
            conn.close()
            return None
        
        # Check if expired or user inactive
        if result['expires_at'] < datetime.now() or not result['active']:
            # Clean up expired session
            cur.execute('DELETE FROM user_sessions WHERE id = %s', (result['id'],))
            conn.commit()
            cur.close()
            conn.close()
            return None
        
        # Update last_active timestamp
        cur.execute('UPDATE user_sessions SET last_active = NOW() WHERE id = %s', (result['id'],))
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            'user_id': result['user_id'],
            'username': result['username'],
            'role': result['role']
        }
    except Exception as e:
        app.logger.error(f"Session validation error: {e}")
        return None


def require_login(f):
    """Decorator to require dashboard login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not ADMIN_PASSWORD_HASH:
            # No password configured, allow access
            return f(*args, **kwargs)
        
        # Check for database session first (multi-user mode)
        if session.get('session_token'):
            user = validate_session()
            if user:
                # Update session with current user info
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['authenticated'] = True
                return f(*args, **kwargs)
            else:
                # Invalid session, clear it
                session.clear()
                return redirect(url_for('login'))
        
        # Fall back to simple auth check (single-password mode)
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Decorator to require specific user roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Check if authenticated at all
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            # Check role (single-password mode sets role='admin')
            user_role = session.get('role', 'viewer')
            if user_role not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def create_session(user_id, ip_address, user_agent):
    """Create a new database session for a user. Returns session token."""
    session_token = secrets.token_hex(32)
    expires_at = datetime.now() + timedelta(days=SESSION_LIFETIME_DAYS)
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
        ''', (user_id, session_token, expires_at, ip_address, user_agent[:512] if user_agent else None))
        conn.commit()
        cur.close()
        conn.close()
        return session_token
    except Exception as e:
        app.logger.error(f"Failed to create session: {e}")
        return None


def revoke_session(session_id, revoking_user_id=None):
    """Revoke a specific session."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('DELETE FROM user_sessions WHERE id = %s RETURNING user_id', (session_id,))
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if result and revoking_user_id:
            log_user_action(revoking_user_id, 'revoke_session', {'session_id': session_id})
        
        return result is not None
    except Exception as e:
        app.logger.error(f"Failed to revoke session: {e}")
        return False


def revoke_all_user_sessions(user_id, except_session_token=None):
    """Revoke all sessions for a user, optionally keeping one."""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        if except_session_token:
            cur.execute('''
                DELETE FROM user_sessions 
                WHERE user_id = %s AND session_token != %s
            ''', (user_id, except_session_token))
        else:
            cur.execute('DELETE FROM user_sessions WHERE user_id = %s', (user_id,))
        
        count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return count
    except Exception as e:
        app.logger.error(f"Failed to revoke sessions: {e}")
        return 0


def get_user_by_username(username):
    """Get user by username."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = %s AND active = true', (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def generate_api_key():
    """Generate a new API key. Returns (full_key, key_hash, key_prefix)."""
    # Generate a secure random key with prefix for identification
    key_body = secrets.token_hex(24)  # 48 chars
    full_key = f"sk_{key_body}"  # sk_ prefix indicates "secret key"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    key_prefix = full_key[:10]  # "sk_" + first 7 chars of body
    return full_key, key_hash, key_prefix


def create_api_key(user_id, name, expires_days=None):
    """Create a new API key for a user. Returns the full key (only shown once) or error dict."""
    full_key, key_hash, key_prefix = generate_api_key()
    
    expires_at = None
    if expires_days:
        expires_at = datetime.now() + timedelta(days=expires_days)
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO user_api_keys (user_id, key_hash, key_prefix, name, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        ''', (user_id, key_hash, key_prefix, name, expires_at))
        key_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        
        return {
            'id': key_id,
            'key': full_key,  # Only returned on creation!
            'prefix': key_prefix,
            'name': name,
            'expires_at': expires_at.isoformat() if expires_at else None
        }
    except Exception as e:
        app.logger.error(f"Failed to create API key: {e}")
        return {'error': str(e)}


def log_user_action(user_id, action, details=None):
    """Log user action for audit trail."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO user_audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, action, json.dumps(details) if details else None, get_client_ip()))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"Failed to log user action: {e}")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Dashboard login page."""
    # Check if multi-user is enabled (users table exists and has users)
    multi_user = False
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE active = true")
        user_count = cur.fetchone()['count']
        cur.close()
        conn.close()
        multi_user = user_count > 0
    except:
        pass
    
    # Fall back to single password mode if no users exist
    if not multi_user:
        if not ADMIN_PASSWORD_HASH:
            return redirect(url_for('index'))
        
        error = None
        if request.method == 'POST':
            password = request.form.get('password', '')
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if password_hash == ADMIN_PASSWORD_HASH:
                session['authenticated'] = True
                session['role'] = 'admin'
                session['username'] = 'admin'
                session.permanent = True
                return redirect(url_for('index'))
            else:
                error = 'Invalid password'
        
        return render_template('login.html', error=error, multi_user=False)
    
    # Multi-user mode
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '').strip()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user = get_user_by_username(username)
        
        if user and user['password_hash'] == password_hash:
            # Check if TOTP is enabled for this user
            if user.get('totp_enabled') and user.get('totp_secret'):
                if not TOTP_AVAILABLE:
                    error = '2FA is enabled but server lacks pyotp library'
                    return render_template('login.html', error=error, multi_user=True)
                
                # If no TOTP code provided, show TOTP prompt
                if not totp_code:
                    return render_template('login.html', 
                                         error=None, 
                                         multi_user=True, 
                                         totp_required=True,
                                         username=username,
                                         password=password)
                
                # Verify TOTP code
                totp = pyotp.TOTP(user['totp_secret'])
                if not totp.verify(totp_code, valid_window=1):
                    error = 'Invalid authentication code'
                    log_user_action(None, 'login_failed', {'username': username, 'ip': get_client_ip(), 'reason': 'invalid_totp'})
                    return render_template('login.html', error=error, multi_user=True)
            
            # Create database session
            client_ip = get_client_ip()
            session_token = create_session(
                user['id'],
                client_ip,
                request.headers.get('User-Agent')
            )
            
            if session_token:
                session['session_token'] = session_token
            
            session['authenticated'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            
            # Update last login
            try:
                conn = get_db()
                cur = conn.cursor()
                cur.execute('UPDATE users SET last_login = NOW() WHERE id = %s', (user['id'],))
                conn.commit()
                cur.close()
                conn.close()
            except:
                pass
            
            log_user_action(user['id'], 'login', {'ip': client_ip, '2fa': user.get('totp_enabled', False)})
            
            # Send login notification email (in background - don't block login)
            try:
                notify_new_login(user, client_ip, request.headers.get('User-Agent'))
            except:
                pass
            
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'
            log_user_action(None, 'login_failed', {'username': username, 'ip': get_client_ip()})
    
    return render_template('login.html', error=error, multi_user=True)


@app.route('/logout')
def logout():
    """Logout and clear session."""
    # Remove database session
    session_token = session.get('session_token')
    if session_token:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('DELETE FROM user_sessions WHERE session_token = %s', (session_token,))
            conn.commit()
            cur.close()
            conn.close()
        except:
            pass
    
    if session.get('user_id'):
        log_user_action(session['user_id'], 'logout')
    session.clear()
    return redirect(url_for('login'))


# ============================================================
# User Profile
# ============================================================

@app.route('/profile')
@require_login
def profile():
    """User profile page."""
    user = None
    
    # Get user info from database if in multi-user mode
    if session.get('user_id'):
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
            user = cur.fetchone()
            cur.close()
            conn.close()
        except:
            pass
    
    # Fallback for single-password mode
    if not user:
        user = {
            'username': session.get('username', 'admin'),
            'email': None,
            'role': session.get('role', 'admin'),
            'created_at': None,
            'last_login': None
        }
    
    return render_template('profile.html', user=user)


@app.route('/profile/password', methods=['POST'])
@require_login
def change_password():
    """Change user's own password."""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validation
    if len(new_password) < 8:
        return render_template('profile.html', user=get_current_user(), error='New password must be at least 8 characters')
    
    if new_password != confirm_password:
        return render_template('profile.html', user=get_current_user(), error='New passwords do not match')
    
    current_hash = hashlib.sha256(current_password.encode()).hexdigest()
    new_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    # Multi-user mode
    if session.get('user_id'):
        try:
            conn = get_db()
            cur = conn.cursor()
            
            # Verify current password
            cur.execute('SELECT password_hash FROM users WHERE id = %s', (session['user_id'],))
            user = cur.fetchone()
            
            if not user or user['password_hash'] != current_hash:
                cur.close()
                conn.close()
                return render_template('profile.html', user=get_current_user(), error='Current password is incorrect')
            
            # Update password
            cur.execute('UPDATE users SET password_hash = %s WHERE id = %s', (new_hash, session['user_id']))
            conn.commit()
            cur.close()
            conn.close()
            
            log_user_action(session['user_id'], 'password_changed')
            
            # Send notification email
            try:
                notify_password_changed(get_current_user())
            except:
                pass
            
            return render_template('profile.html', user=get_current_user(), success=True)
            
        except Exception as e:
            return render_template('profile.html', user=get_current_user(), error=f'Database error: {e}')
    
    # Single-password mode - check against ADMIN_PASSWORD_HASH
    if current_hash != ADMIN_PASSWORD_HASH:
        return render_template('profile.html', user=get_current_user(), error='Current password is incorrect')
    
    # Can't change password in single-password mode via UI
    return render_template('profile.html', user=get_current_user(), 
                          error='Password change not available in single-password mode. Update SENTINEL_ADMIN_PASSWORD_HASH in systemd config.')


def get_current_user():
    """Get current user info for templates."""
    if session.get('user_id'):
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
            user = cur.fetchone()
            cur.close()
            conn.close()
            return user
        except:
            pass
    
    return {
        'username': session.get('username', 'admin'),
        'email': None,
        'role': session.get('role', 'admin'),
        'created_at': None,
        'last_login': None,
        'totp_enabled': False
    }


# ============================================================
# Two-Factor Authentication (2FA/TOTP)
# ============================================================

@app.route('/profile/2fa')
@require_login
def two_factor_page():
    """2FA setup page."""
    if not TOTP_AVAILABLE:
        return render_template('2fa.html', user=get_current_user(), error='2FA not available. Install pyotp and qrcode packages.')
    return render_template('2fa.html', user=get_current_user())


@app.route('/api/me/2fa/setup', methods=['POST'])
@require_login
def setup_2fa():
    """Generate a new TOTP secret for 2FA setup."""
    if not TOTP_AVAILABLE:
        return jsonify({'error': '2FA not available. Install pyotp and qrcode packages.'}), 500
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    user = get_current_user()
    if user.get('totp_enabled'):
        return jsonify({'error': '2FA is already enabled. Disable it first to set up again.'}), 400
    
    # Generate new secret
    secret = pyotp.random_base32()
    
    # Create provisioning URI for QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user['username'],
        issuer_name='C-Sentinel'
    )
    
    # Generate QR code as base64
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Store secret temporarily in session (not yet confirmed)
    session['pending_totp_secret'] = secret
    
    return jsonify({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{qr_base64}'
    })


@app.route('/api/me/2fa/verify', methods=['POST'])
@require_login
def verify_2fa():
    """Verify TOTP code and enable 2FA."""
    if not TOTP_AVAILABLE:
        return jsonify({'error': '2FA not available'}), 500
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code or len(code) != 6:
        return jsonify({'error': 'Please enter a 6-digit code'}), 400
    
    secret = session.get('pending_totp_secret')
    if not secret:
        return jsonify({'error': 'No pending 2FA setup. Start setup again.'}), 400
    
    # Verify the code
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid code. Please try again.'}), 400
    
    # Save secret and enable 2FA
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            UPDATE users SET totp_secret = %s, totp_enabled = true
            WHERE id = %s
        ''', (secret, user_id))
        conn.commit()
        cur.close()
        conn.close()
        
        # Clear pending secret
        session.pop('pending_totp_secret', None)
        
        log_user_action(user_id, '2fa_enabled')
        
        # Notify user
        user = get_current_user()
        if user.get('email'):
            send_user_notification(
                user['email'],
                'Two-factor authentication enabled',
                f"""Hello {user['username']},

Two-factor authentication has been enabled on your C-Sentinel account.

If you did not do this, your account may be compromised. 
Please contact your administrator immediately."""
            )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/me/2fa/disable', methods=['POST'])
@require_login
def disable_2fa():
    """Disable 2FA for current user."""
    if not TOTP_AVAILABLE:
        return jsonify({'error': '2FA not available'}), 500
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    data = request.get_json()
    password = data.get('password', '')
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Verify password before disabling 2FA
    user = get_current_user()
    if user['password_hash'] != password_hash:
        return jsonify({'error': 'Invalid password'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            UPDATE users SET totp_secret = NULL, totp_enabled = false
            WHERE id = %s
        ''', (user_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        log_user_action(user_id, '2fa_disabled')
        
        # Notify user
        if user.get('email'):
            send_user_notification(
                user['email'],
                'Two-factor authentication disabled',
                f"""Hello {user['username']},

Two-factor authentication has been disabled on your C-Sentinel account.

If you did not do this, your account may be compromised. 
Please contact your administrator immediately and re-enable 2FA."""
            )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# API Keys (User can manage their own)
# ============================================================

@app.route('/profile/api-keys')
@require_login
def api_keys_page():
    """API keys management page."""
    return render_template('api_keys.html')


@app.route('/api/me/api-keys', methods=['GET'])
@require_login
def list_my_api_keys():
    """List current user's API keys."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT id, key_prefix, name, created_at, last_used, expires_at, active
        FROM user_api_keys
        WHERE user_id = %s
        ORDER BY created_at DESC
    ''', (user_id,))
    keys = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify([{
        'id': k['id'],
        'prefix': k['key_prefix'],
        'name': k['name'],
        'created_at': k['created_at'].isoformat() if k['created_at'] else None,
        'last_used': k['last_used'].isoformat() if k['last_used'] else None,
        'expires_at': k['expires_at'].isoformat() if k['expires_at'] else None,
        'active': k['active']
    } for k in keys])


@app.route('/api/me/api-keys', methods=['POST'])
@require_login
def create_my_api_key():
    """Create a new API key for current user."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    data = request.get_json()
    name = data.get('name', '').strip()
    expires_days = data.get('expires_days')  # None = never expires
    
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    
    if len(name) > 100:
        return jsonify({'error': 'Name too long (max 100 characters)'}), 400
    
    # Limit number of keys per user
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) as count FROM user_api_keys WHERE user_id = %s', (user_id,))
        count = cur.fetchone()['count']
        cur.close()
        conn.close()
        
        if count >= 10:
            return jsonify({'error': 'Maximum 10 API keys per user'}), 400
    except Exception as e:
        app.logger.error(f"API key count check failed: {e}")
        return jsonify({'error': f'Database error: {str(e)}. Have you run the migration?'}), 500
    
    result = create_api_key(user_id, name, expires_days)
    
    if result and 'error' not in result:
        log_user_action(user_id, 'create_api_key', {'name': name, 'key_prefix': result['prefix']})
        return jsonify(result)
    elif result and 'error' in result:
        return jsonify({'error': result['error']}), 500
    else:
        return jsonify({'error': 'Failed to create API key. Check server logs.'}), 500


@app.route('/api/me/api-keys/<int:key_id>', methods=['DELETE'])
@require_login
def delete_my_api_key(key_id):
    """Delete one of current user's API keys."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    conn = get_db()
    cur = conn.cursor()
    
    # Verify ownership
    cur.execute('SELECT key_prefix FROM user_api_keys WHERE id = %s AND user_id = %s', (key_id, user_id))
    key = cur.fetchone()
    
    if not key:
        cur.close()
        conn.close()
        return jsonify({'error': 'API key not found'}), 404
    
    cur.execute('DELETE FROM user_api_keys WHERE id = %s', (key_id,))
    conn.commit()
    cur.close()
    conn.close()
    
    log_user_action(user_id, 'delete_api_key', {'key_prefix': key['key_prefix']})
    
    return jsonify({'success': True})


@app.route('/api/me/api-keys/<int:key_id>/toggle', methods=['POST'])
@require_login
def toggle_my_api_key(key_id):
    """Enable or disable one of current user's API keys."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not available in single-password mode'}), 400
    
    conn = get_db()
    cur = conn.cursor()
    
    # Verify ownership and toggle
    cur.execute('''
        UPDATE user_api_keys 
        SET active = NOT active 
        WHERE id = %s AND user_id = %s
        RETURNING active, key_prefix
    ''', (key_id, user_id))
    
    result = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    
    if not result:
        return jsonify({'error': 'API key not found'}), 404
    
    log_user_action(user_id, 'toggle_api_key', {
        'key_prefix': result['key_prefix'],
        'active': result['active']
    })
    
    return jsonify({'active': result['active']})


# ============================================================
# User Management (Admin Only)
# ============================================================

@app.route('/admin/users')
@require_login
@require_role('admin')
def admin_users():
    """User management page."""
    return render_template('admin/users.html')


@app.route('/admin/audit')
@require_login
@require_role('admin')
def admin_audit():
    """Audit log page."""
    return render_template('admin/audit.html')


@app.route('/api/admin/audit-log')
@require_login
@require_role('admin')
def get_audit_log():
    """Get paginated audit log entries."""
    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 50)), 200)
    action = request.args.get('action')
    user_id = request.args.get('user_id')
    time_range = request.args.get('time_range', '24h')
    
    offset = (page - 1) * limit
    
    # Build query
    query = '''
        SELECT a.id, a.action, a.details, a.ip_address, a.created_at,
               u.username
        FROM user_audit_log a
        LEFT JOIN users u ON a.user_id = u.id
        WHERE 1=1
    '''
    count_query = 'SELECT COUNT(*) as total FROM user_audit_log a WHERE 1=1'
    params = []
    count_params = []
    
    # Time range filter
    if time_range == '24h':
        query += " AND a.created_at > NOW() - INTERVAL '24 hours'"
        count_query += " AND a.created_at > NOW() - INTERVAL '24 hours'"
    elif time_range == '7d':
        query += " AND a.created_at > NOW() - INTERVAL '7 days'"
        count_query += " AND a.created_at > NOW() - INTERVAL '7 days'"
    elif time_range == '30d':
        query += " AND a.created_at > NOW() - INTERVAL '30 days'"
        count_query += " AND a.created_at > NOW() - INTERVAL '30 days'"
    
    # Action filter
    if action:
        query += ' AND a.action = %s'
        count_query += ' AND a.action = %s'
        params.append(action)
        count_params.append(action)
    
    # User filter
    if user_id:
        query += ' AND a.user_id = %s'
        count_query += ' AND a.user_id = %s'
        params.append(int(user_id))
        count_params.append(int(user_id))
    
    query += ' ORDER BY a.created_at DESC LIMIT %s OFFSET %s'
    params.extend([limit, offset])
    
    conn = get_db()
    cur = conn.cursor()
    
    # Get total count
    cur.execute(count_query, count_params)
    total = cur.fetchone()['total']
    
    # Get entries
    cur.execute(query, params)
    entries = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return jsonify({
        'total': total,
        'page': page,
        'limit': limit,
        'entries': [{
            'id': e['id'],
            'username': e['username'],
            'action': e['action'],
            'details': e['details'],
            'ip_address': e['ip_address'],
            'created_at': e['created_at'].isoformat() if e['created_at'] else None
        } for e in entries]
    })


@app.route('/admin/sessions')
@require_login
@require_role('admin')
def admin_sessions():
    """Session management page."""
    return render_template('admin/sessions.html')


@app.route('/api/admin/sessions')
@require_login
@require_role('admin')
def get_sessions():
    """Get all active sessions."""
    current_token = session.get('session_token')
    
    conn = get_db()
    cur = conn.cursor()
    
    # Get all sessions with user info
    cur.execute('''
        SELECT s.id, s.session_token, s.created_at, s.last_active, s.expires_at, 
               s.ip_address, s.user_agent, u.id as user_id, u.username, u.role
        FROM user_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.expires_at > NOW()
        ORDER BY s.last_active DESC
    ''')
    sessions_data = cur.fetchall()
    
    # Count unique users and active now
    cur.execute('''
        SELECT COUNT(DISTINCT user_id) as unique_users,
               COUNT(*) FILTER (WHERE last_active > NOW() - INTERVAL '5 minutes') as active_now
        FROM user_sessions
        WHERE expires_at > NOW()
    ''')
    stats = cur.fetchone()
    
    cur.close()
    conn.close()
    
    return jsonify({
        'total': len(sessions_data),
        'unique_users': stats['unique_users'],
        'active_now': stats['active_now'],
        'sessions': [{
            'id': s['id'],
            'user_id': s['user_id'],
            'username': s['username'],
            'role': s['role'],
            'created_at': s['created_at'].isoformat() if s['created_at'] else None,
            'last_active': s['last_active'].isoformat() if s['last_active'] else None,
            'expires_at': s['expires_at'].isoformat() if s['expires_at'] else None,
            'ip_address': s['ip_address'],
            'user_agent': s['user_agent'],
            'is_current': s['session_token'] == current_token
        } for s in sessions_data]
    })


@app.route('/api/admin/sessions/<int:session_id>', methods=['DELETE'])
@require_login
@require_role('admin')
def revoke_session_api(session_id):
    """Revoke a specific session."""
    current_token = session.get('session_token')
    
    conn = get_db()
    cur = conn.cursor()
    
    # Check if trying to revoke own session
    cur.execute('SELECT session_token, user_id FROM user_sessions WHERE id = %s', (session_id,))
    target = cur.fetchone()
    
    if not target:
        cur.close()
        conn.close()
        return jsonify({'error': 'Session not found'}), 404
    
    if target['session_token'] == current_token:
        cur.close()
        conn.close()
        return jsonify({'error': 'Cannot revoke your own session'}), 400
    
    # Get username for audit log
    cur.execute('SELECT username FROM users WHERE id = %s', (target['user_id'],))
    user = cur.fetchone()
    
    # Delete the session
    cur.execute('DELETE FROM user_sessions WHERE id = %s', (session_id,))
    conn.commit()
    cur.close()
    conn.close()
    
    log_user_action(session.get('user_id'), 'revoke_session', {
        'target_user': user['username'] if user else 'unknown',
        'session_id': session_id
    })
    
    return jsonify({'success': True})


@app.route('/api/admin/sessions/revoke-all-others', methods=['POST'])
@require_login
@require_role('admin')
def revoke_all_others_api():
    """Revoke all sessions except the current one."""
    current_token = session.get('session_token')
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('''
        DELETE FROM user_sessions 
        WHERE session_token != %s
    ''', (current_token,))
    
    count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    
    log_user_action(session.get('user_id'), 'revoke_all_sessions', {'count': count})
    
    return jsonify({'revoked': count})


@app.route('/api/admin/sessions/cleanup', methods=['POST'])
@require_login
@require_role('admin')
def cleanup_sessions_api():
    """Remove all expired sessions."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('DELETE FROM user_sessions WHERE expires_at < NOW()')
    count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    
    log_user_action(session.get('user_id'), 'cleanup_sessions', {'removed': count})
    
    return jsonify({'removed': count})


@app.route('/api/users', methods=['GET'])
@require_login
@require_role('admin')
def list_users():
    """List all users."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT id, username, email, role, created_at, last_login, active
        FROM users
        ORDER BY username
    ''')
    users = cur.fetchall()
    cur.close()
    conn.close()
    
    result = []
    for u in users:
        user = dict(u)
        user['created_at'] = user['created_at'].isoformat() if user['created_at'] else None
        user['last_login'] = user['last_login'].isoformat() if user['last_login'] else None
        result.append(user)
    
    return jsonify(result)


@app.route('/api/users', methods=['POST'])
@require_login
@require_role('admin')
def create_user():
    """Create a new user."""
    data = request.get_json()
    
    username = data.get('username', '').strip().lower()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'viewer')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    if role not in ('admin', 'operator', 'viewer'):
        return jsonify({'error': 'Invalid role'}), 400
    
    if len(username) < 3 or len(username) > 64:
        return jsonify({'error': 'Username must be 3-64 characters'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        ''', (username, email or None, password_hash, role))
        user_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        
        log_user_action(session.get('user_id'), 'create_user', {'new_user': username, 'role': role})
        
        # Send welcome email with temporary password
        try:
            notify_account_created({'username': username, 'email': email, 'role': role}, temp_password=password)
        except:
            pass
        
        return jsonify({'id': user_id, 'username': username, 'role': role})
    
    except psycopg2.errors.UniqueViolation:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_login
@require_role('admin')
def update_user(user_id):
    """Update a user."""
    data = request.get_json()
    
    # Get current user info for notifications
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT username, email, role FROM users WHERE id = %s', (user_id,))
    current_user = cur.fetchone()
    cur.close()
    conn.close()
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    old_role = current_user['role']
    
    updates = []
    params = []
    
    if 'email' in data:
        updates.append('email = %s')
        params.append(data['email'].strip() or None)
    
    if 'role' in data:
        if data['role'] not in ('admin', 'operator', 'viewer'):
            return jsonify({'error': 'Invalid role'}), 400
        updates.append('role = %s')
        params.append(data['role'])
    
    if 'active' in data:
        updates.append('active = %s')
        params.append(bool(data['active']))
    
    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        updates.append('password_hash = %s')
        params.append(hashlib.sha256(data['password'].encode()).hexdigest())
    
    if not updates:
        return jsonify({'error': 'No updates provided'}), 400
    
    params.append(user_id)
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f'''
            UPDATE users SET {', '.join(updates)}
            WHERE id = %s
            RETURNING username, email, role
        ''', params)
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if not result:
            return jsonify({'error': 'User not found'}), 404
        
        log_user_action(session.get('user_id'), 'update_user', {'target_user_id': user_id, 'updates': list(data.keys())})
        
        # Send notifications for significant changes
        try:
            # Role change notification
            if 'role' in data and data['role'] != old_role:
                notify_role_changed({'username': result['username'], 'email': result['email']}, old_role, data['role'])
            
            # Password change notification (admin changed their password)
            if 'password' in data and data['password']:
                notify_password_changed({'username': result['username'], 'email': result['email']})
        except:
            pass
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_login
@require_role('admin')
def delete_user(user_id):
    """Delete a user (soft delete - sets active=false)."""
    # Don't allow deleting yourself
    if session.get('user_id') == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('UPDATE users SET active = false WHERE id = %s RETURNING username', (user_id,))
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if not result:
            return jsonify({'error': 'User not found'}), 404
        
        log_user_action(session.get('user_id'), 'delete_user', {'target_user': result['username']})
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================
# Database Schema
# ============================================================

def init_db():
    """Initialize database schema."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(255) UNIQUE NOT NULL,
            first_seen TIMESTAMP DEFAULT NOW(),
            last_seen TIMESTAMP DEFAULT NOW()
        )
    ''')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id SERIAL PRIMARY KEY,
            host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
            captured_at TIMESTAMP DEFAULT NOW(),
            exit_code INTEGER,
            data JSONB,
            -- Extracted fields for querying
            process_count INTEGER,
            zombie_count INTEGER,
            memory_percent FLOAT,
            load_1m FLOAT,
            listener_count INTEGER,
            unusual_port_count INTEGER,
            uptime_days FLOAT,
            -- Audit fields (v0.4.0)
            audit_enabled BOOLEAN DEFAULT FALSE,
            audit_risk_score INTEGER,
            audit_risk_level VARCHAR(16),
            audit_auth_failures INTEGER,
            audit_sudo_count INTEGER,
            audit_brute_force BOOLEAN DEFAULT FALSE
        )
    ''')
    
    # Add audit columns if they don't exist (for upgrades)
    audit_columns = [
        ('audit_enabled', 'BOOLEAN DEFAULT FALSE'),
        ('audit_risk_score', 'INTEGER'),
        ('audit_risk_level', 'VARCHAR(16)'),
        ('audit_auth_failures', 'INTEGER'),
        ('audit_sudo_count', 'INTEGER'),
        ('audit_brute_force', 'BOOLEAN DEFAULT FALSE'),
    ]
    
    for col_name, col_type in audit_columns:
        try:
            cur.execute(f'''
                ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS {col_name} {col_type}
            ''')
        except:
            pass  # Column may already exist
    
    cur.execute('''
        CREATE INDEX IF NOT EXISTS idx_fingerprints_host_time 
        ON fingerprints(host_id, captured_at DESC)
    ''')
    
    cur.execute('''
        CREATE INDEX IF NOT EXISTS idx_fingerprints_captured 
        ON fingerprints(captured_at DESC)
    ''')
    
    conn.commit()
    cur.close()
    conn.close()


# ============================================================
# API Endpoints
# ============================================================

@app.route('/api/ingest', methods=['POST'])
@require_api_key
def ingest_fingerprint():
    """Receive fingerprint data from sentinel agents."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        hostname = data.get('system', {}).get('hostname', data.get('hostname', 'unknown'))
        
        conn = get_db()
        cur = conn.cursor()
        
        # Upsert host
        cur.execute('''
            INSERT INTO hosts (hostname, last_seen) 
            VALUES (%s, NOW())
            ON CONFLICT (hostname) DO UPDATE SET last_seen = NOW()
            RETURNING id
        ''', (hostname,))
        host_id = cur.fetchone()['id']
        
        # Extract metrics
        system = data.get('system', {})
        process_summary = data.get('process_summary', {})
        network = data.get('network', {})
        
        # Parse uptime - it's already a float in uptime_days
        try:
            uptime_days = float(system.get('uptime_days', 0))
        except:
            uptime_days = 0
        
        # Parse load - it's an array [1m, 5m, 15m]
        load_avg = system.get('load_average', [0, 0, 0])
        try:
            if isinstance(load_avg, list) and len(load_avg) > 0:
                load_1m = float(load_avg[0])
            else:
                load_1m = 0
        except:
            load_1m = 0

        # Extract audit data (v0.4.0)
        audit = data.get('audit_summary', {})
        audit_enabled = audit.get('enabled', False)
        audit_risk_score = audit.get('risk_score', None)
        audit_risk_level = audit.get('risk_level', None)
        audit_auth = audit.get('authentication', {})
        audit_auth_failures = audit_auth.get('failures', 0)
        audit_brute_force = audit_auth.get('brute_force_detected', False)
        audit_priv = audit.get('privilege_escalation', {})
        audit_sudo_count = audit_priv.get('sudo_count', 0)

        # Insert fingerprint
        cur.execute('''
            INSERT INTO fingerprints (
                host_id, data, exit_code,
                process_count, zombie_count, memory_percent,
                load_1m, listener_count, unusual_port_count, uptime_days,
                audit_enabled, audit_risk_score, audit_risk_level,
                audit_auth_failures, audit_sudo_count, audit_brute_force
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            host_id,
            json.dumps(data),
            request.headers.get('X-Exit-Code', 0),
            process_summary.get('total_count', 0),
            process_summary.get('zombie_count', 0),
            system.get('memory_used_percent', 0),
            load_1m,
            network.get('total_listeners', 0),
            network.get('unusual_ports', 0),
            uptime_days,
            audit_enabled,
            audit_risk_score,
            audit_risk_level,
            audit_auth_failures,
            audit_sudo_count,
            audit_brute_force
        ))
        
        fingerprint_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        
        # Check for alert conditions
        check_and_send_alerts(hostname, audit)
        
        return jsonify({
            'status': 'ok',
            'host_id': host_id,
            'fingerprint_id': fingerprint_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts')
@require_login
def list_hosts():
    """List all known hosts."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('''
        SELECT h.id, h.hostname, h.first_seen, h.last_seen,
               f.exit_code, f.process_count, f.zombie_count,
               f.memory_percent, f.load_1m, f.listener_count,
               f.unusual_port_count, f.uptime_days,
               f.audit_enabled, f.audit_risk_score, f.audit_risk_level,
               f.audit_auth_failures, f.audit_brute_force
        FROM hosts h
        LEFT JOIN LATERAL (
            SELECT * FROM fingerprints 
            WHERE host_id = h.id 
            ORDER BY captured_at DESC 
            LIMIT 1
        ) f ON true
        ORDER BY h.hostname
    ''')
    
    hosts = cur.fetchall()
    cur.close()
    conn.close()
    
    # Convert to serializable format
    result = []
    for h in hosts:
        host = dict(h)
        host['first_seen'] = host['first_seen'].isoformat() if host['first_seen'] else None
        host['last_seen'] = host['last_seen'].isoformat() if host['last_seen'] else None
        
        # Calculate status
        if host['last_seen']:
            last_seen = datetime.fromisoformat(host['last_seen'])
            age_minutes = (datetime.now() - last_seen).total_seconds() / 60
            if age_minutes > 10:
                host['status'] = 'stale'
            elif host['exit_code'] == 2:
                host['status'] = 'critical'
            elif host['exit_code'] == 1:
                host['status'] = 'warning'
            else:
                host['status'] = 'ok'
        else:
            host['status'] = 'unknown'
        
        result.append(host)
    
    return jsonify(result)


@app.route('/api/hosts/<hostname>')
@require_login
def get_host(hostname):
    """Get details for a specific host."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('SELECT * FROM hosts WHERE hostname = %s', (hostname,))
    host = cur.fetchone()
    
    if not host:
        cur.close()
        conn.close()
        return jsonify({'error': 'Host not found'}), 404
    
    # Get recent fingerprints
    cur.execute('''
        SELECT id, captured_at, exit_code, process_count, zombie_count,
               memory_percent, load_1m, listener_count, unusual_port_count, uptime_days,
               audit_enabled, audit_risk_score, audit_risk_level,
               audit_auth_failures, audit_sudo_count, audit_brute_force
        FROM fingerprints
        WHERE host_id = %s
        ORDER BY captured_at DESC
        LIMIT 100
    ''', (host['id'],))
    
    fingerprints = cur.fetchall()
    cur.close()
    conn.close()
    
    result = dict(host)
    result['first_seen'] = result['first_seen'].isoformat() if result['first_seen'] else None
    result['last_seen'] = result['last_seen'].isoformat() if result['last_seen'] else None
    result['fingerprints'] = [
        {**dict(f), 'captured_at': f['captured_at'].isoformat()}
        for f in fingerprints
    ]
    
    return jsonify(result)


@app.route('/api/hosts/<hostname>/latest')
@require_login
def get_latest_fingerprint(hostname):
    """Get the latest full fingerprint for a host."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('''
        SELECT f.data, f.captured_at, f.exit_code
        FROM fingerprints f
        JOIN hosts h ON f.host_id = h.id
        WHERE h.hostname = %s
        ORDER BY f.captured_at DESC
        LIMIT 1
    ''', (hostname,))
    
    result = cur.fetchone()
    cur.close()
    conn.close()
    
    if not result:
        return jsonify({'error': 'No fingerprints found'}), 404
    
    return jsonify({
        'data': result['data'],
        'captured_at': result['captured_at'].isoformat(),
        'exit_code': result['exit_code']
    })


@app.route('/api/stats')
@require_login
def get_stats():
    """Get overall statistics."""
    conn = get_db()
    cur = conn.cursor()
    
    # Host counts
    cur.execute('SELECT COUNT(*) as total FROM hosts')
    total_hosts = cur.fetchone()['total']
    
    # Recent activity (last hour)
    cur.execute('''
        SELECT COUNT(DISTINCT host_id) as active
        FROM fingerprints
        WHERE captured_at > NOW() - INTERVAL '1 hour'
    ''')
    active_hosts = cur.fetchone()['active']
    
    # Critical hosts (includes high-risk audit)
    cur.execute('''
        SELECT COUNT(DISTINCT f.host_id) as critical
        FROM fingerprints f
        WHERE f.captured_at > NOW() - INTERVAL '10 minutes'
        AND (f.exit_code = 2 OR f.audit_risk_level IN ('high', 'critical'))
    ''')
    critical_hosts = cur.fetchone()['critical']
    
    # Total fingerprints
    cur.execute('SELECT COUNT(*) as total FROM fingerprints')
    total_fingerprints = cur.fetchone()['total']
    
    cur.close()
    conn.close()
    
    return jsonify({
        'total_hosts': total_hosts,
        'active_hosts': active_hosts,
        'critical_hosts': critical_hosts,
        'total_fingerprints': total_fingerprints
    })


# ============================================================
# Events API (Operator+ access for modifications)
# ============================================================

@app.route('/api/hosts/<hostname>/events')
@require_login
def get_events(hostname):
    """Get security events for a host."""
    event_type = request.args.get('type')
    include_acknowledged = request.args.get('include_acknowledged', 'false').lower() == 'true'
    limit = min(int(request.args.get('limit', 100)), 500)
    
    conn = get_db()
    cur = conn.cursor()
    
    # Get host ID
    cur.execute('SELECT id FROM hosts WHERE hostname = %s', (hostname,))
    host = cur.fetchone()
    if not host:
        cur.close()
        conn.close()
        return jsonify({'error': 'Host not found'}), 404
    
    # Build query
    query = '''
        SELECT id, event_type, count, details, captured_at, acknowledged
        FROM audit_events
        WHERE host_id = %s
    '''
    params = [host['id']]
    
    if not include_acknowledged:
        query += ' AND acknowledged = false'
    
    if event_type:
        query += ' AND event_type = %s'
        params.append(event_type)
    
    query += ' ORDER BY captured_at DESC LIMIT %s'
    params.append(limit)
    
    cur.execute(query, params)
    events = cur.fetchall()
    cur.close()
    conn.close()
    
    return jsonify([{
        'id': e['id'],
        'event_type': e['event_type'],
        'count': e['count'],
        'details': e['details'],
        'captured_at': e['captured_at'].isoformat() if e['captured_at'] else None,
        'acknowledged': e['acknowledged']
    } for e in events])


@app.route('/api/hosts/<hostname>/events/acknowledge', methods=['POST'])
@require_login
@require_role('admin', 'operator')
def acknowledge_events(hostname):
    """Acknowledge all events for a host. Requires operator or admin role."""
    conn = get_db()
    cur = conn.cursor()
    
    # Get host ID
    cur.execute('SELECT id FROM hosts WHERE hostname = %s', (hostname,))
    host = cur.fetchone()
    if not host:
        cur.close()
        conn.close()
        return jsonify({'error': 'Host not found'}), 404
    
    cur.execute('''
        UPDATE audit_events
        SET acknowledged = true
        WHERE host_id = %s AND acknowledged = false
    ''', (host['id'],))
    
    count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    
    log_user_action(session.get('user_id'), 'acknowledge_events', {'hostname': hostname, 'count': count})
    
    return jsonify({'acknowledged': count})


@app.route('/api/hosts/<hostname>/reset-audit', methods=['POST'])
@require_login
@require_role('admin', 'operator')
def reset_audit(hostname):
    """Reset audit counters for a host. Requires operator or admin role."""
    conn = get_db()
    cur = conn.cursor()
    
    # Get host
    cur.execute('SELECT id FROM hosts WHERE hostname = %s', (hostname,))
    host = cur.fetchone()
    if not host:
        cur.close()
        conn.close()
        return jsonify({'error': 'Host not found'}), 404
    
    # Reset cumulative totals in hosts table
    cur.execute('''
        UPDATE hosts
        SET audit_total_auth_failures = 0,
            audit_total_sudo = 0,
            audit_total_file_access = 0,
            audit_total_brute_force = 0,
            audit_totals_since = NOW()
        WHERE id = %s
    ''', (host['id'],))
    
    # Acknowledge all events
    cur.execute('''
        UPDATE audit_events
        SET acknowledged = true
        WHERE host_id = %s AND acknowledged = false
    ''', (host['id'],))
    
    events_acknowledged = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    
    log_user_action(session.get('user_id'), 'reset_audit', {'hostname': hostname, 'events_acknowledged': events_acknowledged})
    
    return jsonify({'success': True, 'events_acknowledged': events_acknowledged})


# ============================================================
# Web Interface
# ============================================================

@app.route('/')
@require_login
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/host/<hostname>')
@require_login
def host_detail(hostname):
    """Host detail page."""
    return render_template('host.html', hostname=hostname)


# ============================================================
# Health Check
# ============================================================

@app.route('/health')
def health():
    """Health check endpoint."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.close()
        conn.close()
        return jsonify({'status': 'healthy', 'database': 'connected'})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500


# ============================================================
# CLI Commands
# ============================================================

@app.cli.command('create-user')
def create_user_cli():
    """Create a new user interactively."""
    import getpass
    
    print("Create new C-Sentinel user")
    print("-" * 30)
    
    username = input("Username: ").strip().lower()
    if not username or len(username) < 3:
        print("Error: Username must be at least 3 characters")
        return
    
    email = input("Email (optional): ").strip() or None
    
    password = getpass.getpass("Password (min 8 chars): ")
    if len(password) < 8:
        print("Error: Password must be at least 8 characters")
        return
    
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("Error: Passwords do not match")
        return
    
    print("\nRoles: admin, operator, viewer")
    role = input("Role [viewer]: ").strip().lower() or 'viewer'
    if role not in ('admin', 'operator', 'viewer'):
        print("Error: Invalid role")
        return
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        ''', (username, email, password_hash, role))
        user_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n✓ User '{username}' created successfully (ID: {user_id}, Role: {role})")
        
    except psycopg2.errors.UniqueViolation:
        print(f"Error: Username '{username}' already exists")
    except Exception as e:
        print(f"Error: {e}")


@app.cli.command('list-users')
def list_users_cli():
    """List all users."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT id, username, email, role, active, last_login FROM users ORDER BY username')
        users = cur.fetchall()
        cur.close()
        conn.close()
        
        if not users:
            print("No users found.")
            return
        
        print(f"{'ID':<4} {'Username':<20} {'Role':<10} {'Active':<8} {'Last Login'}")
        print("-" * 70)
        for u in users:
            last_login = u['last_login'].strftime('%Y-%m-%d %H:%M') if u['last_login'] else 'Never'
            active = '✓' if u['active'] else '✗'
            print(f"{u['id']:<4} {u['username']:<20} {u['role']:<10} {active:<8} {last_login}")
            
    except Exception as e:
        print(f"Error: {e}")


@app.cli.command('reset-password')
def reset_password_cli():
    """Reset a user's password."""
    import getpass
    
    username = input("Username: ").strip().lower()
    
    password = getpass.getpass("New password (min 8 chars): ")
    if len(password) < 8:
        print("Error: Password must be at least 8 characters")
        return
    
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("Error: Passwords do not match")
        return
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('UPDATE users SET password_hash = %s WHERE username = %s RETURNING id', 
                    (password_hash, username))
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        if result:
            print(f"✓ Password updated for '{username}'")
        else:
            print(f"Error: User '{username}' not found")
            
    except Exception as e:
        print(f"Error: {e}")


# ============================================================
# Main
# ============================================================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
