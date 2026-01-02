#!/usr/bin/env python3
"""
C-Sentinel Dashboard
A web interface for viewing system fingerprints across multiple hosts.
"""

import os
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, jsonify, request, Response
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# Configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432'),
    'database': os.environ.get('DB_NAME', 'sentinel'),
    'user': os.environ.get('DB_USER', 'sentinel'),
    'password': os.environ.get('DB_PASSWORD', 'your_db_pass_secured'),
}

API_KEY = os.environ.get('SENTINEL_API_KEY', 'change-me-in-production')


def get_db():
    """Get database connection."""
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)


def require_api_key(f):
    """Decorator to require API key for endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if key != API_KEY:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated


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
        
        return jsonify({
            'status': 'ok',
            'host_id': host_id,
            'fingerprint_id': fingerprint_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts')
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
# Web Interface
# ============================================================

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/host/<hostname>')
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
# Main
# ============================================================

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
