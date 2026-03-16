from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime
import random, json, os

app = Flask(__name__)
app.secret_key = 'cyberrisk_secret_2024_tn'

# ─── In-Memory Database ───────────────────────────────────────
USERS = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user':  {'password': 'user123',  'role': 'user'},
}

VICTIM_MAP = {
    'Chennai':         ['Arun Kumar', 'Divya', 'Rohit', 'Sneha'],
    'Coimbatore':      ['Priya', 'Kiran', 'Sanjay', 'Meena'],
    'Madurai':         ['Karthik', 'Anitha', 'Ramesh', 'Deepa'],
    'Salem':           ['Lakshmi', 'Vignesh', 'Saranya', 'Prakash'],
    'Tiruchirappalli': ['Ravi', 'Naveen', 'Swetha', 'Manoj'],
}

SCAM_TYPES = [
    'UPI Fraud',
    'OTP Verification Scam',
    'Online Shopping Scam',
    'Job Offer Scam',
    'Lottery Fraud',
]

import datetime as _dt
def _mo(offset=0):
    d = _dt.date.today().replace(day=15)
    # subtract offset months
    for _ in range(offset):
        d = (d.replace(day=1) - _dt.timedelta(days=1)).replace(day=15)
    return d.strftime('%Y-%m-%d') + ' 10:00'

INCIDENTS = [
    {'id':1,'district':'Chennai',        'scam_type':'UPI Fraud',            'victim_name':'Arun Kumar','victim_count':45,'threat_index':'High',  'timestamp':_mo(0)},
    {'id':2,'district':'Coimbatore',     'scam_type':'OTP Verification Scam','victim_name':'Priya',     'victim_count':23,'threat_index':'Medium','timestamp':_mo(0)},
    {'id':3,'district':'Madurai',        'scam_type':'Online Shopping Scam', 'victim_name':'Karthik',   'victim_count':12,'threat_index':'Low',   'timestamp':_mo(1)},
    {'id':4,'district':'Salem',          'scam_type':'Job Offer Scam',       'victim_name':'Lakshmi',   'victim_count':34,'threat_index':'High',  'timestamp':_mo(1)},
    {'id':5,'district':'Tiruchirappalli','scam_type':'Lottery Fraud',        'victim_name':'Ravi',      'victim_count':18,'threat_index':'Medium','timestamp':_mo(2)},
]

ALERTS = [
    {'id':1,'message':'High Threat Index Detected in Chennai','district':'Chennai','timestamp':_mo(0),'read':False},
    {'id':2,'message':'High Threat Index Detected in Salem',  'district':'Salem',  'timestamp':_mo(1),'read':False},
]

_next_id       = 6
_next_alert_id = 3

# ─── Analysis: always use ACTUAL entered data ───────────────
def run_ml_analysis():
    """
    District threat level = exactly what was entered in Data Entry.
    If a district has multiple entries the LATEST entry's threat_index is used.
    If a district has NO entry it shows 'No Data'.
    ML runs in the background only to produce the trend forecast numbers.
    """
    # Build risk map strictly from latest actual incident per district
    order = ['Low', 'Medium', 'High']
    risk  = {}
    latest = {}   # district -> latest incident by id

    for inc in INCIDENTS:
        dist = inc['district']
        if dist not in latest or inc['id'] > latest[dist]['id']:
            latest[dist] = inc

    for dist in VICTIM_MAP:
        if dist in latest:
            risk[dist] = latest[dist]['threat_index']   # exact value from data entry
        else:
            risk[dist] = 'No Data'

    return _build_result(risk)

def _build_result(risk):
    order = ['High', 'Medium', 'Low', 'No Data']

    def sort_key(d):
        v = risk.get(d, 'No Data')
        return order.index(v) if v in order else len(order)

    ranked = sorted(VICTIM_MAP.keys(), key=sort_key)

    scam_counts  = {s: 0 for s in SCAM_TYPES}
    dist_victims = {d: 0 for d in VICTIM_MAP}
    for inc in INCIDENTS:
        scam_counts[inc['scam_type']]  = scam_counts.get(inc['scam_type'], 0) + 1
        dist_victims[inc['district']]  = dist_victims.get(inc['district'], 0) + inc['victim_count']

    # Trend: month-wise victim count aggregated from real data
    from collections import defaultdict
    monthly = defaultdict(int)
    for inc in INCIDENTS:
        try:
            mo = inc['timestamp'][:7]   # "YYYY-MM"
        except Exception:
            mo = 'Unknown'
        monthly[mo] += inc['victim_count']

    # Last 6 months labels + data
    import datetime as dt
    today = dt.date.today()
    trend_labels, trend_data = [], []
    for offset in range(5, -1, -1):
        d  = today.replace(day=1) - dt.timedelta(days=offset * 28)
        ym = d.strftime('%Y-%m')
        trend_labels.append(d.strftime('%b'))
        trend_data.append(monthly.get(ym, 0))

    # Top district = one with highest threat from actual data (ignore No Data)
    real = {d: v for d, v in risk.items() if v != 'No Data'}
    if real:
        top = min(real, key=lambda d: order.index(real[d]))
    else:
        top = list(VICTIM_MAP.keys())[0]

    return {
        'district_risk':    risk,
        'ranking':          [{'rank': i+1, 'district': d, 'threat': risk[d]} for i, d in enumerate(ranked)],
        'scam_distribution': scam_counts,
        'district_victims': dist_victims,
        'trend_labels':     trend_labels,
        'trend_data':       trend_data,
        'top_district':     top,
        'top_threat':       risk.get(top, 'No Data'),
        'total_victims':    sum(dist_victims.values()),
        'high_zones':       [d for d, t in risk.items() if t == 'High'],
    }

# ─── Auth Routes ────────────────────────────────────────────
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','').strip()
        if u in USERS and USERS[u]['password'] == p:
            session['username'] = u
            session['role']     = USERS[u]['role']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u    = request.form.get('username','').strip()
        p    = request.form.get('password','').strip()
        role = request.form.get('role','user')
        if not u or not p:
            return render_template('register.html', error='Username and password required.')
        if u in USERS:
            return render_template('register.html', error='Username already exists.')
        USERS[u] = {'password':p,'role':role}
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Page Routes ────────────────────────────────────────────
def require_login():
    if 'username' not in session:
        return redirect(url_for('login'))
    return None

@app.route('/dashboard')
def dashboard():
    r = require_login(); return r if r else render_template('dashboard.html')

@app.route('/threat-map')
def threat_map():
    r = require_login(); return r if r else render_template('threat_map.html')

@app.route('/data-entry')
def data_entry():
    r = require_login(); return r if r else render_template('data_entry.html')

@app.route('/analytics')
def analytics():
    r = require_login(); return r if r else render_template('analytics.html')

@app.route('/visualization')
def visualization():
    r = require_login(); return r if r else render_template('visualization.html')

@app.route('/incidents')
def incidents():
    r = require_login(); return r if r else render_template('incidents.html')

@app.route('/cyber-safety')
def cyber_safety():
    r = require_login(); return r if r else render_template('cyber_safety.html')

# ─── API ────────────────────────────────────────────────────
@app.route('/api/session')
def api_session():
    return jsonify({'username':session.get('username',''),'role':session.get('role','user'),'logged_in':'username' in session})

@app.route('/api/incidents', methods=['GET'])
def api_get_incidents():
    return jsonify(INCIDENTS)

@app.route('/api/incidents', methods=['POST'])
def api_add_incident():
    global _next_id, _next_alert_id
    if session.get('role') != 'admin':
        return jsonify({'error':'Forbidden'}), 403
    d = request.json
    d['id']        = _next_id; _next_id += 1
    d['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M')
    INCIDENTS.append(d)
    alert = False
    if d.get('threat_index') == 'High':
        ALERTS.insert(0,{'id':_next_alert_id,'message':f"High Threat Index Detected in {d['district']}",'district':d['district'],'timestamp':d['timestamp'],'read':False})
        _next_alert_id += 1; alert = True
    return jsonify({'success':True,'alert':alert,'incident':d})

@app.route('/api/incidents/<int:iid>', methods=['PUT'])
def api_update_incident(iid):
    global _next_alert_id
    if session.get('role') != 'admin':
        return jsonify({'error':'Forbidden'}), 403
    d = request.json
    for i,inc in enumerate(INCIDENTS):
        if inc['id'] == iid:
            INCIDENTS[i].update(d); INCIDENTS[i]['id'] = iid
            alert = False
            if d.get('threat_index') == 'High':
                ALERTS.insert(0,{'id':_next_alert_id,'message':f"High Threat Index Detected in {d.get('district',inc['district'])}",'district':d.get('district',inc['district']),'timestamp':datetime.now().strftime('%Y-%m-%d %H:%M'),'read':False})
                _next_alert_id += 1; alert = True
            return jsonify({'success':True,'alert':alert})
    return jsonify({'error':'Not found'}), 404

@app.route('/api/incidents/<int:iid>', methods=['DELETE'])
def api_delete_incident(iid):
    global INCIDENTS
    if session.get('role') != 'admin':
        return jsonify({'error':'Forbidden'}), 403
    INCIDENTS = [i for i in INCIDENTS if i['id'] != iid]
    return jsonify({'success':True})

@app.route('/api/alerts')
def api_alerts():
    return jsonify(ALERTS)

@app.route('/api/alerts/read', methods=['POST'])
def api_read_alerts():
    for a in ALERTS: a['read'] = True
    return jsonify({'success':True})

@app.route('/api/victims/<district>')
def api_victims(district):
    return jsonify(VICTIM_MAP.get(district, []))

@app.route('/api/analytics')
def api_analytics():
    data = run_ml_analysis()
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
