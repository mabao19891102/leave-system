"""
药事管理组 假期管理系统 v2.0
====================
权限体系：admin=超级管理员(全部权限), approver=审批人(审批+管理), employee=普通员工, viewer=只读查看余额
功能：请假申请(年假/调休假)、加班申请、调休补假申请、审批自动化、权限管理、审批抄送
"""

import os, sqlite3, json, math, socket
from datetime import datetime, date, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, g, session, redirect, url_for, Response

app = Flask(__name__)
app.secret_key = 'hermes-leave-mgmt-v2-2026'
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'leave_system.db')

# ── Database ──────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            employee_id TEXT UNIQUE NOT NULL,
            department TEXT NOT NULL DEFAULT '药事管理组',
            leader TEXT NOT NULL DEFAULT '马文兵',
            hire_date DATE NOT NULL,
            annual_days REAL DEFAULT 0,
            used_annual REAL DEFAULT 0,
            remaining_annual REAL DEFAULT 0,
            comp_days REAL DEFAULT 0,
            used_comp REAL DEFAULT 0,
            remaining_comp REAL DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            app_type TEXT NOT NULL CHECK(app_type IN ('请假','加班','调休补假')),
            leave_type TEXT CHECK(leave_type IS NULL OR leave_type IN ('年假','调休假')),
            start_date DATE,
            end_date DATE,
            days REAL,
            overtime_date DATE,
            overtime_hours REAL,
            overtime_type TEXT,
            reason TEXT,
            status TEXT NOT NULL DEFAULT '待审批' CHECK(status IN ('待审批','已批准','已驳回','已撤销')),
            approver_comment TEXT,
            approver TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        );

        CREATE TABLE IF NOT EXISTS system_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL, detail TEXT, operator TEXT DEFAULT '系统',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_app_employee ON applications(employee_id);
        CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status);
        CREATE INDEX IF NOT EXISTS idx_app_type ON applications(app_type);
    """)
    db.commit()

# ── Auth helpers ──────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def is_admin():
    """超级管理员（马文兵）"""
    return session.get('role') == 'admin'

def is_approver():
    """可以审批的人：admin 或 approver 角色"""
    return session.get('role') in ('admin', 'approver')

def is_viewer():
    """只读查看者"""
    return session.get('role') == 'viewer'

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if not is_admin():
            return jsonify({'error': '无权限，仅超级管理员可操作'}), 403
        return f(*args, **kwargs)
    return decorated

def approver_or_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if not is_approver():
            return jsonify({'error': '无权限，仅审批人或管理员可操作'}), 403
        return f(*args, **kwargs)
    return decorated

def get_current_employee():
    db = get_db()
    emp = db.execute("SELECT * FROM employees WHERE name=?", (session.get('user', ''),)).fetchone()
    return emp

# ── Routes ────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == 'admin' and password == 'admin123':
            session['user'] = '马文兵'
            session['role'] = 'admin'
            session['emp_id'] = 4  # 马文兵 in DB
            return redirect(url_for('index'))

        db = get_db()
        emp = db.execute(
            "SELECT id, name, employee_id, role, position_status FROM employees WHERE name=? AND password=? AND is_active=1",
            (username, password)
        ).fetchone()
        if emp:
            session['user'] = emp['name']
            session['emp_id'] = emp['id']
            if emp['name'] == '马文兵':
                session['role'] = 'admin'
            else:
                session['role'] = emp['role'] or 'employee'
            return redirect(url_for('index'))
        return render_template('login.html', error='用户名或密码错误')
    return render_template('login.html')

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    """修改密码"""
    data = request.get_json()
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not new_pw or len(new_pw) < 4:
        return jsonify({'error': '新密码至少4位'}), 400
    db = get_db()
    emp = db.execute("SELECT * FROM employees WHERE name=? AND password=?", (session['user'], old_pw)).fetchone()
    if not emp:
        return jsonify({'error': '原密码错误'}), 400
    db.execute("UPDATE employees SET password=? WHERE id=?", (new_pw, emp['id']))
    db.commit()
    log_action(f"{session['user']}修改了密码")
    return jsonify({'success': True, 'message': '密码修改成功！新密码请妥善保管'})


@app.route('/api/admin/passwords')
@login_required
@admin_required
def view_passwords():
    db = get_db()
    emps = db.execute("SELECT name, employee_id, password, role FROM employees WHERE is_active=1 ORDER BY id").fetchall()
    return jsonify([dict(e) for e in emps])


@app.route('/api/admin/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_password():
    data = request.get_json()
    eid = data.get('employee_id', '')
    name = data.get('name', '')
    db = get_db()
    emp = db.execute("SELECT id FROM employees WHERE employee_id=? AND name=?", (str(eid), name)).fetchone()
    if not emp:
        return jsonify({'error': '员工不存在'}), 404
    db.execute("UPDATE employees SET password=? WHERE id=?", (str(eid), emp['id']))
    db.commit()
    log_action(f"管理员重置了{name}的密码")
    return jsonify({'success': True, 'message': f'{name}的密码已重置为{eid}'})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── Dashboard ─────────────────────────────────────────────────────────────

@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats():
    """仪表盘统计数据"""
    db = get_db()
    from datetime import date
    today = date.today()

    # Education distribution
    edu_dist = db.execute("""
        SELECT COALESCE(NULLIF(education,''), '未设置') as label, COUNT(*) as count
        FROM employees WHERE is_active=1 GROUP BY education ORDER BY count DESC
    """).fetchall()

    # Years of service distribution (using hire_date)
    emps = db.execute("SELECT hire_date FROM employees WHERE is_active=1").fetchall()
    service_buckets = {'1年以下': 0, '1-3年': 0, '3-5年': 0, '5-10年': 0, '10年以上': 0}
    for e in emps:
        try:
            years = (today - date.fromisoformat(e['hire_date'])).days / 365.25
        except:
            continue
        if years < 1: service_buckets['1年以下'] += 1
        elif years < 3: service_buckets['1-3年'] += 1
        elif years < 5: service_buckets['3-5年'] += 1
        elif years < 10: service_buckets['5-10年'] += 1
        else: service_buckets['10年以上'] += 1

    # Join month distribution
    join_dist = db.execute("""
        SELECT SUBSTR(join_group_date,1,7) as month, COUNT(*) as count
        FROM employees WHERE is_active=1 AND join_group_date != ''
        GROUP BY month ORDER BY month
    """).fetchall()

    # Leave type statistics
    leave_stats = db.execute("""
        SELECT leave_type, COUNT(*) as count, SUM(days) as total_days
        FROM applications WHERE status='已批准' AND app_type='请假'
        GROUP BY leave_type
    """).fetchall()

    return jsonify({
        'edu': [dict(r) for r in edu_dist],
        'service': [{'label': k, 'count': v} for k, v in service_buckets.items()],
        'join': [dict(r) for r in join_dist],
        'leave_stats': [dict(r) for r in leave_stats],
    })


@app.route('/')
@login_required
def index():
    db = get_db()
    user = session['user']
    emp = get_current_employee()

    if is_admin() or is_approver():
        # Admin/approver - see all stats
        stats = {
            'emp_count': db.execute("SELECT COUNT(*) FROM employees WHERE is_active=1").fetchone()[0],
            'pending_count': db.execute("SELECT COUNT(*) FROM applications WHERE status='待审批'").fetchone()[0],
            'approved_count': db.execute("SELECT COUNT(*) FROM applications WHERE status='已批准'").fetchone()[0],
            'total_overtime': db.execute("SELECT COALESCE(SUM(overtime_hours),0) FROM applications WHERE app_type='加班' AND status='已批准'").fetchone()[0],
        }
        recent_apps = db.execute("""
            SELECT a.*, e.name as emp_name
            FROM applications a JOIN employees e ON a.employee_id = e.id
            ORDER BY a.created_at DESC LIMIT 10
        """).fetchall()
        pending_apps = db.execute("""
            SELECT a.*, e.name as emp_name
            FROM applications a JOIN employees e ON a.employee_id = e.id
            WHERE a.status='待审批' ORDER BY a.created_at DESC LIMIT 10
        """).fetchall()
    else:
        # Regular employee - see only their own
        stats = {
            'emp_count': 1,
            'pending_count': db.execute("SELECT COUNT(*) FROM applications WHERE employee_id=? AND status='待审批'", (emp['id'],)).fetchone()[0],
            'approved_count': db.execute("SELECT COUNT(*) FROM applications WHERE employee_id=? AND status='已批准'", (emp['id'],)).fetchone()[0],
            'total_overtime': db.execute("SELECT COALESCE(SUM(overtime_hours),0) FROM applications WHERE employee_id=? AND app_type='加班' AND status='已批准'", (emp['id'],)).fetchone()[0],
        }
        recent_apps = db.execute("""
            SELECT a.*, e.name as emp_name
            FROM applications a JOIN employees e ON a.employee_id = e.id
            WHERE a.employee_id=? ORDER BY a.created_at DESC LIMIT 10
        """, (emp['id'],)).fetchall()
        pending_apps = []

    # Today's on-leave (admin sees all, employee sees only own team - which is the same here)
    today = date.today().isoformat()
    on_leave = db.execute("""
        SELECT e.name, a.leave_type, a.start_date, a.end_date
        FROM applications a JOIN employees e ON a.employee_id = e.id
        WHERE a.status='已批准' AND a.app_type='请假' AND ? BETWEEN substr(a.start_date,1,10) AND substr(a.end_date,1,10)
    """, (today,)).fetchall()

    return render_template('index.html', stats=stats, recent_apps=recent_apps,
                         pending_apps=pending_apps, on_leave=on_leave,
                         is_admin=is_admin(), user=user, emp=emp,
                         role=session.get('role'))

# ── Employee APIs ─────────────────────────────────────────────────────────

@app.route('/api/employees')
@login_required
def get_employees():
    db = get_db()
    show_deleted = request.args.get('show_deleted', '')
    active_filter = "" if show_deleted else "WHERE e.is_active=1"

    if is_admin():
        employees = db.execute(f"""
            SELECT e.*,
                   COALESCE((SELECT SUM(days) FROM applications WHERE employee_id=e.id AND app_type='加班' AND status='已批准'), 0) as overtime_earned
            FROM employees e {active_filter}
            ORDER BY e.id
        """).fetchall()
    else:
        emp = get_current_employee()
        employees = db.execute(f"""
            SELECT e.*,
                   COALESCE((SELECT SUM(days) FROM applications WHERE employee_id=e.id AND app_type='加班' AND status='已批准'), 0) as overtime_earned
            FROM employees e WHERE e.id=?
        """, (emp['id'],)).fetchall()

    # Add display fields: convert annual_days to 天数(半天粒度) + 小时(余数)
    result = []
    for e in employees:
        d = dict(e)
        total_hours = (d.get('annual_days') or 0) * 8
        d['annual_days_display'] = int(total_hours / 4) / 2
        d['annual_hours_display'] = total_hours - (d['annual_days_display'] * 8)

        # Same for overtime
        ot_hours = (d.get('overtime_earned') or 0) * 8
        d['overtime_days_display'] = int(ot_hours / 4) / 2
        d['overtime_hours_display'] = ot_hours - (d['overtime_days_display'] * 8)

        result.append(d)

    return jsonify(result)

@app.route('/api/employees/<int:eid>')
@login_required
def get_employee(eid):
    db = get_db()
    if not is_admin():
        emp = get_current_employee()
        if emp['id'] != eid:
            return jsonify({'error': '无权限'}), 403
    emp = db.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if not emp:
        return jsonify({'error': '员工不存在'}), 404
    return jsonify(dict(emp))

@app.route('/api/employees/<int:eid>/applications')
@login_required
def get_employee_applications(eid):
    db = get_db()
    if not is_admin():
        emp = get_current_employee()
        if emp['id'] != eid:
            return jsonify({'error': '无权限'}), 403
    apps = db.execute("""
        SELECT * FROM applications WHERE employee_id=?
        ORDER BY created_at DESC
    """, (eid,)).fetchall()
    return jsonify([dict(a) for a in apps])

@app.route('/api/employees/my-info')
@login_required
def get_my_info():
    emp = get_current_employee()
    if not emp:
        return jsonify({'error': '未找到员工信息'}), 404
    return jsonify(dict(emp))

# ── Applications (Unified: 请假/加班/调休补假) ────────────────────────────

@app.route('/api/applications')
@login_required
def get_applications():
    db = get_db()
    status_filter = request.args.get('status', '')
    app_type_filter = request.args.get('app_type', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    export_all = request.args.get('export', '')  # '1' = return all without pagination

    query = """
        SELECT a.*, e.name as emp_name, e.employee_id as emp_code
        FROM applications a JOIN employees e ON a.employee_id = e.id
        WHERE 1=1
    """
    params = []

    if not is_admin() and not is_viewer():
        emp = get_current_employee()
        query += " AND a.employee_id=?"
        params.append(emp['id'])

    if status_filter:
        query += " AND a.status=?"
        params.append(status_filter)
    if app_type_filter:
        query += " AND a.app_type=?"
        params.append(app_type_filter)
    if date_from:
        query += " AND a.created_at >= ?"
        params.append(date_from + ' 00:00:00')
    if date_to:
        query += " AND a.created_at <= ?"
        params.append(date_to + ' 23:59:59')
    # Employee name filter (admin only)
    emp_name_filter = request.args.get('emp_name', '').strip()
    if emp_name_filter and is_admin():
        query += " AND e.name LIKE ?"
        params.append(f'%{emp_name_filter}%')
    query += " ORDER BY a.created_at DESC"

    apps = db.execute(query, params).fetchall()
    return jsonify([dict(a) for a in apps])

@app.route('/api/applications/pending-count')
@login_required
def get_pending_count():
    db = get_db()
    if is_admin():
        count = db.execute("SELECT COUNT(*) FROM applications WHERE status='待审批'").fetchone()[0]
    else:
        count = 0
    return jsonify({'count': count})

@app.route('/api/applications/create', methods=['POST'])
@login_required
def create_application():
    data = request.get_json()
    db = get_db()
    emp = get_current_employee()

    app_type = data.get('app_type')  # 请假/加班/调休补假

    if app_type == '请假':
        return create_leave_application(db, emp, data)
    elif app_type == '加班':
        return create_overtime_application(db, emp, data)
    elif app_type == '调休补假':
        return create_comp_leave_application(db, emp, data)
    else:
        return jsonify({'error': '未知申请类型'}), 400


def create_leave_application(db, emp, data):
    """请假申请：年假/调休假，支持时间"""
    leave_type = data.get('leave_type')
    start_date = data.get('start_date')
    start_time = data.get('start_time', '')
    end_date = data.get('end_date')
    end_time = data.get('end_time', '')
    days = float(data.get('days', 0))
    reason = data.get('reason', '')

    if leave_type not in ('年假', '调休假'):
        return jsonify({'error': '请假类型仅支持年假和调休假'}), 400
    if not start_date or not end_date or days <= 0:
        return jsonify({'error': '请填写完整的请假信息'}), 400

    # Append time to dates for storage
    start_dt = f"{start_date} {start_time}" if start_time else start_date
    end_dt = f"{end_date} {end_time}" if end_time else end_date

    # Balance check
    if leave_type == '年假' and days > (emp['remaining_annual'] or 0):
        return jsonify({'error': f'年假余额不足！剩余{emp["remaining_annual"]:.1f}天，申请{days}天'}), 400
    if leave_type == '调休假' and days > (emp['remaining_comp'] or 0):
        return jsonify({'error': f'调休假余额不足！剩余{emp["remaining_comp"]:.1f}天，申请{days}天'}), 400

    # Overlap check (use date-only part for comparison)
    ol_start = start_date
    ol_end = end_date
    overlap = db.execute("""
        SELECT COUNT(*) FROM applications
        WHERE employee_id=? AND status IN ('待审批','已批准') AND app_type='请假'
        AND ? <= substr(end_date,1,10) AND ? >= substr(start_date,1,10)
    """, (emp['id'], ol_start, ol_end)).fetchone()[0]
    if overlap > 0:
        return jsonify({'error': '该时间段已有请假申请，请勿重复提交'}), 400

    db.execute("""
        INSERT INTO applications (employee_id, app_type, leave_type, start_date, end_date, days, reason)
        VALUES (?, '请假', ?, ?, ?, ?, ?)
    """, (emp['id'], leave_type, start_dt, end_dt, days, reason))
    db.commit()
    log_action(f"{emp['name']} 提交{leave_type}申请{days}天")
    return jsonify({'success': True, 'message': f'{leave_type}申请已提交，等待马文兵审批'})


def create_overtime_application(db, emp, data):
    """加班申请：支持起始/结束时间"""
    start_date = data.get('start_date')
    start_time = data.get('start_time', '')
    end_date = data.get('end_date')
    end_time = data.get('end_time', '')
    hours = float(data.get('overtime_hours', 0))
    overtime_type = data.get('overtime_type', '休息日加班')
    reason = data.get('reason', '')

    if not start_date:
        return jsonify({'error': '请填写加班开始日期'}), 400
    if hours <= 0:
        return jsonify({'error': '请填写加班时长'}), 400

    # Auto-calculate hours from time range if provided
    if start_date == end_date and start_time and end_time:
        try:
            fmt = '%H:%M'
            from datetime import datetime as dt
            t1 = dt.strptime(start_time, fmt)
            t2 = dt.strptime(end_time, fmt)
            auto_hours = (t2 - t1).seconds / 3600
            if auto_hours > 0:
                hours = round(auto_hours, 1)
        except:
            pass  # fallback to manual hours input

    # Calculate comp days
    rate = 1.5 if overtime_type == '法定假日加班' else 1.0
    comp_days = round(hours * rate / 8, 1)

    db.execute("""
        INSERT INTO applications (employee_id, app_type, overtime_date, overtime_hours, overtime_type, days, reason, start_date, end_date)
        VALUES (?, '加班', ?, ?, ?, ?, ?, ?, ?)
    """, (emp['id'], start_date, hours, overtime_type, comp_days, reason, start_date or end_date, end_date or start_date))
    db.commit()
    log_action(f"{emp['name']} 提交加班申请{hours}小时({overtime_type})")
    return jsonify({'success': True, 'message': f'加班申请已提交，审批通过后将获得{comp_days}天调休假'})


def create_comp_leave_application(db, emp, data):
    """调休补假申请：使用调休余额来请假，支持时间"""
    start_date = data.get('start_date')
    start_time = data.get('start_time', '')
    end_date = data.get('end_date')
    end_time = data.get('end_time', '')
    days = float(data.get('days', 0))
    reason = data.get('reason', '')

    if not start_date or not end_date or days <= 0:
        return jsonify({'error': '请填写完整的调休补假信息'}), 400
    if days > (emp['remaining_comp'] or 0):
        return jsonify({'error': f'调休余额不足！剩余{emp["remaining_comp"]:.1f}天，申请{days}天'}), 400

    # Append time to dates for storage
    start_dt = f"{start_date} {start_time}" if start_time else start_date
    end_dt = f"{end_date} {end_time}" if end_time else end_date

    # Overlap check (date-only part)
    overlap = db.execute("""
        SELECT COUNT(*) FROM applications
        WHERE employee_id=? AND status IN ('待审批','已批准') AND app_type='调休补假'
        AND ? <= substr(end_date,1,10) AND ? >= substr(start_date,1,10)
    """, (emp['id'], start_date, end_date)).fetchone()[0]
    if overlap > 0:
        return jsonify({'error': '该时间段已有调休补假申请'}), 400

    db.execute("""
        INSERT INTO applications (employee_id, app_type, leave_type, start_date, end_date, days, reason)
        VALUES (?, '调休补假', '调休假', ?, ?, ?, ?)
    """, (emp['id'], start_dt, end_dt, days, reason))
    db.commit()
    log_action(f"{emp['name']} 提交调休补假申请{days}天")
    return jsonify({'success': True, 'message': '调休补假申请已提交，等待马文兵审批'})


# ── Approval ──────────────────────────────────────────────────────────────

@app.route('/api/applications/approve', methods=['POST'])
@login_required
def approve_application():
    if not is_admin():
        return jsonify({'error': '仅部门负责人马文兵可审批'}), 403

    data = request.get_json()
    app_id = data.get('application_id')
    action = data.get('action')  # approve / reject
    comment = data.get('comment', '')

    db = get_db()
    app = db.execute("""
        SELECT a.*, e.name as emp_name FROM applications a
        JOIN employees e ON a.employee_id = e.id WHERE a.id=?
    """, (app_id,)).fetchone()

    if not app:
        return jsonify({'error': '申请不存在'}), 404
    if app['status'] != '待审批':
        return jsonify({'error': '该申请已被处理'}), 400

    if action == 'approve':
        new_status = '已批准'
        # 获取抄送人设置
        cc_setting = db.execute("SELECT value FROM system_settings WHERE key='cc_viewer'").fetchone()
        cc_id = cc_setting['value'] if cc_setting else ''
        # 更新申请
        db.execute("""
            UPDATE applications SET status=?, approver_comment=?, approver=?,
                     cc_to=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
        """, (new_status, comment, session.get('user','马文兵'), cc_id, app_id))
        db.commit()
        err = apply_balance_update(db, app)
        if err:
            return jsonify({'error': err}), 400
    else:
        new_status = '已驳回'
        db.execute("""
            UPDATE applications SET status=?, approver_comment=?, approver=?,
                     updated_at=CURRENT_TIMESTAMP WHERE id=?
        """, (new_status, comment, session.get('user','马文兵'), app_id))
        db.commit()

    log_action(f"马文兵{'批准' if action=='approve' else '驳回'} {app['app_type']}#{app_id}: {comment}")
    return jsonify({'success': True, 'message': f'申请已{new_status}'})


def apply_balance_update(db, app):
    """根据审批通过的申请类型，更新员工假期余额"""
    emp_id = app['employee_id']
    emp = db.execute("SELECT * FROM employees WHERE id=?", (emp_id,)).fetchone()

    if app['app_type'] == '请假':
        if app['leave_type'] == '年假':
            new_used = (emp['used_annual'] or 0) + app['days']
            new_remaining = (emp['annual_days'] or 0) - new_used
            if new_remaining < 0:
                return f'年假余额不足！已使用{emp["used_annual"]}天，申请{app["days"]}天，总额度{emp["annual_days"]}天'
            db.execute("UPDATE employees SET used_annual=?, remaining_annual=? WHERE id=?",
                      (new_used, new_remaining, emp_id))
        elif app['leave_type'] == '调休假':
            new_used = (emp['used_comp'] or 0) + app['days']
            new_remaining = (emp['comp_days'] or 0) - new_used
            if new_remaining < 0:
                return f'调休假余额不足！'
            db.execute("UPDATE employees SET used_comp=?, remaining_comp=? WHERE id=?",
                      (new_used, new_remaining, emp_id))

    elif app['app_type'] == '加班':
        # 加班审批通过 → 增加调休额度 + 同步更新年假总额
        comp_earned = app['days'] or 0
        new_comp = (emp['comp_days'] or 0) + comp_earned
        new_remaining = new_comp - (emp['used_comp'] or 0)
        db.execute("UPDATE employees SET comp_days=?, remaining_comp=? WHERE id=?",
                  (new_comp, new_remaining, emp_id))

        # 同步重新计算年假总额 = 寒假 + 暑假 + 所有已批准加班
        ot_total = db.execute("""
            SELECT COALESCE(SUM(days), 0) FROM applications
            WHERE employee_id=? AND app_type='加班' AND status='已批准'
        """, (emp_id,)).fetchone()[0]
        winter = emp['winter_vacation'] or 0
        summer = emp['summer_vacation'] or 0
        new_annual = winter + summer + (ot_total or 0)
        new_rem = new_annual - (emp['used_annual'] or 0)
        db.execute("UPDATE employees SET annual_days=?, remaining_annual=? WHERE id=?",
                  (new_annual, max(new_rem, 0), emp_id))

    elif app['app_type'] == '调休补假':
        # 调休补假 = 使用调休余额
        new_used = (emp['used_comp'] or 0) + app['days']
        new_remaining = (emp['comp_days'] or 0) - new_used
        if new_remaining < 0:
            return f'调休假余额不足！'
        db.execute("UPDATE employees SET used_comp=?, remaining_comp=? WHERE id=?",
                  (new_used, new_remaining, emp_id))

    return None

# ── Admin: Balance Management ─────────────────────────────────────────────

@app.route('/api/admin/init-annual', methods=['POST'])
@login_required
@admin_required
def init_annual_leave():
    from datetime import date, datetime
    db = get_db()
    employees = db.execute("SELECT * FROM employees WHERE is_active=1").fetchall()
    today = date.today()
    count = 0

    for emp in employees:
        try:
            hire_date = datetime.strptime(emp['hire_date'], '%Y-%m-%d').date()
        except:
            continue
        years = (today - hire_date).days / 365.25

        if years < 1:
            months = (today.year - hire_date.year) * 12 + (today.month - hire_date.month)
            annual = round(min(max(months, 0) / 2.4, 5), 1)
        elif years < 10:
            annual = 5.0
        elif years < 20:
            annual = 10.0
        else:
            annual = 15.0

        remaining = annual - (emp['used_annual'] or 0)
        db.execute("UPDATE employees SET annual_days=?, remaining_annual=? WHERE id=?",
                  (annual, max(remaining, 0), emp['id']))
        count += 1

    db.commit()
    return jsonify({'success': True, 'message': f'已为{count}名员工初始化年假额度'})


@app.route('/api/admin/add-employee', methods=['POST'])
@login_required
@admin_required
def add_employee():
    """添加新员工"""
    data = request.get_json()
    name = data.get('name', '').strip()
    emp_id = data.get('employee_id', '').strip()
    hire_date = data.get('hire_date', '').strip()
    join_date = data.get('join_group_date', '').strip() or hire_date
    position = data.get('position_status', '在岗')

    if not name or not emp_id or not hire_date:
        return jsonify({'error': '请填写姓名、职工编号和入职日期'}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM employees WHERE employee_id=?", (emp_id,)).fetchone()
    if existing:
        return jsonify({'error': f'职工编号 {emp_id} 已存在'}), 400

    db.execute("""
        INSERT INTO employees (name, employee_id, department, leader, hire_date, join_group_date, position_status, annual_days, remaining_annual)
        VALUES (?, ?, '药事管理组', '马文兵', ?, ?, ?, 0, 0)
    """, (name, emp_id, hire_date, join_date, position))
    db.commit()

    log_action(f"马文兵添加员工: {name}({emp_id})")
    return jsonify({'success': True, 'message': f'已添加员工 {name}'})


@app.route('/api/admin/update-balance', methods=['POST'])
@login_required
@admin_required
def update_balance():
    data = request.get_json()
    eid = data.get('employee_id')
    db = get_db()
    emp = db.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
    if not emp:
        return jsonify({'error': '员工不存在'}), 404

    winter = float(data.get('winter_vacation', emp['winter_vacation'] or 0))
    summer = float(data.get('summer_vacation', emp['summer_vacation'] or 0))
    comp = float(data.get('comp_days', emp['comp_days'] or 0))
    position = data.get('position_status', emp['position_status'] or '在岗')
    join_date = data.get('join_group_date', emp['join_group_date'] or '')
    education = data.get('education', emp['education'] or '')
    new_hire = data.get('hire_date', '')

    # Auto-calculate overtime earned from approved overtime
    ot_earned = db.execute("""
        SELECT COALESCE(SUM(days), 0) FROM applications
        WHERE employee_id=? AND app_type='加班' AND status='已批准'
    """, (eid,)).fetchone()[0]

    # annual_days: use manual value if provided, otherwise auto = winter + summer + overtime
    if 'annual_days' in data:
        annual = float(data['annual_days'])
        source = f"手动设置"
    else:
        annual = winter + summer + (ot_earned or 0)
        source = f"寒假{winter}+暑假{summer}+加班{ot_earned}"

    if new_hire:
        db.execute("UPDATE employees SET hire_date=? WHERE id=?", (new_hire, eid))

    db.execute("""
        UPDATE employees SET winter_vacation=?, summer_vacation=?,
                             annual_days=?, remaining_annual=? - used_annual,
                             comp_days=?, remaining_comp=? - used_comp,
                             position_status=?, join_group_date=?, education=?
        WHERE id=?
    """, (winter, summer, annual, annual, comp, comp, position, join_date, education, eid))
    db.commit()
    log_action(f"马文兵更新员工{eid}: 寒假{winter}天, 暑假{summer}天, 年假总额{annual}天({source}), 调休{comp}天")
    return jsonify({'success': True, 'message': f'已更新，年假总额={annual}天（{source}）'})


@app.route('/api/admin/recalculate', methods=['POST'])
@login_required
@admin_required
def recalculate_all():
    """重新计算所有员工的年假总额 = 寒假 + 暑假 + 加班天数"""
    db = get_db()
    employees = db.execute("SELECT * FROM employees WHERE is_active=1").fetchall()
    count = 0

    for emp in employees:
        winter = emp['winter_vacation'] or 0
        summer = emp['summer_vacation'] or 0
        ot_earned = db.execute("""
            SELECT COALESCE(SUM(days), 0) FROM applications
            WHERE employee_id=? AND app_type='加班' AND status='已批准'
        """, (emp['id'],)).fetchone()[0] or 0
        annual = winter + summer + ot_earned
        remaining = annual - (emp['used_annual'] or 0)
        db.execute("UPDATE employees SET annual_days=?, remaining_annual=? WHERE id=?",
                  (annual, max(remaining, 0), emp['id']))
        count += 1

    db.commit()
    log_action(f"马文兵重新计算{count}名员工的年假")
    return jsonify({'success': True, 'message': f'已重新计算{count}名员工年假（年假=寒假+暑假+加班天数）'})


@app.route('/api/admin/quick-update-status', methods=['POST'])
@login_required
@admin_required
def quick_update_status():
    """快速更新岗位状态（表格内下拉直接修改）"""
    data = request.get_json()
    eid = data.get('employee_id')
    status = data.get('position_status', '在岗')
    db = get_db()
    db.execute("UPDATE employees SET position_status=? WHERE id=?", (status, eid))
    db.commit()
    return jsonify({'success': True})


# ── Role Management ────────────────────────────────────────────────────────

@app.route('/api/admin/roles', methods=['GET'])
@login_required
@admin_required
def get_roles():
    """获取所有员工的角色信息"""
    db = get_db()
    emps = db.execute("SELECT id, name, employee_id, role, position_status, education FROM employees WHERE is_active=1 ORDER BY id").fetchall()
    return jsonify([dict(e) for e in emps])


@app.route('/api/admin/update-role', methods=['POST'])
@login_required
@admin_required
def update_role():
    """更新员工角色"""
    data = request.get_json()
    emp_id = data.get('employee_id')
    new_role = data.get('role')
    if new_role not in ('employee', 'approver', 'viewer'):
        return jsonify({'error': '无效的角色'}), 400
    db = get_db()
    emp = db.execute("SELECT name FROM employees WHERE id=?", (emp_id,)).fetchone()
    if not emp:
        return jsonify({'error': '员工不存在'}), 404
    if emp['name'] == '马文兵':
        return jsonify({'error': '不能修改超级管理员的角色'}), 400
    db.execute("UPDATE employees SET role=? WHERE id=?", (new_role, emp_id))
    db.commit()
    log_action(f"管理员更新员工{emp['name']}角色为{new_role}")
    return jsonify({'success': True, 'message': f'已更新{emp["name"]}为{new_role}'})


@app.route('/api/admin/set-cc', methods=['POST'])
@login_required
@admin_required
def set_cc():
    """设置审批抄送人"""
    data = request.get_json()
    viewer_id = data.get('viewer_id', '')
    db = get_db()
    # Save to settings
    db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('cc_viewer', ?)", (str(viewer_id),))
    db.commit()
    return jsonify({'success': True, 'message': '抄送人已设置'})


@app.route('/api/admin/get-cc', methods=['GET'])
@login_required
def get_cc():
    """获取抄送人设置"""
    db = get_db()
    cc = db.execute("SELECT value FROM system_settings WHERE key='cc_viewer'").fetchone()
    viewer_id = cc['value'] if cc else ''
    viewer = None
    if viewer_id:
        v = db.execute("SELECT id, name FROM employees WHERE id=?", (viewer_id,)).fetchone()
        if v:
            viewer = dict(v)
    return jsonify({'viewer': viewer})


# ── Viewer (Read-only balance) ─────────────────────────────────────────────

@app.route('/balance-view')
@login_required
def balance_view():
    """余额查看页面（仅viewer角色可看）"""
    if not is_viewer() and not is_admin():
        return redirect(url_for('index'))
    return render_template('balance_view.html')

@app.route('/api/balance-data')
@login_required
def balance_data():
    """返回余额数据（给viewer使用）"""
    db = get_db()
    emps = db.execute("""
        SELECT name, employee_id, education, position_status,
               annual_days, used_annual, remaining_annual,
               comp_days, used_comp, remaining_comp
        FROM employees WHERE is_active=1 ORDER BY id
    """).fetchall()
    result = []
    for e in emps:
        d = dict(e)
        ra = d['remaining_annual'] or 0
        rc = d['remaining_comp'] or 0
        d['annual_days_display'] = math.floor(ra * 8 / 4) / 2
        d['annual_hours_display'] = round(ra * 8 - (d['annual_days_display'] * 8))
        d['comp_days_display'] = math.floor(rc * 8 / 4) / 2
        d['comp_hours_display'] = round(rc * 8 - (d['comp_days_display'] * 8))
        result.append(d)
    return jsonify(result)


@app.route('/api/admin/delete-employee', methods=['POST'])
@login_required
@admin_required
def delete_employee():
    """删除员工"""
    data = request.get_json()
    eid = data.get('employee_id')
    db = get_db()
    emp = db.execute("SELECT name FROM employees WHERE id=?", (eid,)).fetchone()
    if not emp:
        return jsonify({'error': '员工不存在'}), 404
    db.execute("UPDATE employees SET is_active=0 WHERE id=?", (eid,))
    db.commit()
    log_action(f"马文兵删除员工: {emp['name']}(ID:{eid})")
    return jsonify({'success': True, 'message': f'已删除员工 {emp["name"]}'})

@app.route('/api/admin/restore-employee', methods=['POST'])
@login_required
@admin_required
def restore_employee():
    """恢复已删除员工"""
    data = request.get_json()
    eid = data.get('employee_id')
    db = get_db()
    emp = db.execute("SELECT name FROM employees WHERE id=?", (eid,)).fetchone()
    if not emp:
        return jsonify({'error': '员工不存在'}), 404
    db.execute("UPDATE employees SET is_active=1 WHERE id=?", (eid,))
    db.commit()
    log_action(f"马文兵恢复员工: {emp['name']}(ID:{eid})")
    return jsonify({'success': True, 'message': f'已恢复员工 {emp["name"]}'})


# ── Monthly Report ────────────────────────────────────────────────────────

@app.route('/api/reports/monthly')
@login_required
def monthly_report():
    """月度汇总报表：在岗天数、公休、余假等"""
    db = get_db()
    year_month = request.args.get('month', '')
    emp_name_filter = request.args.get('emp_name', '')

    from calendar import monthrange
    from datetime import date

    # Default to current month
    if not year_month:
        today = date.today()
        year_month = today.strftime('%Y-%m')

    try:
        year, month = map(int, year_month.split('-'))
    except:
        return jsonify({'error': '月份格式错误'}), 400

    # Get all active employees
    query = "SELECT * FROM employees WHERE is_active=1"
    params = []
    if emp_name_filter and (is_admin() or is_viewer()):
        query += " AND name LIKE ?"
        params.append(f'%{emp_name_filter}%')
    elif not is_admin() and not is_viewer():
        emp = get_current_employee()
        query += " AND id=?"
        params.append(emp['id'])

    employees = db.execute(query, params).fetchall()
    if not employees:
        return jsonify({'error': '无员工数据'}), 404

    # Month boundaries
    first_day = date(year, month, 1)
    last_day_num = monthrange(year, month)[1]
    last_day = date(year, month, last_day_num)
    prev_month = last_day_num if month == 1 else month - 1
    prev_year = year - 1 if month == 1 else year
    prev_last_day_num = monthrange(prev_year, prev_month)[1]
    prev_month_end = date(prev_year, prev_month, prev_last_day_num)

    month_str = f"{year:04d}-{month:02d}"
    prev_month_str = f"{prev_year:04d}-{prev_month:02d}"

    # Calculate working days (公休 = weekends)
    total_days = last_day_num
    weekend_days = 0
    for d in range(1, last_day_num + 1):
        wd = date(year, month, d).weekday()
        if wd >= 5:  # Saturday=5, Sunday=6
            weekend_days += 1
    work_days = total_days - weekend_days

    result = []

    for emp in employees:
        # Current balance
        curr_annual_remain = emp['remaining_annual'] or 0
        curr_comp_remain = emp['remaining_comp'] or 0

        # Get approved leaves in this month
        annual_taken = db.execute("""
            SELECT COALESCE(SUM(days), 0) FROM applications
            WHERE employee_id=? AND app_type='请假' AND leave_type='年假'
            AND status='已批准' AND start_date LIKE ?
        """, (emp['id'], f'{month_str}%')).fetchone()[0]

        comp_taken = db.execute("""
            SELECT COALESCE(SUM(days), 0) FROM applications
            WHERE employee_id=? AND app_type='请假' AND leave_type='调休假'
            AND status='已批准' AND start_date LIKE ?
        """, (emp['id'], f'{month_str}%')).fetchone()[0]

        comp_leave_taken = db.execute("""
            SELECT COALESCE(SUM(days), 0) FROM applications
            WHERE employee_id=? AND app_type='调休补假'
            AND status='已批准' AND start_date LIKE ?
        """, (emp['id'], f'{month_str}%')).fetchone()[0]

        # Previous month end balance = current + this month's usage
        prev_annual_remain = curr_annual_remain + annual_taken
        prev_comp_remain = curr_comp_remain + comp_taken + comp_leave_taken

        # Total personal leave taken this month
        total_personal_leave = annual_taken + comp_taken + comp_leave_taken

        result.append({
            'name': emp['name'],
            'employee_id': emp['employee_id'],
            'month': month_str,
            'work_days': work_days,
            'weekend_days': weekend_days,
            'prev_annual': round(prev_annual_remain, 1),
            'prev_comp': round(prev_comp_remain, 1),
            'annual_taken': round(annual_taken, 1),
            'comp_taken': round(comp_taken, 1),
            'comp_leave_taken': round(comp_leave_taken, 1),
            'total_leave_taken': round(total_personal_leave, 1),
            'curr_annual': round(curr_annual_remain, 1),
            'curr_comp': round(curr_comp_remain, 1),
        })

    return jsonify(result)


# ── Detail Reports API ─────────────────────────────────────────────────────

@app.route('/api/reports/details')
@login_required
def report_details():
    """返回明细数据：加班/调休/请假"""
    db = get_db()
    rtype = request.args.get('type', 'overtime')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    emp_name = request.args.get('emp_name', '')

    app_type_map = {'overtime': '加班', 'comp': '调休补假', 'leave': '请假'}
    app_type = app_type_map.get(rtype)

    query = """
        SELECT a.*, e.name as emp_name
        FROM applications a JOIN employees e ON a.employee_id = e.id
        WHERE a.app_type=?"""
    params = [app_type]

    if date_from:
        query += " AND a.created_at >= ?"
        params.append(date_from + ' 00:00:00')
    if date_to:
        query += " AND a.created_at <= ?"
        params.append(date_to + ' 23:59:59')
    if emp_name:
        query += " AND e.name=?"
        params.append(emp_name)

    query += " ORDER BY a.created_at DESC"
    apps = db.execute(query, params).fetchall()

    import calendar
    weekdays = ['周一','周二','周三','周四','周五','周六','周日']

    result = []
    for a in apps:
        d = dict(a)
        d['weekday'] = ''
        sd = (a['start_date'] or '')[:10]
        if sd:
            try:
                from datetime import datetime
                dt = datetime.strptime(sd, '%Y-%m-%d')
                d['weekday'] = weekdays[dt.weekday()]
            except:
                pass
        d['start_time'] = (a['start_date'] or '')[11:16]
        d['end_time'] = (a['end_date'] or '')[11:16]
        d['start_date_only'] = sd
        result.append(d)

    return jsonify(result)


# ── Daily Attendance Export ────────────────────────────────────────────────

@app.route('/api/reports/daily-attendance')
@login_required
def daily_attendance_export():
    """按日考勤表：序号/工资号/姓名/组别 + 每日休假标记 + 汇总"""
    try:
        from calendar import monthrange
        from datetime import date, datetime, timedelta
        import io, urllib.parse

        db = get_db()
        year_month = request.args.get('month', '')

        if not year_month:
            today = date.today()
            year_month = today.strftime('%Y-%m')

        try:
            year, month = map(int, year_month.split('-'))
        except:
            return jsonify({'error': '月份格式错误'}), 400

        last_day_num = monthrange(year, month)[1]
        month_str = f"{year:04d}-{month:02d}"

        employees = db.execute("SELECT * FROM employees WHERE is_active=1 ORDER BY id").fetchall()

        # Filter by employee if specified
        emp_filter = request.args.get('emp_name', '')
        if emp_filter:
            employees = [e for e in employees if e['name'] == emp_filter]

        leaves = db.execute("""
            SELECT a.* FROM applications a
            WHERE a.status='已批准' AND a.start_date LIKE ?
            AND a.app_type IN ('请假','调休补假')
            ORDER BY a.employee_id, a.start_date
        """, (f'{month_str}%',)).fetchall()

        overlapping = db.execute("""
            SELECT a.* FROM applications a
            WHERE a.status='已批准' AND a.start_date < ? AND a.end_date >= ?
            AND a.app_type IN ('请假','调休补假')
            ORDER BY a.employee_id, a.start_date
        """, (f'{month_str}-01', f'{month_str}-01')).fetchall()

        all_leaves = list(leaves) + list(overlapping)
        daily_map = {}

        for lv in all_leaves:
            eid = lv['employee_id']
            start_str = (lv['start_date'] or '')[:10]
            end_str = (lv['end_date'] or '')[:10]

            try:
                sdt = datetime.strptime(start_str, '%Y-%m-%d').date()
                edt = datetime.strptime(end_str, '%Y-%m-%d').date()
            except:
                continue

            if lv['app_type'] == '请假':
                display_type = '年' if lv['leave_type'] == '年假' else '调'
            elif lv['app_type'] == '调休补假':
                display_type = '补'
            else:
                continue

            total_days = lv['days'] or 0
            current = max(sdt, date(year, month, 1))
            end_bound = min(edt, date(year, month, last_day_num))

            if current > end_bound:
                continue

            span_days = (edt - sdt).days + 1
            remaining = total_days

            while current <= end_bound and remaining > 0:
                day_num = current.day
                day_val = remaining if span_days <= 1 else min(1.0, remaining)
                day_val = min(day_val, remaining)
                is_half = day_val <= 0.5
                if eid not in daily_map:
                    daily_map[eid] = {}
                daily_map[eid][day_num] = {'type': display_type, 'half': is_half}
                remaining -= day_val
                current += timedelta(days=1)

        output = io.StringIO()
        output.write('\uFEFF')

        row1 = ['序号', '工资号', '姓名', '组别']
        for d in range(1, last_day_num + 1):
            row1.append(str(d))
        row1 += ['年假合计', '调休合计', '补假合计', '剩余年假', '剩余调休']
        output.write(','.join(f'"{h}"' for h in row1) + '\n')

        for idx, emp in enumerate(employees, 1):
            eid = emp['id']
            row = [str(idx), emp['employee_id'], emp['name'], '药事管理组']
            a_sum, c_sum, cl_sum = 0, 0, 0

            for d in range(1, last_day_num + 1):
                entry = daily_map.get(eid, {}).get(d)
                if entry:
                    t = entry['type']
                    h = entry['half']
                    if t == '年' or t == '调':
                        disp = '休半天假' if h else '休一天假'
                    else:  # 补
                        disp = '补休半天' if h else '补休一天值班假'
                    row.append(disp)
                    val = 0.5 if h else 1.0
                    if entry['type'] == '年': a_sum += val
                    elif entry['type'] == '调': c_sum += val
                    elif entry['type'] == '补': cl_sum += val
                else:
                    row.append('')

            row += [str(a_sum), str(c_sum), str(cl_sum),
                    str(emp['remaining_annual'] or 0), str(emp['remaining_comp'] or 0)]
            output.write(','.join(f'"{c}"' for c in row) + '\n')

        csv_content = output.getvalue()
        output.close()

        filename = f"考勤明细_{month_str}.csv"
        encoded = urllib.parse.quote(filename)
        return Response(
            csv_content,
            mimetype='text/csv; charset=utf-8',
            headers={'Content-Disposition': f"attachment; filename*=UTF-8''{encoded}",
                     'Content-Type': 'text/csv; charset=utf-8'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── System Log ────────────────────────────────────────────────────────────

def log_action(action, detail=''):
    try:
        db = get_db()
        db.execute("INSERT INTO system_log (action, detail, operator) VALUES (?, ?, ?)",
                  (action, detail, session.get('user', '系统')))
        db.commit()
    except:
        pass

@app.route('/api/logs')
@login_required
def get_logs():
    db = get_db()
    logs = db.execute("SELECT * FROM system_log ORDER BY created_at DESC LIMIT 50").fetchall()
    return jsonify([dict(l) for l in logs])

# ── Page routes ───────────────────────────────────────────────────────────

@app.route('/my')
@login_required
def my_page():
    return render_template('my.html', is_admin=is_admin())

@app.route('/employees')
@login_required
def employees_page():
    return render_template('employees.html', is_admin=is_admin())

@app.route('/applications')
@login_required
def applications_page():
    return render_template('applications.html', is_admin=is_admin(), role=session.get('role'))

@app.route('/approvals')
@login_required
def approvals_page():
    if not is_admin():
        return redirect(url_for('index'))
    return render_template('approvals.html', is_admin=True)

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html', is_admin=is_admin())


@app.route('/permissions')
@login_required
@admin_required
def permissions_page():
    return render_template('permissions.html')

@app.route('/change-password')
@login_required
def change_password_page():
    return render_template('change_password.html')

@app.route('/admin-passwords')
@login_required
@admin_required
def admin_passwords_page():
    return render_template('admin_passwords.html')

@app.route('/monthly-report')
@login_required
def monthly_report_page():
    return render_template('monthly_report.html', is_admin=is_admin(), session=session)

# ── Main ──────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    print(f"药事管理组假期管理系统 v2.0")
    print(f"当前员工: {count}人")
    print(f"部门负责人: 马文兵 (全部权限)")
    print(f"启动地址: http://0.0.0.0:{os.environ.get('PORT', 8012)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8012))
    app.run(host='0.0.0.0', port=port, debug=True)
