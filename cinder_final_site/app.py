from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'cinder.db')


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '見習い',
            rules_accepted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def create_user(username, password, role='見習い', rules_accepted=0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash, role, rules_accepted) VALUES (?, ?, ?, ?)',
                  (username, generate_password_hash(password), role, rules_accepted))
        conn.commit()
        return True
    except Exception as e:
        print('create_user error:', e)
        return False
    finally:
        conn.close()


def get_user_by_name(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    return row


def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, role, created_at, rules_accepted FROM users ORDER BY created_at DESC')
    rows = c.fetchall()
    conn.close()
    return rows


app = Flask(__name__)
app.secret_key = os.urandom(24)

init_db()

# Ensure an admin exists (admin / Cinder2025)
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("SELECT COUNT(*) FROM users WHERE role='管理者'")
if c.fetchone()[0] == 0:
    create_user('admin', 'Cinder2025', role='管理者', rules_accepted=1)
    print('初期管理者アカウントを作成しました: admin / Cinder2025')
conn.close()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def index():
    if session.get('username'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == 'POST':
        username = request.form.get('username')
        message = request.form.get('message')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO applications (username, message) VALUES (?, ?)', (username, message))
        conn.commit()
        conn.close()
        flash('申請を受け取りました。管理者の承認をお待ちください。')
        return redirect(url_for('index'))
    return render_template('apply.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = get_user_by_name(username)
    if user and check_password_hash(user[2], password):
        session['username'] = user[1]
        session['role'] = user[3]
        # If rules not accepted, redirect to rules page
        if user[4] == 0:
            return redirect(url_for('rules'))
        return redirect(url_for('dashboard'))
    flash('ユーザー名またはパスワードが正しくありません。')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if not session.get('username'):
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))


@app.route('/rules', methods=['GET', 'POST'])
def rules():
    if not session.get('username'):
        return redirect(url_for('index'))
    username = session.get('username')
    if request.method == 'POST':
        # mark user as having accepted rules
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE users SET rules_accepted = 1 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        flash('ルールを承認しました。ようこそ。')
        return redirect(url_for('dashboard'))
    return render_template('rules.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('username') or session.get('role') != '管理者':
        flash('管理者のみアクセス可能です。')
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        app_id = request.form.get('app_id')
        if action == 'accept':
            c.execute('SELECT username FROM applications WHERE id = ?', (app_id,))
            row = c.fetchone()
            if row:
                username = row[0]
                try:
                    create_user(username, 'Cinder2025', role='見習い', rules_accepted=0)
                    c.execute('DELETE FROM applications WHERE id = ?', (app_id,))
                    conn.commit()
                    flash(f'申請を承認しました: {username}（初期パスワード: Cinder2025）')
                except Exception as e:
                    flash('ユーザー作成中にエラーが発生しました。')
        elif action == 'reject':
            c.execute('SELECT username FROM applications WHERE id = ?', (app_id,))
            row = c.fetchone()
            if row:
                c.execute('DELETE FROM applications WHERE id = ?', (app_id,))
                conn.commit()
                flash('申請を却下しました。')
    c.execute('SELECT id, username, message, created_at FROM applications ORDER BY created_at DESC')
    apps = c.fetchall()
    c.execute('SELECT COUNT(*) FROM users')
    total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM applications')
    pending = c.fetchone()[0]
    conn.close()
    users = get_all_users()
    return render_template('admin.html', apps=apps, total=total, pending=pending, users=users)


@app.route('/members')
def members():
    if not session.get('username'):
        return redirect(url_for('index'))
    users = get_all_users()
    return render_template('members.html', users=users)


@app.route('/stats')
def stats():
    if not session.get('username'):
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM applications')
    pending = c.fetchone()[0]
    conn.close()
    return render_template('stats.html', total=total, pending=pending)


@app.route('/board', methods=['GET', 'POST'])
def board():
    if not session.get('username'):
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        content = request.form.get('content')
        author = session.get('username')
        if content and len(content.strip()) > 0:
            c.execute('INSERT INTO posts (author, content) VALUES (?, ?)', (author, content))
            conn.commit()
    c.execute('SELECT author, content, created_at FROM posts ORDER BY created_at DESC')
    posts = c.fetchall()
    conn.close()
    return render_template('board.html', posts=posts)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
