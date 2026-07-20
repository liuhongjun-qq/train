import os
import sqlite3
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 使用环境变量或随机密钥（不再硬编码弱密钥）
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# 密码以哈希形式存储，不再存明文
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# Session 安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# 登录失败次数限制
LOGIN_MAX_ATTEMPTS = 5           # 最大尝试次数
LOGIN_LOCKOUT_MINUTES = 5        # 锁定时间（分钟）
login_attempts: dict[str, list] = {}   # IP -> [失败时间戳列表]


def _get_client_ip() -> str:
    """获取客户端真实 IP（支持反向代理）"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_ip_blocked(ip: str) -> bool:
    """检查 IP 是否因多次登录失败被临时封禁"""
    now = datetime.now()
    attempts = login_attempts.get(ip, [])
    # 清理超过锁定周期的旧记录
    login_attempts[ip] = [t for t in attempts if t > now - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)]
    return len(login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS


def _record_failed_attempt(ip: str) -> None:
    """记录一次失败的登录尝试"""
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(datetime.now())


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（使用明文密码存储，与原有 USERS 字典区分）
    default_users = [
        ("admin", "admin123", "admin@example.com", "13800138000"),
        ("alice", "alice2025", "alice@example.com", "13900139001"),
    ]
    for u, p, e, ph in default_users:
        c.execute(f"INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('{u}', '{p}', '{e}', '{ph}')")
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成")


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        # 不将密码字段传给模板
        user = {k: v for k, v in USERS[username].items() if k != "password"}
    elif username:
        # 从 SQLite 数据库取用户信息
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(f"SELECT username, email, phone FROM users WHERE username = '{username}'")
            row = c.fetchone()
            if row:
                user = {"username": row[0], "email": row[1], "phone": row[2]}
        except Exception as e:
            print(f"[SQL] 首页查询错误: {e}")
        finally:
            conn.close()
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = _get_client_ip()

        # 检查 IP 是否被临时封禁
        if _is_ip_blocked(client_ip):
            return render_template(
                "login.html",
                error=f"登录失败次数过多，请 {LOGIN_LOCKOUT_MINUTES} 分钟后再试！"
            )

        # 输入清洗与校验
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or len(username) > 64:
            return render_template("login.html", error="用户名格式不正确！")
        if not password or len(password) > 128:
            return render_template("login.html", error="密码格式不正确！")

        # 安全比对密码（使用哈希）—— 先查 USERS 字典（哈希密码）
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            # 登录成功，清除该 IP 的失败记录
            login_attempts.pop(client_ip, None)
            session["username"] = username
            user = {k: v for k, v in USERS[username].items() if k != "password"}
            return render_template("index.html", user=user)

        # 再查 SQLite 数据库（明文密码）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        db_query = f"SELECT username, password, email, phone FROM users WHERE username = '{username}'"
        print(f"[SQL] 登录查询: {db_query}")
        try:
            c.execute(db_query)
            db_user = c.fetchone()
            conn.close()

            if db_user and db_user[1] == password:  # 明文比对
                login_attempts.pop(client_ip, None)
                session["username"] = username
                user_info = {
                    "username": db_user[0],
                    "email": db_user[2],
                    "phone": db_user[3],
                }
                return render_template("index.html", user=user_info)

        except Exception as e:
            print(f"[SQL] 登录查询错误: {e}")
            conn.close()

        # 记录失败尝试
        _record_failed_attempt(client_ip)
        remaining = LOGIN_MAX_ATTEMPTS - len(login_attempts.get(client_ip, []))
        return render_template("login.html", error=f"用户名或密码错误！剩余尝试次数：{remaining}")

    success_msg = session.pop("register_success", None)
    return render_template("login.html", success=success_msg)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """用户注册（使用 f-string 字符串拼接 SQL，存在 SQL 注入漏洞）"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 漏洞：使用 f-string 拼接 SQL，未做任何过滤
        query = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] 注册查询: {query}")
        try:
            c.execute(query)
            conn.commit()
            session["register_success"] = "注册成功，请登录"
            return redirect("/login")
        except Exception as e:
            print(f"[SQL] 注册错误: {e}")
            return render_template("register.html", error=f"注册失败：{e}")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/search", methods=["GET"])
def search():
    """用户搜索（使用 f-string 字符串拼接 SQL，存在 SQL 注入漏洞）"""
    keyword = request.args.get("keyword", "").strip()
    results = []
    sql = ""

    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 漏洞：使用 f-string 拼接 SQL，未做任何过滤
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] 搜索查询: {sql}")
        try:
            c.execute(sql)
            results = c.fetchall()
        except Exception as e:
            print(f"[SQL] 搜索错误: {e}")
            flash(f"搜索出错：{e}")
        finally:
            conn.close()

    username = session.get("username")
    user = None
    if username and username in USERS:
        user = {k: v for k, v in USERS[username].items() if k != "password"}
    elif username:
        conn2 = sqlite3.connect("data/users.db")
        try:
            row = conn2.execute(f"SELECT username, email, phone FROM users WHERE username = '{username}'").fetchone()
            if row:
                user = {"username": row[0], "email": row[1], "phone": row[2]}
        except Exception as e:
            print(f"[SQL] 搜索页用户查询错误: {e}")
        finally:
            conn2.close()

    return render_template("index.html", user=user, search_results=results, keyword=keyword, search_sql=sql)


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
