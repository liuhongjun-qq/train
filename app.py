import os
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session
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


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        # 不将密码字段传给模板
        user = {k: v for k, v in USERS[username].items() if k != "password"}
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

        # 安全比对密码（使用哈希）
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            # 登录成功，清除该 IP 的失败记录
            login_attempts.pop(client_ip, None)
            session["username"] = username
            user = {k: v for k, v in USERS[username].items() if k != "password"}
            return render_template("index.html", user=user)

        # 记录失败尝试
        _record_failed_attempt(client_ip)
        remaining = LOGIN_MAX_ATTEMPTS - len(login_attempts.get(client_ip, []))
        return render_template("login.html", error=f"用户名或密码错误！剩余尝试次数：{remaining}")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
