import os
import uuid
import imghdr
import sqlite3
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

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

# 上传文件大小限制
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# 上传文件保存路径
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 允许上传的文件扩展名白名单
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "svg"}

# 允许的 MIME 类型白名单
ALLOWED_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/bmp",
                     "image/webp", "image/x-icon", "image/svg+xml"}

# 单个用户最大上传限制（5个文件）
MAX_FILES_PER_USER = 5

# 登录失败次数限制
LOGIN_MAX_ATTEMPTS = 5           # 最大尝试次数
LOGIN_LOCKOUT_MINUTES = 5        # 锁定时间（分钟）
login_attempts: dict[str, list] = {}   # IP -> [失败时间戳列表]


def _get_client_ip() -> str:
    """获取客户端真实 IP（仅在有反向代理时信任 X-Forwarded-For）"""
    # 仅当明确配置了可信代理时才取 X-Forwarded-For
    trusted_proxy = os.environ.get("TRUSTED_PROXY", "").lower() in ("1", "true", "yes")
    if trusted_proxy:
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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 插入默认用户（使用哈希密码存储）
    default_users = [
        ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000", 99999),
        ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001", 100),
    ]
    for u, p, e, ph, b in default_users:
        c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)", (u, p, e, ph, b))
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
            c.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
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

        # 再查 SQLite 数据库（哈希密码比对）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
            db_user = c.fetchone()
            conn.close()

            if db_user and check_password_hash(db_user[1], password):  # 哈希比对
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
    """用户注册（已修复：参数化查询 + 密码哈希存储）"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or len(username) > 32:
            return render_template("register.html", error="用户名长度不正确！")
        if not password or len(password) > 64:
            return render_template("register.html", error="密码长度不正确！")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 已修复：使用参数化查询 + 密码哈希存储
        password_hash = generate_password_hash(password)
        query = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)"
        print(f"[SQL] 注册查询: {query} 参数: ({username}, {email}, {phone})")
        try:
            c.execute(query, (username, password_hash, email, phone, 0))
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
    """用户搜索（已修复：参数化查询 + 输入校验）"""
    keyword = request.args.get("keyword", "").strip()
    results = []
    sql = ""

    if keyword:
        if len(keyword) > 64:
            keyword = keyword[:64]

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 已修复：使用参数化查询
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f'%{keyword}%'
        print(f"[SQL] 搜索查询: {sql} 参数: ({like_param})")
        try:
            c.execute(sql, (like_param, like_param))
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
            row = conn2.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,)).fetchone()
            if row:
                user = {"username": row[0], "email": row[1], "phone": row[2]}
        except Exception as e:
            print(f"[SQL] 搜索页用户查询错误: {e}")
        finally:
            conn2.close()

    return render_template("index.html", user=user, search_results=results, keyword=keyword, search_sql=sql)


def allowed_file(filename: str) -> bool:
    """检查文件扩展名是否在白名单中"""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def validate_image_content(filepath: str) -> bool:
    """使用 imghdr 验证文件是否为真实图片"""
    img_type = imghdr.what(filepath)
    if img_type is None:
        # imghdr 不认识的可能是 svg（svg需要单独验证）
        try:
            with open(filepath, "rb") as f:
                header = f.read(1024)
            return b"<svg" in header.lower() or b"<?xml" in header.lower()
        except Exception:
            return False
    return True


def get_user_upload_count(username: str) -> int:
    """获取指定用户已上传的文件数量"""
    user_upload_dir = os.path.join(UPLOAD_FOLDER, username)
    if not os.path.isdir(user_upload_dir):
        return 0
    return len(os.listdir(user_upload_dir))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """用户头像上传（已修复：扩展名校验、MIME校验、路径穿越防护、UUID重命名、用户隔离）"""
    if "username" not in session:
        return redirect("/login")

    username = session["username"]

    if request.method == "POST":
        # F-08 修复：限制同用户上传文件数量
        if get_user_upload_count(username) >= MAX_FILES_PER_USER:
            return render_template("upload.html", error=f"上传文件数已达上限（{MAX_FILES_PER_USER}个），请先删除旧文件再上传！")

        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件！")

        original_filename = file.filename

        # F-02 修复：使用 werkzeug 的 secure_filename 防止路径遍历
        safe_filename = secure_filename(original_filename)
        if safe_filename != original_filename:
            print(f"[UPLOAD] 文件名安全处理: {original_filename} -> {safe_filename}")

        # F-01 修复：白名单校验文件扩展名
        if not allowed_file(original_filename):
            print(f"[UPLOAD] 拒绝上传（扩展名不合法）: {original_filename}")
            return render_template("upload.html", error=f"仅支持上传图片文件（{', '.join(sorted(ALLOWED_EXTENSIONS))}）！")

        # F-03 修复：验证 MIME 类型
        mime_type = file.content_type
        if mime_type not in ALLOWED_MIMETYPES and mime_type is not None:
            print(f"[UPLOAD] 拒绝上传（MIME类型不合法）: {original_filename} ({mime_type})")
            return render_template("upload.html", error="文件类型不正确，请上传图片文件！")

        # F-05/F-06 修复：UUID重命名 + 用户隔离目录
        ext = original_filename.rsplit(".", 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        user_upload_dir = os.path.join(UPLOAD_FOLDER, username)
        os.makedirs(user_upload_dir, exist_ok=True)
        filepath = os.path.join(user_upload_dir, unique_filename)

        # 保存文件
        file.save(filepath)

        # F-04 修复：验证文件内容是否为真实图片
        if not validate_image_content(filepath):
            os.remove(filepath)
            print(f"[UPLOAD] 删除非图片文件: {filepath}")
            return render_template("upload.html", error="上传的文件不是有效的图片文件！")

        file_url = url_for("static", filename=f"uploads/{username}/{unique_filename}")
        print(f"[UPLOAD] 文件上传成功: {filepath} -> {file_url}")

        return render_template("upload.html",
                               success=True,
                               file_url=file_url,
                               filename=unique_filename,
                               original_filename=original_filename)

    return render_template("upload.html")


@app.route("/profile", methods=["GET"])
def profile():
    """个人中心（已修复：从session获取用户，不再接受URL参数指定他人）"""
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    error_msg = request.args.get("error", "")

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            user_data = {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "phone": row[3],
                "balance": row[4]
            }
        else:
            # 如果 SQLite 没有此用户，从 USERS 字典查
            if username in USERS:
                user_data = {
                    "id": 0,
                    "username": USERS[username]["username"],
                    "email": USERS[username]["email"],
                    "phone": USERS[username]["phone"],
                    "balance": USERS[username].get("balance", 0)
                }
            else:
                return render_template("profile.html", error="未找到用户信息！")
    except Exception as e:
        print(f"[SQL] 个人中心查询错误: {e}")
        return render_template("profile.html", error=f"查询出错：{e}")
    finally:
        conn.close()

    return render_template("profile.html", user=user_data, error=error_msg)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值功能（已修复：校验用户身份 + 金额正负）"""
    if "username" not in session:
        return redirect("/login")

    username = session["username"]
    amount = request.form.get("amount", "0").strip()

    # A-04 修复：校验 amount 必须为正数
    try:
        amount = float(amount)
    except ValueError:
        return redirect("/profile?error=金额格式不正确！")

    if amount <= 0:
        return redirect("/profile?error=充值金额必须大于零！")

    # A-03 修复：根据 session 中的 username 确定 user_id，不接受外部传入
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        # 先查当前用户的 id
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if not row:
            conn.close()
            # USERS 字典中的用户不支持充值
            flash("该账户不支持充值功能")
            return redirect("/profile")

        user_id = row[0]
        # 已修复：参数化查询 + 金额正负校验
        c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        conn.commit()
        print(f"[RECHARGE] 用户 {username}(ID={user_id}) 充值 {amount} 成功")
    except Exception as e:
        print(f"[RECHARGE] 充值错误: {e}")
        flash(f"充值失败：{e}")
    finally:
        conn.close()

    return redirect("/profile")


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
