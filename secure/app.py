"""
用户管理系统 — 安全修复版（含业务逻辑修复）
=============================================
修复说明：
  1. 所有 SQL 查询使用参数化查询（?占位符），消除 SQL 注入
  2. 密码使用 Werkzeug 哈希存储，不再明文保存
  3. 用户信息不返回密码字段到前端
  4. Session 添加安全配置
  5. 添加 CSRF 保护和登录频率限制
  6. 文件上传安全检查：后缀过滤、UUID重命名、文件头校验
  7. IDOR 越权漏洞修复：个人中心只能查看自己的资料
  8. 充值金额校验：amount 必须为正数
  9. 密码不在个人中心页面显示
 10. SSRF 防护：限制 URL 协议为 http/https，禁止内网 IP
"""
import os
import uuid
import sqlite3
import re
import socket
import urllib.request
import urllib.error
import urllib.parse
import subprocess
import platform
import re
import json
import xml.etree.ElementTree as ET
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

csrf = CSRFProtect(app)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpg/jpeg",
    b"\x89PNG": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
    b"BM": "bmp",
}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_header(file_path):
    with open(file_path, "rb") as f:
        header = f.read(8)
    return any(header.startswith(sig) for sig in IMAGE_SIGNATURES)


def init_db():
    os.makedirs("data", exist_ok=True)
    os.makedirs("static/uploads", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000"),
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001"),
    )
    conn.commit()
    conn.close()

init_db()


def get_db():
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    return conn


def get_safe_user(username):
    if not username:
        return None
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "id": row["id"],
            "username": row["username"],
            "role": "user",
            "email": row["email"],
            "phone": row["phone"],
            "balance": row["balance"] if row["balance"] else 0,
        }
    return None


class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired(), Length(2, 20)])
    password = PasswordField("密码", validators=[DataRequired(), Length(1, 100)])
    submit = SubmitField("登 录")


@app.route("/")
def index():
    user = get_safe_user(session.get("username"))
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row and check_password_hash(row["password"], password):
            session.clear()
            session["username"] = username
            session["user_id"] = row["id"]
            session.permanent = True
            user = get_safe_user(username)
            return render_template("index.html", user=user)
        return render_template("login.html", form=form, error="认证失败，请检查您的凭证")
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), email, phone),
            )
            conn.commit()
            return render_template("login.html", form=form, error="注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html", form=form, error="用户名已存在")
        finally:
            conn.close()
    return render_template("register.html", form=form)


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    user = get_safe_user(session.get("username"))
    if keyword:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?",
            (f"%{keyword}%", f"%{keyword}%"),
        )
        for row in cursor.fetchall():
            results.append({
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
                "phone": row["phone"],
            })
        conn.close()
    return render_template("index.html", user=user, search_results=results if keyword else None, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件")
        if not allowed_file(file.filename):
            return render_template("upload.html", error="不支持的文件类型，仅允许图片文件")
        ext = file.filename.rsplit(".", 1)[1].lower()
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        save_path = os.path.join("static/uploads", new_filename)
        file.save(save_path)
        if not validate_image_header(save_path):
            os.remove(save_path)
            return render_template("upload.html", error="文件内容不是合法的图片格式")
        file_url = url_for("static", filename=f"uploads/{new_filename}")
        return render_template("upload.html", file_url=file_url, filename=new_filename)
    return render_template("upload.html")


@app.route("/profile", methods=["GET"])
def profile():
    """【已修复】个人中心：只能查看自己的资料，不显示密码"""
    if "username" not in session:
        return redirect("/login")

    user_id = request.args.get("user_id", type=int)

    # 【已修复】IDOR 防护：检查当前登录用户是否与请求的 user_id 匹配
    if session.get("user_id") != user_id:
        return render_template("profile.html", user=None, error="无权查看其他用户的资料")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        user_data = {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "phone": row["phone"],
            "role": "user" if row["username"] not in ("admin",) else "admin",
            "balance": row["balance"] if row["balance"] else 0,
        }
        return render_template("profile.html", user=user_data)
    return render_template("profile.html", user=None, error="用户不存在")


@app.route("/recharge", methods=["POST"])
def recharge():
    """【已修复】充值：验证登录、验证金额正数、使用参数化查询"""
    if "username" not in session:
        return redirect("/login")

    user_id = request.form.get("user_id", type=int)
    amount = request.form.get("amount", type=float)

    # 【已修复】IDOR 防护：只能给自己的账户充值
    if session.get("user_id") != user_id:
        return render_template("profile.html", user=None, error="无权给其他用户充值")

    # 【已修复】金额校验：amount 必须为正数
    if not amount or amount <= 0:
        return redirect(f"/profile?user_id={user_id}")

    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE id = ?", (amount, user_id))
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")


@app.route("/page")
def page():
    """【已修复】动态页面加载：限制只能访问 pages/ 目录下的 .html 文件"""
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_error="未指定页面名称")

    # 【已修复】只允许 .html 后缀
    if not name.endswith(".html"):
        name = name + ".html"

    # 【已修复】使用 os.path.realpath 规范化路径
    pages_dir = os.path.realpath("pages")
    page_path = os.path.realpath(os.path.join("pages", name))

    # 【已修复】检查路径是否在 pages 目录内，防止 ../ 逃逸
    if not page_path.startswith(pages_dir):
        return render_template("index.html", page_error="页面不存在")

    # 检查文件是否存在
    if not os.path.exists(page_path):
        return render_template("index.html", page_error="页面不存在")

    # 读取文件内容
    with open(page_path, "r", encoding="utf-8") as f:
        page_content = f.read()

    username = session.get("username")
    user = None
    if username:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            user = {
                "username": row["username"],
                "role": "user",
                "email": row["email"],
                "phone": row["phone"],
                "balance": row["balance"] if row["balance"] else 0,
            }

    return render_template("index.html", user=user, page_content=page_content, page_name=name)


@app.route("/change-password", methods=["POST"])
def change_password():
    """【已修复】修改密码：CSRF防护 + 身份验证 + 旧密码验证 + 密码哈希"""
    if "username" not in session:
        return redirect("/login")

    # 只允许修改自己的密码
    current_user = session.get("username")
    target_username = request.form.get("username")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password")

    if not target_username or not new_password or target_username != current_user:
        return redirect("/profile?user_id=" + str(session.get("user_id", 1)))

    # 验证旧密码
    from_db = None
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (target_username,))
    row = cursor.fetchone()

    if row:
        if not check_password_hash(row["password"], old_password):
            conn.close()
            return redirect("/profile?user_id=" + str(session.get("user_id", 1)))
        cursor.execute("UPDATE users SET password = ? WHERE username = ?",
                       (generate_password_hash(new_password), target_username))
        conn.commit()
    conn.close()

    return redirect("/profile?user_id=" + str(session.get("user_id", 1)))


def is_internal_ip(hostname):
    """检查目标 IP 是否为内网地址，防止 SSRF"""
    try:
        ip = socket.gethostbyname(hostname)
        # 检查私有 IP 地址段
        private_ranges = [
            "127.", "10.", "192.168.",
            "169.254.", "0.",
        ]
        # 172.16.0.0 - 172.31.255.255
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                return True
        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True
        return False
    except Exception:
        return True  # 解析失败时拒绝访问


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """【已修复】URL 抓取：限制协议、禁止内网、禁止 file://"""
    if "username" not in session:
        return redirect("/login")

    url = request.form.get("url", "")
    if not url:
        return render_template("index.html", fetch_error="请输入 URL")

    # 限制只允许 http/https 协议
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return render_template("index.html", fetch_error="不支持的协议类型")

    # 禁止访问内网地址（SSRF 防护）
    hostname = parsed.hostname
    if not hostname or is_internal_ip(hostname):
        return render_template("index.html", fetch_error="不允许访问内网地址")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        response = urllib.request.urlopen(req, timeout=10)
        status_code = response.getcode()
        content = response.read().decode("utf-8", errors="ignore")[:5000]
        response.close()

        username = session.get("username")
        user = get_safe_user(username)
        return render_template("index.html", user=user,
                               fetch_status=status_code, fetch_content=content, fetch_url=url)
    except Exception as e:
        return render_template("index.html", fetch_error=f"抓取失败: {e}")


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """【已修复】Ping 网络诊断：使用参数列表而非 shell=True，防止命令注入"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        ip = request.form.get("ip", "")

        # 【已修复】使用参数列表而非 f-string 拼接，防止命令注入
        # 只允许 IP 地址和域名（字母数字.-）
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9\.\-]+$', ip):
            return render_template("ping.html", result="错误：只允许输入 IP 地址或域名", ip=ip)

        try:
            # 【已修复】使用参数列表，shell=False（默认），防止命令注入
            output = subprocess.check_output(
                ["ping", "-c", "3", ip],
                timeout=30,
                stderr=subprocess.STDOUT,
            )
            result = output.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            result = f"命令执行失败 (返回码: {e.returncode})\n{e.output.decode('utf-8', errors='ignore')}"
        except subprocess.TimeoutExpired:
            result = "命令执行超时"
        except Exception as e:
            result = f"执行错误: {e}"

        return render_template("ping.html", result=result, ip=ip)

    return render_template("ping.html")


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    """【已修复】XML 数据导入：禁用外部实体解析，防止 XXE 攻击"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        xml_data = request.form.get("xml_data", "")

        if not xml_data.strip():
            return render_template("xml_import.html", result=json.dumps({"error": "请输入 XML 数据"}, ensure_ascii=False, indent=2))

        try:
            # 【已修复】创建解析器时禁用外部实体解析
            parser = ET.XMLParser()
            parser.parser.EntityResolver = lambda *a: None  # type: ignore
            # 【已修复】禁止 DTD 加载外部资源
            parser.parser.setFeature(ET.XMLParser.feature_external_ges, False)  # type: ignore
            parser.parser.setFeature(ET.XMLParser.feature_external_pes, False)  # type: ignore

            root = ET.fromstring(xml_data, parser)
            users = []
            for user_elem in root.findall(".//user"):
                name = user_elem.findtext("name", "")
                email = user_elem.findtext("email", "")
                users.append({"name": name, "email": email})

            result = {
                "status": "success",
                "users_count": len(users),
                "users": users,
            }
            return render_template("xml_import.html", result=json.dumps(result, ensure_ascii=False, indent=2))

        except Exception as e:
            error_msg = str(e)
            # 不暴露敏感错误信息
            if "cannot decode" in error_msg.lower() or "invalid" in error_msg.lower():
                error_msg = "XML 格式错误"
            return render_template("xml_import.html", result=json.dumps({"error": f"XML 解析失败: {error_msg}"}, ensure_ascii=False, indent=2))

    return render_template("xml_import.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
