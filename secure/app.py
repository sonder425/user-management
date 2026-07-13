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
"""
import os
import uuid
import sqlite3
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
