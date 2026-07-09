"""
用户管理系统 — 安全修复版（含上传功能）
========================================
修复说明：
  1. 所有 SQL 查询使用参数化查询（?占位符），消除 SQL 注入
  2. 密码使用 Werkzeug 哈希存储，不再明文保存
  3. 用户信息不返回密码字段到前端
  4. Session 添加安全配置
  5. 添加 CSRF 保护和登录频率限制
  6. 文件上传安全检查：后缀过滤、UUID重命名、文件头校验
"""
import os
import uuid
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for
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

# 允许上传的文件后缀
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

# 常见图片文件头（魔数）
IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpg/jpeg",
    b"\x89PNG": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
    b"BM": "bmp",
}


def allowed_file(filename):
    """检查文件后缀是否在允许列表中"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_header(file_path):
    """通过文件头魔数验证是否为合法图片"""
    with open(file_path, "rb") as f:
        header = f.read(8)
    for sig in IMAGE_SIGNATURES:
        if header.startswith(sig):
            return True
    return False


# ===== 数据库 =====

def init_db():
    """初始化数据库和上传目录"""
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
            phone TEXT
        )
    """)
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
    """获取数据库连接"""
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    return conn


def get_safe_user(username):
    """从数据库查询用户，返回不含密码的字典"""
    if not username:
        return None
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "username": row["username"],
            "role": "user",
            "email": row["email"],
            "phone": row["phone"],
            "balance": 0,
        }
    return None


# ===== 登录表单 =====

class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired(), Length(2, 20)])
    password = PasswordField("密码", validators=[DataRequired(), Length(1, 100)])
    submit = SubmitField("登 录")


# ===== 路由 =====

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
    """上传头像 —— 包含安全检查"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件")

        # 【已修复】检查文件后缀
        if not allowed_file(file.filename):
            return render_template("upload.html", error="不支持的文件类型，仅允许图片文件")

        # 【已修复】使用 UUID 重命名文件，防止覆盖和路径穿越
        ext = file.filename.rsplit(".", 1)[1].lower()
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        save_path = os.path.join("static/uploads", new_filename)

        file.save(save_path)

        # 【已修复】检查文件头魔数，验证是否为真实图片
        if not validate_image_header(save_path):
            os.remove(save_path)
            return render_template("upload.html", error="文件内容不是合法的图片格式")

        file_url = url_for("static", filename=f"uploads/{new_filename}")
        return render_template("upload.html", file_url=file_url, filename=new_filename)

    return render_template("upload.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
