"""
用户管理系统 — SQL注入修复版
============================
修复说明：
  1. 所有 SQL 查询改为参数化查询（?占位符），彻底消除 SQL 注入风险
  2. 密码使用 Werkzeug 哈希存储，不再明文保存
  3. 用户信息不返回密码字段到前端
  4. Session 添加安全配置
  5. 添加 CSRF 保护和登录频率限制
"""
import os
import sqlite3
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session
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
)

csrf = CSRFProtect(app)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])


# ===== 数据库 =====

def init_db():
    """初始化数据库，创建 users 表"""
    os.makedirs("data", exist_ok=True)
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
    # 插入默认用户（密码已哈希）
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
    # 【已修复】使用参数化查询，避免 SQL 注入
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
    """首页"""
    user = get_safe_user(session.get("username"))
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    """登录"""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        # 【已修复】使用参数化查询
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
    """注册 —— 【已修复】使用参数化查询，无 SQL 注入风险"""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 【已修复】使用 ? 占位符参数化查询，不用 f-string 拼接
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
    """搜索 —— 【已修复】使用参数化查询，无 SQL 注入风险"""
    keyword = request.args.get("keyword", "")
    results = []
    user = get_safe_user(session.get("username"))

    if keyword:
        # 【已修复】使用 ? 占位符参数化查询
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


@app.route("/logout")
def logout():
    """登出"""
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
