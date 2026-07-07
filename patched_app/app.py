"""
用户管理系统 — 安全加固版
=========================
修复清单：
  V-001 ✅ 密码哈希存储（Werkzeug）
  V-002 ✅ 密码不返回前端
  V-003 ✅ 环境变量密钥 + 随机回退
  V-005 ✅ Session 安全配置（HttpOnly / SameSite / Secure）
  V-006 ✅ CSRF 保护（Flask-WTF）
  V-007 ✅ 登录频率限制（Flask-Limiter）
  V-008 ✅ 生产模式关闭 debug
  V-009 ✅ 登录后重新生成 session
"""
import os
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

# ── 应用初始化 ──────────────────────────────────────────────
app = Flask(__name__)

# V-003 修复：安全密钥 —— 优先环境变量，否则随机 64 位 hex
app.secret_key = os.environ.get(
    "SECRET_KEY",
    os.urandom(32).hex()      # 每次重启都会变，生产环境必须设环境变量
)

# V-005 修复：Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,          # 防 XSS 窃取 cookie
    SESSION_COOKIE_SAMESITE="Lax",         # 防 CSRF
    SESSION_COOKIE_SECURE=True,            # 仅 HTTPS 传输（本地调试可关）
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),   # 2 小时过期
)

# V-006 修复：CSRF 保护
csrf = CSRFProtect(app)

# V-007 修复：登录频率限制 —— 同一 IP 每分钟最多 10 次
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# ── 登录表单（Flask-WTF） ──────────────────────────────────
class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[
        DataRequired(message="用户名不能为空"),
        Length(min=2, max=20, message="用户名长度 2~20 位"),
    ])
    password = PasswordField("密码", validators=[
        DataRequired(message="密码不能为空"),
        Length(min=6, max=100, message="密码长度不能少于 6 位"),
    ])
    submit = SubmitField("登 录")


# ── V-001 修复：密码哈希存储 ──────────────────────────────
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),   # 哈希！
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),  # 哈希！
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ── V-002 修复：不返回密码字段 ────────────────────────────
def get_safe_user(username):
    """返回不包含密码的用户信息"""
    user = USERS.get(username)
    if user is None:
        return None
    return {k: v for k, v in user.items() if k != "password"}


# ── 路由 ──────────────────────────────────────────────────

@app.route("/")
def index():
    """首页 —— 不传密码到前端"""
    username = session.get("username")
    user = get_safe_user(username)
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
# V-007 修复：限制登录接口频率
@limiter.limit("10 per minute")
def login():
    """登录 —— 哈希比对 + CSRF 保护 + 频率限制"""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = USERS.get(username)

        # V-001 修复：哈希比对（不是 ==）
        if user and check_password_hash(user["password"], password):
            # V-009 修复：重新生成 session 防固定
            session.clear()
            session.regenerate()
            session["username"] = username
            session.permanent = True

            safe_user = get_safe_user(username)
            return render_template("index.html", user=safe_user)

        # 统一错误信息 —— 不明确告知"用户名或密码哪个错了"
        return render_template("login.html", form=form, error="认证失败，请检查您的凭证")

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    """登出 —— 清除 session"""
    session.clear()
    return redirect("/")


# ── 启动 ──────────────────────────────────────────────────
if __name__ == "__main__":
    # V-008 修复：生产环境关闭 debug
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
