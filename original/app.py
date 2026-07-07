from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# 用户数据库（明文密码，不做任何哈希处理）
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


@app.route("/")
def index():
    """首页路由：从 session 获取当前登录用户名，取出完整信息传递给模板"""
    username = session.get("username")
    user = USERS.get(username)  # 包含密码字段的完整信息
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录路由：GET 返回登录页，POST 验证身份"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 从 USERS 字典获取用户
        user = USERS.get(username)

        # 直接用 == 比对密码明文
        if user and user["password"] == password:
            session["username"] = username
            # 将用户完整信息（含密码）传给模板
            return render_template("index.html", user=user)
        else:
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """登出路由：清除 session 后重定向到首页"""
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
