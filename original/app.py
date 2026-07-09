from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

# ===== 数据库初始化 =====
def init_db():
    """初始化数据库和上传目录"""
    os.makedirs("data", exist_ok=True)
    os.makedirs("static/uploads", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()

    # 创建 users 表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)

    # 插入默认用户（使用 INSERT OR IGNORE 防止重复）
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                   ("admin", "admin123", "admin@example.com", "13800138000"))
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                   ("alice", "alice2025", "alice@example.com", "13900139001"))

    conn.commit()
    conn.close()

# 启动时调用
init_db()


# ===== 数据库连接辅助函数 =====
def get_db():
    """获取数据库连接（返回字典类型行）"""
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    return conn


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
    """首页路由"""
    username = session.get("username")
    user = USERS.get(username)

    # 如果在 USERS 字典中找不到，尝试从数据库查找（注册用户）
    if username and not user:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username='{username}'")
        row = cursor.fetchone()
        conn.close()
        if row:
            user = {
                "username": row["username"],
                "password": row["password"],
                "email": row["email"],
                "phone": row["phone"],
                "role": "user",
                "balance": 0
            }

    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录路由：GET 返回登录页，POST 验证身份"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 先从 USERS 字典查找
        user = USERS.get(username)

        # 如果字典没有，从数据库查找（注册用户）
        if not user:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE username='{username}'")
            row = cursor.fetchone()
            conn.close()
            if row:
                user = {
                    "username": row["username"],
                    "password": row["password"],
                    "email": row["email"],
                    "phone": row["phone"],
                    "role": "user",
                    "balance": 0
                }

        # 直接用 == 比对密码明文
        if user and user["password"] == password:
            session["username"] = username
            return render_template("index.html", user=user)
        else:
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册路由：GET 返回注册页，POST 提交注册信息到数据库"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 使用 f-string 字符串拼接 SQL（故意不参数化，用于演示 SQL 注入）
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")  # 后台打印 SQL 语句

        try:
            conn = sqlite3.connect("data/users.db")
            cursor = conn.cursor()
            cursor.execute(sql)
            conn.commit()
            conn.close()
            return render_template("login.html", error="注册成功，请登录")
        except Exception as e:
            print(f"[SQL错误] {e}")
            return render_template("register.html", error=f"注册失败：{e}")

    return render_template("register.html")


@app.route("/search")
def search():
    """搜索路由：通过 URL 参数 keyword 搜索用户"""
    keyword = request.args.get("keyword", "")
    results = []
    username = session.get("username")
    user = USERS.get(username)

    if keyword:
        # 使用 f-string 字符串拼接 SQL（故意不参数化，用于演示 SQL 注入）
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")  # 在后台打印执行的 SQL 语句

        try:
            conn = sqlite3.connect("data/users.db")
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            conn.close()

            # 将 Row 对象转换为字典列表
            for row in rows:
                results.append({
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"],
                    "phone": row["phone"]
                })
        except Exception as e:
            print(f"[SQL错误] {e}")

    return render_template("index.html", user=user, search_results=results, keyword=keyword)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """上传头像路由：需要登录，GET返回上传页，POST接收文件"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            # 使用用户提供的原始文件名保存，不做任何检查
            filename = file.filename
            file.save(os.path.join("static/uploads", filename))
            file_url = url_for("static", filename=f"uploads/{filename}")
            return render_template("upload.html", file_url=file_url, filename=filename)
        else:
            return render_template("upload.html", error="请选择一个文件")

    return render_template("upload.html")


@app.route("/logout")
def logout():
    """登出路由：清除 session 后重定向到首页"""
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
