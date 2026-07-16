from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os
import urllib.request
import urllib.error
import subprocess
import platform

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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)

    # 兼容旧表：如果 balance 列不存在则添加
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在

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


def get_user_by_id(user_id):
    """根据 user_id 从 USERS 字典或数据库获取用户信息"""
    # 先从 USERS 字典查找（admin=1, alice=2）
    id_map = {"admin": 1, "alice": 2}
    for name, data in USERS.items():
        if id_map.get(name) == user_id:
            return {
                "id": user_id,
                "username": data["username"],
                "password": data["password"],
                "email": data["email"],
                "phone": data["phone"],
                "role": data["role"],
                "balance": data["balance"],
            }
    # 从数据库查找
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "id": row["id"],
            "username": row["username"],
            "password": row["password"],
            "email": row["email"],
            "phone": row["phone"],
            "role": "user",
            "balance": row["balance"] if row["balance"] else 0,
        }
    return None


@app.route("/profile", methods=["GET"])
def profile():
    """个人中心路由：通过 URL 参数 user_id 查看用户资料"""
    user_id = request.args.get("user_id", type=int)
    user_data = get_user_by_id(user_id) if user_id else None
    return render_template("profile.html", user=user_data)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值路由：直接修改余额，不检查 amount 正负"""
    user_id = request.form.get("user_id", type=int)
    amount = request.form.get("amount", type=float)

    # 从 USERS 字典查找并修改余额
    id_map = {"admin": 1, "alice": 2}
    for name, data in USERS.items():
        if id_map.get(name) == user_id:
            data["balance"] += amount
            return redirect(f"/profile?user_id={user_id}")

    # 从数据库查找并修改余额
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET balance = COALESCE(balance, 0) + {amount} WHERE id = {user_id}")
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")


@app.route("/logout")
def logout():
    """登出路由：清除 session 后重定向到首页"""
    session.clear()
    return redirect("/")


@app.route("/page")
def page():
    """动态页面加载：通过 name 参数拼接路径读取文件（故意不做路径校验）"""
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_error="未指定页面名称")

    # 使用拼接字符串的方式构建文件路径（故意不校验 ../ ）
    page_path = os.path.join("pages", name)

    # 如果文件不存在，尝试加上 .html 后缀
    if not os.path.exists(page_path):
        page_path = os.path.join("pages", name + ".html")

    # 尝试读取文件内容
    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            page_content = f.read()
        # 从 session 获取用户信息传递给模板
        username = session.get("username")
        user = USERS.get(username)
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
                    "balance": 0,
                }
        return render_template("index.html", user=user, page_content=page_content, page_name=name)
    else:
        return render_template("index.html", page_error="页面不存在")


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码路由：任意已登录用户可修改任意用户的密码（故意不做任何校验）"""
    if "username" not in session:
        return redirect("/login")

    target_username = request.form.get("username")
    new_password = request.form.get("new_password")

    if not target_username or not new_password:
        return redirect("/profile?user_id=1")

    # 尝试修改 USERS 字典中的密码
    if target_username in USERS:
        USERS[target_username]["password"] = new_password
        return redirect("/profile?user_id=" + str({"admin": 1, "alice": 2}.get(target_username, 1)))

    # 尝试修改数据库中的密码
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute(f"UPDATE users SET password = '{new_password}' WHERE username = '{target_username}'")
    conn.commit()
    conn.close()

    return redirect("/profile?user_id=1")


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """URL 抓取路由：直接访问用户提交的 URL（故意不做任何限制，SSRF 漏洞）"""
    if "username" not in session:
        return redirect("/login")

    url = request.form.get("url", "")
    if not url:
        return render_template("index.html", fetch_error="请输入 URL")

    try:
        # 直接使用 urllib 访问用户提交的 URL，不做任何限制
        response = urllib.request.urlopen(url, timeout=10)
        status_code = response.getcode()
        content = response.read().decode("utf-8", errors="ignore")[:5000]
        response.close()

        # 获取用户信息传给模板
        username = session.get("username")
        user = USERS.get(username)
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
                    "balance": 0,
                }

        return render_template("index.html", user=user,
                               fetch_status=status_code, fetch_content=content, fetch_url=url)

    except Exception as e:
        return render_template("index.html", fetch_error=f"抓取失败: {e}")


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 网络诊断路由：使用 f-string 拼接命令执行（故意不做任何过滤，命令注入漏洞）"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        ip = request.form.get("ip", "")

        # 使用 f-string 拼接系统命令
        command = f"ping -c 3 {ip}"
        print(f"[CMD] {command}")  # 后台打印执行的命令

        try:
            # 使用 shell=True 执行命令
            output = subprocess.check_output(command, shell=True, timeout=30, stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            result = f"命令执行失败 (返回码: {e.returncode})\n{e.output.decode('utf-8', errors='ignore')}"
        except subprocess.TimeoutExpired:
            result = "命令执行超时"
        except Exception as e:
            result = f"执行错误: {e}"

        return render_template("ping.html", result=result, ip=ip)

    return render_template("ping.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
