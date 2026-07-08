# 用户管理系统 — 安全审计项目

> 从一份"故意有漏洞"的 Flask 代码出发，完成：  
> **漏洞发现 → 漏洞分析 → 漏洞修复 → 报告输出** 的完整安全实践。

---

## 📂 项目结构

```
user-management/
├── README.md                          ← 项目说明
├── docs/
│   ├── 漏洞修复报告.pdf               ← 综合漏洞分析与修复方案
│   └── 密码安全修复报告.pdf           ← 专项密码安全修复报告
│
├── original/                          ← 原始漏洞版（有漏洞的版本）
│   ├── app.py                        ← 含密码明文存储等 11 个漏洞
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html                ← HTML 注释泄露管理员账号
│   │   └── index.html                ← 页面展示明文密码
│   └── static/css/style.css
│
├── patched/                           ← 安全加固版（漏洞已修复）
│   ├── app.py                        ← 全部漏洞修复后的代码
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html                ← 移除调试注释，添加 CSRF 保护
│   │   └── index.html                ← 移除密码显示
│   └── static/css/style.css
│
└── secure/                            ← SQL注入修复版（全新项目）
    ├── app.py                        ← 全部使用参数化查询，消除SQL注入
    ├── templates/
    │   ├── base.html
    │   ├── login.html                ← WTForms + CSRF 保护
    │   ├── register.html             ← 含注册功能
    │   └── index.html                ← 含参数化搜索
    └── static/css/style.css
```

---

## 🔴 发现的漏洞（共 11 个）

### 密码安全相关（5 个）

| 编号 | 漏洞 | 等级 | 状态 |
|------|------|------|------|
| PS-001 | 密码明文存储 | 严重 | ✅ 已修复 |
| PS-002 | 密码明文显示在前端 | 严重 | ✅ 已修复 |
| PS-003 | 硬编码弱密钥 | 高危 | ✅ 已修复 |
| PS-004 | 无暴力破解防护 | 中危 | ✅ 已修复 |
| PS-005 | 无 HTTPS 明文传输 | 中危 | ✅ 已修复 |

### 其他安全漏洞（6 个）

| 编号 | 漏洞 | 等级 | 状态 |
|------|------|------|------|
| V-004 | HTML 注释泄露管理员账号 | 中危 | ✅ 已修复 |
| V-005 | 无 Session 安全配置 | 中危 | ✅ 已修复 |
| V-006 | 无 CSRF 保护 | 中危 | ✅ 已修复 |
| V-008 | Debug 模式开启 | 中危 | ✅ 已修复 |
| V-009 | Session 固定攻击 | 低危 | ✅ 已修复 |
| V-011 | Debugger PIN 泄露 | 低危 | ✅ 已修复 |

### SQL 注入漏洞（3 个）

| 编号 | 漏洞 | 等级 | 位置 | 状态 |
|------|------|------|------|------|
| SQL-001 | 注册功能 SQL 注入 | 严重 | `original/app.py` register 路由 | ✅ `secure/` 已修复 |
| SQL-002 | 搜索功能 SQL 注入 | 严重 | `original/app.py` search 路由 | ✅ `secure/` 已修复 |
| SQL-003 | 登录/首页 SQL 注入 | 高危 | `original/app.py` login/index 路由 | ✅ `secure/` 已修复 |

---

## 🛠 修复措施

| 措施 | 涉及漏洞 |
|------|---------|
| Werkzeug 密码哈希（`generate_password_hash`） | PS-001 |
| 删除模板中的密码显示行 | PS-002 |
| 环境变量密钥 + 随机回退 | PS-003 / V-005 |
| Flask-Limiter 登录频率限制 | PS-004 |
| HTTPS 证书配置 | PS-005 |
| 删除 HTML 调试注释 | V-004 |
| Flask-WTF CSRF 保护 | V-006 |
| 关闭 debug 模式 | V-008 |
| 登录后 session.regenerate() | V-009 |

---

## 🚀 运行方式

### 原始漏洞版（体验漏洞）

```bash
cd original
pip install flask
python app.py
```

### 安全加固版（体验修复效果）

```bash
cd patched
pip install flask flask-wtf flask-limiter
python app.py
```

### SQL注入修复版（全新项目，全部参数化查询）

```bash
cd secure
pip install flask flask-wtf flask-limiter
python app.py
```

### 核心修复对比

| SQL 写法 | 漏洞版（`original/`） | 修复版（`secure/`） |
|---------|-------------------|-------------------|
| 注册 | `f"INSERT INTO users VALUES ('{username}')"` | `"INSERT INTO users VALUES (?)"` |
| 搜索 | `f"SELECT * FROM users LIKE '%{keyword}%'"` | `"SELECT * FROM users LIKE ?"` |
| 登录 | `f"SELECT * FROM users WHERE username='{username}'"` | `"SELECT * FROM users WHERE username = ?"` |

访问地址：`http://127.0.0.1:5000`
默认账号：`admin` / `admin123`

---

## 📄 报告文档

- [`docs/漏洞修复报告.pdf`](docs/漏洞修复报告.pdf) — 11 个漏洞的完整分析与修复方案
- [`docs/密码安全修复报告.pdf`](docs/密码安全修复报告.pdf) — 密码安全专项修复报告

---

## 📚 参考资料

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [Flask 安全最佳实践](https://flask.palletsprojects.com/en/stable/security/)
- [Werkzeug 密码哈希文档](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security)
