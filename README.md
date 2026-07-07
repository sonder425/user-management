# 用户管理系统 — 安全审计项目

> 从一份"故意有漏洞"的 Flask 代码出发，完成：  
> **漏洞发现 → 漏洞分析 → 漏洞修复 → 报告输出** 的完整安全实践。

---

## 项目结构

```
user-management-security/
├── README.md                          ← 本文件 · 项目说明
├── docs/
│   └── 漏洞修复报告.md                 ← 完整的漏洞分析与修复方案
│
├── original/                          ← 原始漏洞版（来源）
│   └── app.py、templates/、static/
│
└── patched_app/                       ← 安全加固版
    ├── app.py                         ← 修复全部漏洞后的代码
    ├── templates/
    │   ├── base.html
    │   ├── login.html
    │   └── index.html
    └── static/
        └── css/style.css
```

---

## 发现的漏洞（共 11 个）

| 编号 | 漏洞 | 等级 |
|------|------|------|
| V-001 | 密码明文存储 | 🔴 严重 |
| V-002 | 密码明文显示在前端 | 🔴 严重 |
| V-003 | 硬编码弱密钥 | 🔴 高危 |
| V-004 | HTML 注释泄露管理员账号 | 🟠 中危 |
| V-005 | 无 Session 安全配置 | 🟠 中危 |
| V-006 | 无 CSRF 保护 | 🟠 中危 |
| V-007 | 无登录频率限制（可爆破） | 🟠 中危 |
| V-008 | Debug 模式开启 | 🟠 中危 |
| V-009 | Session 固定攻击 | 🟢 低危 |
| V-010 | 无 HTTPS 传输 | 🟢 低危 |
| V-011 | Debugger PIN 泄露 | 🟢 低危 |

---

## 修复措施一览

| 措施 | 涉及漏洞 |
|------|---------|
| ✅ Werkzeug 密码哈希（`generate_password_hash`） | V-001 |
| ✅ 删除模板中的密码显示行 | V-002 |
| ✅ 环境变量密钥 + 随机回退 | V-003 |
| ✅ 删除 HTML 调试注释 | V-004 |
| ✅ Session 安全配置（HttpOnly/SameSite） | V-005 |
| ✅ Flask-WTF CSRF 保护 | V-006 |
| ✅ Flask-Limiter 登录频率限制 | V-007 |
| ✅ 关闭 debug 模式 | V-008 |
| ✅ 登录后 session.regenerate() | V-009 |

---

## 环境依赖

```bash
cd patched_app
pip install flask flask-wtf flask-limiter
python app.py
```

---

## 参考资料

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [Flask 安全最佳实践](https://flask.palletsprojects.com/en/stable/security/)
- [Werkzeug 密码哈希文档](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security)
