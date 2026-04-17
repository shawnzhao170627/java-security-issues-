# CWE Top 25:2025 中文详解

> 最后更新：2026-04-17

## 概述

CWE Top 25 是由 MITRE 公司发布的最危险软件弱点排名，基于 NIST 国家漏洞数据库（NVD）中的 CVE 数据分析得出。

## 2025 版完整列表

| 排名 | CWE编号 | 名称 | 得分 |
|------|---------|------|------|
| 1 | CWE-79 | 跨站脚本 (XSS) | 60.38 |
| 2 | CWE-89 | SQL注入 | 28.72 |
| 3 | CWE-352 | 跨站请求伪造 (CSRF) | 13.64 |
| 4 | CWE-862 | 缺失授权 | 13.28 |
| 5 | CWE-787 | 越界写入 | 12.68 |
| 6 | CWE-22 | 路径遍历 | 8.99 |
| 7 | CWE-416 | 释放后使用 | 8.47 |
| 8 | CWE-125 | 越界读取 | 7.88 |
| 9 | CWE-78 | OS命令注入 | 7.85 |
| 10 | CWE-94 | 代码注入 | 7.57 |
| 11 | CWE-120 | 缓冲区溢出（经典） | 6.96 |
| 12 | CWE-434 | 危险类型文件上传 | 6.87 |
| 13 | CWE-476 | 空指针解引用 | 6.41 |
| 14 | CWE-121 | 栈缓冲区溢出 | 5.75 |
| 15 | CWE-502 | 不可信数据反序列化 | 5.23 |
| 16 | CWE-122 | 堆缓冲区溢出 | 5.21 |
| 17 | CWE-863 | 授权错误 | 4.14 |
| 18 | CWE-20 | 输入验证不当 | 4.09 |
| 19 | CWE-284 | 访问控制不当 | 4.07 |
| 20 | CWE-200 | 敏感信息泄露 | 4.01 |
| 21 | CWE-306 | 关键功能缺失认证 | 3.47 |
| 22 | CWE-918 | 服务端请求伪造 (SSRF) | 3.36 |
| 23 | CWE-77 | 命令注入 | 3.15 |
| 24 | CWE-639 | 用户控制键绕过授权 | 2.62 |
| 25 | CWE-770 | 资源分配无限制 | 2.54 |

---

## 详细说明

### Top 5 详解

#### 1. CWE-79: Cross-site Scripting (XSS)

**描述**：在生成网页时未能正确中和用户输入，导致恶意脚本被执行。

**Java 相关**：
```java
// 漏洞代码
response.getWriter().println("<div>" + userInput + "</div>");

// 安全代码
response.getWriter().println("<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>");
```

**防护措施**：
- 输出编码（HTML/JavaScript/URL/CDATA）
- 使用安全的模板引擎
- Content-Security-Policy 头

---

#### 2. CWE-89: SQL Injection

**描述**：用户输入被拼接到 SQL 命令中执行。

**Java 相关**：
```java
// 漏洞代码
String sql = "SELECT * FROM users WHERE id = " + userId;

// 安全代码
String sql = "SELECT * FROM users WHERE id = ?";
pstmt.setString(1, userId);
```

**防护措施**：
- 参数化查询
- 存储过程
- ORM 安全 API
- 最小权限原则

---

#### 3. CWE-352: Cross-Site Request Forgery (CSRF)

**描述**：攻击者诱使用户在已认证的 Web 应用中执行非预期操作。

**Java 相关**：
```java
// Spring Security CSRF 防护
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}
```

**防护措施**：
- CSRF Token
- SameSite Cookie
- 二次认证（关键操作）
- 检查 Referer 头

---

#### 4. CWE-862: Missing Authorization

**描述**：系统未能对用户操作进行适当的授权检查。

**Java 相关**：
```java
// 漏洞代码
@DeleteMapping("/user/{id}")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}

// 安全代码
@DeleteMapping("/user/{id}")
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}
```

**防护措施**：
- 基于角色的访问控制（RBAC）
- 每个接口都做权限校验
- 使用 Spring Security 等框架

---

#### 5. CWE-787: Out-of-bounds Write

**描述**：写入操作超出缓冲区边界，可能导致代码执行或数据损坏。

**注意**：这类问题在 Java 中相对较少（相比 C/C++），但在使用 JNI 或直接内存操作时仍可能发生。

---

### 与 Java 开发最相关的 CWE

| CWE | 名称 | Java 风险等级 | 说明 |
|-----|------|--------------|------|
| CWE-79 | XSS | 高 | JSP/模板引擎输出需编码 |
| CWE-89 | SQL注入 | 高 | JDBC/MyBatis/JPA 都需注意 |
| CWE-352 | CSRF | 高 | Spring Security 默认防护 |
| CWE-862 | 缺失授权 | 高 | 需在每个接口实现 |
| CWE-22 | 路径遍历 | 高 | 文件操作需校验路径 |
| CWE-434 | 危险文件上传 | 高 | 文件上传需严格校验 |
| CWE-502 | 反序列化 | 高 | Java 重灾区 |
| CWE-918 | SSRF | 中 | HTTP 客户端调用 |
| CWE-78 | 命令注入 | 中 | Runtime.exec() |
| CWE-200 | 敏感信息泄露 | 中 | 日志/错误信息 |

---

## 参考资料

- [CWE Top 25 官方页面](https://cwe.mitre.org/top25/)
- [CWE Top 25:2025 详细列表](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [NVD 国家漏洞数据库](https://nvd.nist.gov/)
