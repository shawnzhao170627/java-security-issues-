---
id: CRLF-INJECTION
name: CRLF 注入
severity: medium
owasp: "A05:2025"
cwe: ["CWE-74", "CWE-113"]
category: injection
frameworks: [HTTP, Servlet, Spring MVC]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# CRLF 注入

> 最后更新：2026-04-17

## 概述

CRLF（Carriage Return + Line Feed，`\r\n`）注入是指攻击者在 HTTP 请求中插入 `\r\n` 字符，从而分割 HTTP 头部或注入额外的 HTTP 响应头。可导致 HTTP 响应拆分（HTTP Response Splitting）、日志注入（Log Injection）、邮件头注入等安全问题。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Security Misconfiguration |
| CWE | CWE-74 (Injection), CWE-113 (HTTP Response Splitting) |
| 严重程度 | 中危 |

## 攻击类型

### 1. HTTP 响应拆分

用户输入被拼接到 HTTP 响应头中，攻击者注入 `\r\n` 分割响应：

```
# 正常请求
GET /redirect?url=/home HTTP/1.1

# 恶意请求 - 注入额外响应头和响应体
GET /redirect?url=/home%0d%0aSet-Cookie:%20session=attacker-controlled HTTP/1.1

# 更严重的攻击 - 注入完整响应
GET /redirect?url=/home%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>malicious</html>
```

### 2. 日志注入

在用户输入中插入 `\r\n` 伪造日志条目：

```
# 正常输入
username=admin

# 恶意输入 - 伪造日志条目
username=admin%0d%0a[ERROR]%20User%20login%20failed%20from%20192.168.1.100
```

### 3. 邮件头注入

在邮件表单中注入 CRLF，添加额外收件人或修改邮件内容：

```
# 恶意输入
email=test@example.com%0d%0aBcc:%20victim@target.com%0d%0a%0d%0aMalicious%20content
```

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 CRLF 注入漏洞，仅用于教学目的
// 漏洞类型：CRLF-INJECTION
// 风险等级：medium
// 对应文档：docs/vulnerabilities/injection/crlf-injection.md

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;

@RestController
@RequestMapping("/api")
public class CrlfVulnerable {

    // [VULNERABLE] 用户输入拼接到响应头
    @GetMapping("/redirect")
    public String redirect(@RequestParam String url, HttpServletResponse response)
            throws Exception {
        // 用户输入直接设置到 Header 中
        response.setHeader("X-Redirect-Url", url); // CRLF 注入
        response.sendRedirect(url);
        return "redirecting...";
    }

    // [VULNERABLE] 用户输入写入日志，未过滤 CRLF
    @PostMapping("/login")
    public String login(@RequestParam String username, HttpServletRequest request) {
        // 日志注入：攻击者可伪造日志条目
        System.out.println("User login: " + username + " from " + request.getRemoteAddr());
        return "login processed";
    }

    // [VULNERABLE] 用户输入拼接到 Cookie 值中
    @GetMapping("/set-preference")
    public String setPreference(@RequestParam String theme, HttpServletResponse response) {
        // Cookie 值包含 CRLF 可注入额外 Set-Cookie 头
        response.setHeader("Set-Cookie", "theme=" + theme); // CRLF 注入
        return "preference set";
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 CRLF 注入漏洞的安全修复方案
// 修复方式：CRLF 过滤 / URL 编码 / 输入验证
// 对应文档：docs/vulnerabilities/injection/crlf-injection.md

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api")
public class CrlfSecure {

    // [SECURE] 方案1：过滤 CRLF 字符
    private String sanitizeCrlf(String input) {
        if (input == null) return null;
        // 移除所有 CR 和 LF 字符
        return input.replaceAll("[\r\n]", "");
    }

    // [SECURE] 方案2：使用 URL 编码
    private String encodeForHeader(String input) {
        return URLEncoder.encode(input, StandardCharsets.UTF_8);
    }

    // [SECURE] 重定向使用白名单
    private static final java.util.Set<String> ALLOWED_REDIRECTS = java.util.Set.of(
        "/home", "/dashboard", "/profile"
    );

    @GetMapping("/redirect")
    public String redirect(@RequestParam String url, HttpServletResponse response) {
        // [SECURE] 使用重定向白名单
        if (!ALLOWED_REDIRECTS.contains(url)) {
            throw new IllegalArgumentException("Invalid redirect URL");
        }
        // URL 已在白名单中，安全使用
        try {
            response.sendRedirect(url);
        } catch (Exception e) {
            throw new RuntimeException("Redirect failed", e);
        }
        return "redirecting...";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username) {
        // [SECURE] 日志输出前过滤 CRLF
        String safeUsername = sanitizeCrlf(username);
        System.out.println("User login: " + safeUsername);
        return "login processed";
    }

    @GetMapping("/set-preference")
    public String setPreference(@RequestParam String theme, HttpServletResponse response) {
        // [SECURE] 使用 Spring 的 Cookie 类而非手动拼接头
        Cookie cookie = new Cookie("theme", sanitizeCrlf(theme));
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        return "preference set";
    }
}
```

## 检测方法

1. **静态分析**：搜索 `response.setHeader()`、`response.addHeader()` 中使用用户输入
2. **动态测试**：在参数中注入 `%0d%0a` 测试响应头是否被分割
3. **日志审计**：检查日志是否包含异常的换行和伪造条目

**Semgrep 规则**：

```yaml
rules:
  - id: java-crlf-header-injection
    patterns:
      - pattern: |
          $RESP.setHeader($HEADER, $INPUT)
      - pattern-not: |
          $RESP.setHeader("...", "...")
    message: |
      检测到 HTTP 响应头设置中使用非常量值，可能存在 CRLF 注入风险。
      建议：过滤用户输入中的 \r\n 字符，或使用 URL 编码。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: injection
      cwe: CWE-113

  - id: java-crlf-redirect
    patterns:
      - pattern: |
          $RESP.sendRedirect($INPUT)
      - pattern-not: |
          $RESP.sendRedirect("...")
    message: |
      检测到 sendRedirect 使用非常量参数，可能存在 CRLF 注入和开放重定向风险。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: injection
      cwe: CWE-113
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 过滤 CRLF 字符 | 在所有用户输入拼接到 Header/Cookie 前移除 `\r\n` |
| P0 | 重定向白名单 | 使用白名单验证重定向目标 |
| P1 | URL 编码 | 对输出到响应头的值进行 URL 编码 |
| P1 | 使用安全 API | 使用 `Cookie` 类而非手动拼接 `Set-Cookie` 头 |
| P2 | 日志框架配置 | 使用结构化日志，避免 CRLF 影响日志完整性 |
| P2 | WAF 规则 | 在入口处拦截含 `%0d%0a` 的请求参数 |

## 参考资料

- [CWE-113: HTTP Response Splitting](https://cwe.mitre.org/data/definitions/113.html)
- [CWE-74: Injection](https://cwe.mitre.org/data/definitions/74.html)
- [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [Spring Security Header Writers](https://docs.spring.io/spring-security/reference/servlet/headers/)
