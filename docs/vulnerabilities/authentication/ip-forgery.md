---
id: IP-FORGERY
name: IP 伪造
severity: medium
owasp: "A01:2025"
cwe: ["CWE-290", "CWE-346"]
category: authentication
frameworks: [Servlet, Spring MVC, Nginx, Cloudflare]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# IP 伪造

> 最后更新：2026-04-17

## 概述

IP 伪造（IP Forgery / IP Spoofing）在 Web 应用场景中指攻击者通过伪造 HTTP 请求头（如 `X-Forwarded-For`、`X-Real-IP`、`X-Client-IP` 等）来欺骗服务端获取错误的客户端 IP 地址。如果应用基于 IP 做访问控制、速率限制、审计日志等安全决策，IP 伪造可导致安全绕过。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-290 (Authentication Bypass by Spoofing), CWE-346 (Origin Validation Error) |
| 严重程度 | 中危 |

## 攻击类型

### 1. X-Forwarded-For 伪造

```http
GET /api/admin/dashboard HTTP/1.1
Host: target.com
X-Forwarded-For: 10.0.0.1    # 伪造内网 IP
X-Real-IP: 10.0.0.1
```

### 2. 多层代理头注入

```
X-Forwarded-For: 10.0.0.1, 192.168.1.1, real-client-ip
# 攻击者在头部添加伪造 IP，如果服务端取第一个值则被欺骗
```

### 3. 绕过 IP 白名单

```http
# 正常请求被拒绝
GET /api/internal HTTP/1.1
X-Forwarded-For: public-ip

# 伪造为内网 IP 绕过
GET /api/internal HTTP/1.1
X-Forwarded-For: 192.168.1.100
```

### 4. 绕过速率限制

```http
# 每次请求使用不同的伪造 IP 绕过速率限制
GET /api/login HTTP/1.1
X-Forwarded-For: 1.2.3.4

GET /api/login HTTP/1.1
X-Forwarded-For: 5.6.7.8
```

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 IP 伪造漏洞，仅用于教学目的
// 漏洞类型：IP-FORGERY
// 风险等级：medium
// 对应文档：docs/vulnerabilities/authentication/ip-forgery.md

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;

@RestController
@RequestMapping("/api")
public class IpForgeryVulnerable {

    // [VULNERABLE] 直接读取 X-Forwarded-For 作为客户端 IP
    @GetMapping("/admin/dashboard")
    public String adminDashboard(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (isAdminIp(clientIp)) {
            return "admin dashboard";
        }
        return "access denied";
    }

    // [VULNERABLE] 用 IP 做速率限制，但 IP 可被伪造
    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (rateLimitExceeded(clientIp)) {
            return "rate limited";
        }
        // 认证逻辑...
        return "login result";
    }

    // [VULNERABLE] 使用不可靠的工具方法获取 IP
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null) ip = request.getHeader("X-Real-IP");
        if (ip == null) ip = request.getHeader("X-Client-IP");
        if (ip == null) ip = request.getRemoteAddr();
        return ip; // 优先取请求头，容易被伪造
    }

    private boolean isAdminIp(String ip) {
        return ip != null && ip.startsWith("192.168.");
    }

    private boolean rateLimitExceeded(String ip) {
        // 简化示例
        return false;
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 IP 伪造漏洞的安全修复方案
// 修复方式：可信代理链验证 / 取最右侧 IP / 不依赖 IP 做关键安全决策
// 对应文档：docs/vulnerabilities/authentication/ip-forgery.md

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.*;

@RestController
@RequestMapping("/api")
public class IpForgerySecure {

    // [SECURE] 方案1：配置可信代理列表，从可信代理链中取真实 IP
    private static final java.util.Set<String> TRUSTED_PROXIES = java.util.Set.of(
        "10.0.0.1",    // Nginx 代理
        "10.0.0.2"     // CDN 节点
    );

    // [SECURE] 方案2：取 X-Forwarded-For 最右侧的可信 IP
    private String getRealClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");

        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            // 从右向左遍历，找到第一个非可信代理的 IP
            String[] ips = forwardedFor.split(",");
            for (int i = ips.length - 1; i >= 0; i--) {
                String ip = ips[i].trim();
                if (!TRUSTED_PROXIES.contains(ip)) {
                    return ip; // 这是真实客户端 IP
                }
            }
        }

        // 没有经过代理，直接取 remote addr
        return request.getRemoteAddr();
    }

    // [SECURE] 方案3：不依赖 IP 做关键安全决策
    @GetMapping("/admin/dashboard")
    public String adminDashboard(HttpServletRequest request) {
        // [SECURE] 用认证而非 IP 白名单做访问控制
        // IP 白名单仅作为额外防御层，不作为主要安全措施
        return "admin dashboard"; // 依赖 Spring Security 认证
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest request) {
        // [SECURE] 使用不可伪造的 remoteAddr 做基础速率限制
        String clientIp = request.getRemoteAddr();
        // 补充：如果使用反向代理，确保代理层配置了速率限制
        // 应用层的 IP 限制仅作为补充
        return "login result";
    }
}
```

### Nginx 配置参考

```nginx
# [SECURE] 在反向代理层配置真实 IP
server {
    # 设置可信代理
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;

    # 使用最右侧的 X-Forwarded-For 作为真实 IP
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    # 速率限制
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    location /api/login {
        limit_req zone=login burst=3;
        proxy_pass http://backend;
    }
}
```

## 检测方法

1. **代码审计**：搜索 `getHeader("X-Forwarded-For")`、`getHeader("X-Real-IP")` 用法
2. **动态测试**：在请求中添加伪造的 `X-Forwarded-For` 测试 IP 限制绕过
3. **配置审计**：检查反向代理是否正确配置 `set_real_ip_from`

**Semgrep 规则**：

```yaml
rules:
  - id: java-ip-forgery-xforwardedfor
    patterns:
      - pattern: |
          $REQ.getHeader("X-Forwarded-For")
    message: |
      检测到直接读取 X-Forwarded-For 请求头获取客户端 IP，该头可被客户端伪造。
      建议：使用 request.getRemoteAddr() 或配置可信代理链验证。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: authentication
      cwe: CWE-290

  - id: java-ip-forgery-xrealip
    patterns:
      - pattern: |
          $REQ.getHeader("X-Real-IP")
    message: |
      检测到读取 X-Real-IP 请求头获取客户端 IP，该头可被伪造。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: authentication
      cwe: CWE-290
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 不依赖 IP 做关键安全决策 | 访问控制应基于认证，IP 仅作辅助 |
| P0 | 代理层配置真实 IP | Nginx/Apache 配置 `set_real_ip_from` |
| P1 | 可信代理链验证 | 从右向左遍历 X-Forwarded-For 取真实 IP |
| P1 | 速率限制在代理层 | Nginx/Cloudflare 层做速率限制更可靠 |
| P2 | 使用 `request.getRemoteAddr()` | 直接取 TCP 连接 IP，不可被 HTTP 头伪造 |
| P2 | 日志记录原始 IP | 同时记录 remoteAddr 和 X-Forwarded-For 便于审计 |

## 参考资料

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [Nginx Real IP Module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [OWASP IP Spoofing](https://owasp.org/www-community/attacks/IP_Spoofing)
