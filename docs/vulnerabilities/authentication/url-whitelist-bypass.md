---
id: URL-WHITELIST-BYPASS
name: URL 白名单绕过
severity: medium
owasp: "A01:2025"
cwe: ["CWE-20", "CWE-601"]
category: authentication
frameworks: [Spring Security, Servlet Filter, Nginx]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# URL 白名单绕过

> 最后更新：2026-04-17

## 概述

URL 白名单绕过是指攻击者利用 URL 解析差异、编码变体、路径规范化不一致等技巧，绕过基于 URL 的访问控制策略。常见于 Spring Security 的 `antMatchers()` 白名单配置、Nginx 反向代理的 location 规则、SSRF 防护的 URL 白名单等场景。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-20 (Improper Input Validation), CWE-601 (Open Redirect) |
| 严重程度 | 中危 |

## 攻击类型

### 1. 路径遍历绕过

```
# 白名单: /public/**
# 绕过：利用路径遍历
GET /public/../admin/dashboard HTTP/1.1

# 编码变体
GET /public/%2e%2e/admin/dashboard HTTP/1.1
GET /public/..;/admin/dashboard HTTP/1.1
```

### 2. URL 编码绕过

```
# 白名单: https://trusted.com
# 绕过：利用 URL 编码差异
https://trusted.com%00@evil.com       # 空字节截断
https://trusted.com@evil.com           # URL 认证信息绕过
https://evil.com?trusted.com           # 查询参数混淆
https://trusted.com.evil.com           # 子域名混淆
```

### 3. Spring Security antMatchers 绕过

```java
// [VULNERABLE] 白名单配置被绕过
http.authorizeRequests()
    .antMatchers("/public/**").permitAll()
    .anyRequest().authenticated();

// 绕过方式：
// GET /public/%2e%2e/admin  →  规范化后为 /public/../admin → /admin
// GET /public/..;/admin     →  Servlet 路径解析差异
```

### 4. 协议绕过

```
# 白名单: http(s)://
# 绕过：使用其他协议
gopher://internal-host:6379/          # Redis SSRF
file:///etc/passwd                    # 本地文件读取
dict://internal-host:6379/INFO        # Redis 信息泄露
```

### 5. 大小写绕过

```
# 白名单: /api/public
# 绕过：Windows/某些服务器不区分大小写
GET /API/PUBLIC/../admin HTTP/1.1
```

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 URL 白名单绕过漏洞，仅用于教学目的
// 漏洞类型：URL-WHITELIST-BYPASS
// 风险等级：medium
// 对应文档：docs/vulnerabilities/authentication/url-whitelist-bypass.md

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;

@Configuration
public class UrlWhitelistVulnerable extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            // [VULNERABLE] 使用 antMatchers 可能被路径遍历绕过
            .antMatchers("/public/**").permitAll()
            .antMatchers("/api/health").permitAll()
            .anyRequest().authenticated();
    }
}

// [VULNERABLE] SSRF 防护中的 URL 白名单
@RestController
@RequestMapping("/proxy")
public class SsrfProxyVulnerable {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "api.trusted.com",
        "cdn.trusted.com"
    );

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        try {
            // [VULNERABLE] 简单的字符串匹配，可被绕过
            URI uri = new URI(url);
            if (!ALLOWED_HOSTS.contains(uri.getHost())) {
                throw new SecurityException("Host not allowed");
            }
            // 但 URL 解析可能有差异
            // 绕过：http://api.trusted.com@evil.com
            // 绕过：http://evil.com#api.trusted.com
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder().uri(uri).build();
            return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 URL 白名单绕过漏洞的安全修复方案
// 修复方式：路径规范化 / 使用.mvcMatchers / 严格 URL 解析
// 对应文档：docs/vulnerabilities/authentication/url-whitelist-bypass.md

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;

@Configuration
public class UrlWhitelistSecure extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            // [SECURE] 使用 mvcMatchers 匹配 Servlet 路径（规范化后）
            .mvcMatchers("/public/**").permitAll()
            .mvcMatchers("/api/health").permitAll()
            .anyRequest().authenticated();
    }
}

// [SECURE] SSRF 防护中的严格 URL 校验
@RestController
@RequestMapping("/proxy")
public class SsrfProxySecure {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "api.trusted.com",
        "cdn.trusted.com"
    );

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        try {
            // [SECURE] 严格 URL 解析和校验
            URL parsedUrl = new URL(url);

            // 1. 仅允许 http/https 协议
            String protocol = parsedUrl.getProtocol().toLowerCase();
            if (!protocol.equals("http") && !protocol.equals("https")) {
                throw new SecurityException("Only HTTP/HTTPS allowed");
            }

            // 2. 精确匹配主机名（不允许子域名混淆）
            String host = parsedUrl.getHost().toLowerCase();
            if (!ALLOWED_HOSTS.contains(host)) {
                throw new SecurityException("Host not allowed: " + host);
            }

            // 3. 解析 IP 后检查是否为内网地址
            InetAddress address = InetAddress.getByName(host);
            if (address.isSiteLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isAnyLocalAddress()) {
                throw new SecurityException("Internal address not allowed");
            }

            // 4. 限制端口
            int port = parsedUrl.getPort();
            if (port != -1 && port != 80 && port != 443) {
                throw new SecurityException("Non-standard port not allowed");
            }

            // [SECURE] 重建 URL 防止解析差异
            URL safeUrl = new URL(protocol, host, port, parsedUrl.getPath());

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder().uri(safeUrl.toURI()).build();
            return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Invalid URL", e);
        }
    }
}
```

## 检测方法

1. **配置审计**：检查 Spring Security 的 URL 匹配器是否使用 `mvcMatchers` 而非 `antMatchers`
2. **动态测试**：使用路径遍历、URL 编码变体测试白名单绕过
3. **代码审计**：搜索 `antMatchers`、URL 白名单字符串匹配逻辑

**Semgrep 规则**：

```yaml
rules:
  - id: java-spring-antmatchers
    patterns:
      - pattern: |
          .antMatchers(...)
    message: |
      检测到使用 antMatchers()，可能存在 URL 白名单绕过风险。
      建议：使用 mvcMatchers() 替代，其路径匹配更精确。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: authentication
      cwe: CWE-20

  - id: java-url-whitelist-string-match
    patterns:
      - pattern: |
          $SET.contains($URI.getHost())
    message: |
      检测到简单的 hostname 字符串匹配做白名单，可能被 URL 编码/子域名混淆绕过。
      建议：增加协议校验、IP 内网检查、端口限制。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: authentication
      cwe: CWE-20
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 使用 `mvcMatchers` | Spring Security 中用 `mvcMatchers` 替代 `antMatchers` |
| P0 | URL 规范化 | 对 URL 先做规范化再进行白名单校验 |
| P1 | 协议白名单 | 仅允许 `http`/`https` 协议 |
| P1 | 精确主机名匹配 | 不使用通配符或 `contains`，使用精确匹配 |
| P1 | IP 内网检查 | 解析域名后检查 IP 是否为内网地址 |
| P2 | 端口限制 | 仅允许标准端口（80/443） |
| P2 | URL 重建 | 校验后重建 URL 防止解析差异 |

## 参考资料

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [Spring Security URL Matching](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [URL Parsing Differences](https://portswigger.net/research/url-parse-quandaries)
