---
id: OPEN-REDIRECT
name: URL 开放重定向
severity: medium
owasp: "A01:2025"
cwe: ["CWE-601"]
category: injection
frameworks: [Spring MVC, HttpServletResponse, Spring Security]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# URL 开放重定向

> 最后更新：2026-04-17

## 概述

开放重定向（Open Redirect）是指应用程序将用户重定向到未经验证的外部 URL，攻击者可利用此漏洞构造钓鱼链接，使受害者以为访问的是合法网站，实则被引导至恶意站点。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-601 |
| 严重程度 | 中危 |

## 攻击类型

| 类型 | 说明 |
|------|------|
| 直接重定向 | `redirect?url=https://evil.com` |
| 绕过白名单 | 利用 URL 解析差异绕过域名校验 |
| 协议混淆 | `//evil.com`（协议相对 URL） |
| 参数污染 | `?url=good.com&url=evil.com` |

## Java 场景

### Spring MVC 直接重定向

```java
// [VULNERABLE] 直接使用用户提供的 URL 进行重定向
@GetMapping("/redirect")
public void redirect(@RequestParam String url, HttpServletResponse response)
        throws IOException {
    // 危险：未校验 url 参数，可重定向到任意外部地址
    response.sendRedirect(url);
}

// 攻击：/redirect?url=https://evil.com/phishing
// 钓鱼链接：https://bank.com/redirect?url=https://evil.com/login
```

```java
// [SECURE] 白名单校验目标域名
@GetMapping("/redirect")
public void redirect(@RequestParam String url, HttpServletResponse response)
        throws IOException {
    if (!isSafeUrl(url)) {
        response.sendRedirect("/error/invalid-redirect");
        return;
    }
    response.sendRedirect(url);
}

private static final Set<String> ALLOWED_HOSTS = Set.of(
    "www.example.com",
    "app.example.com",
    "docs.example.com"
);

private boolean isSafeUrl(String url) {
    try {
        URI uri = new URI(url);
        String host = uri.getHost();
        // 只允许相对路径或白名单域名
        if (host == null) {
            // 相对路径，安全
            return url.startsWith("/") && !url.startsWith("//");
        }
        return ALLOWED_HOSTS.contains(host.toLowerCase());
    } catch (URISyntaxException e) {
        return false;
    }
}
```

### Spring Security 登录后重定向

```java
// [VULNERABLE] 登录成功后直接重定向到用户指定的 returnUrl
@PostMapping("/login")
public String login(@RequestParam String username,
                    @RequestParam String password,
                    @RequestParam(required = false) String returnUrl) {
    if (authService.authenticate(username, password)) {
        // 危险：returnUrl 未校验，登录后可跳到攻击者的钓鱼页
        return "redirect:" + returnUrl;
    }
    return "redirect:/login?error";
}
// 攻击：/login?returnUrl=https://evil.com
```

```java
// [SECURE] 登录后重定向仅允许相对路径
@PostMapping("/login")
public String login(@RequestParam String username,
                    @RequestParam String password,
                    @RequestParam(required = false) String returnUrl,
                    HttpServletRequest request) {
    if (authService.authenticate(username, password)) {
        String safeUrl = getSafeReturnUrl(returnUrl, request);
        return "redirect:" + safeUrl;
    }
    return "redirect:/login?error";
}

private String getSafeReturnUrl(String returnUrl, HttpServletRequest request) {
    if (returnUrl == null || returnUrl.isBlank()) {
        return "/dashboard";
    }
    // 只允许相对路径，不允许协议相对 URL（//evil.com）
    if (returnUrl.startsWith("/") && !returnUrl.startsWith("//")) {
        return returnUrl;
    }
    // 同域绝对路径校验
    try {
        URI uri = new URI(returnUrl);
        String requestHost = request.getServerName();
        if (requestHost.equals(uri.getHost())) {
            return returnUrl;
        }
    } catch (URISyntaxException ignored) {}

    return "/dashboard";
}
```

### URL 解析绕过防护

```java
// [VULNERABLE] 仅检查 URL 是否包含合法域名，可被绕过
private boolean isAllowed(String url) {
    // 危险：contains 检查可被绕过
    // 攻击：https://evil.com?redirect=example.com
    //       https://example.com.evil.com
    return url.contains("example.com");
}
```

```java
// [SECURE] 严格解析 URL 的 host 部分
private boolean isAllowed(String url) {
    try {
        URI uri = URI.create(url);
        String host = uri.getHost();
        if (host == null) return false;
        // 精确匹配 host，防止子域名欺骗
        return host.equals("example.com") || host.endsWith(".example.com");
    } catch (IllegalArgumentException e) {
        return false;
    }
}
```

## 检测方法

1. **搜索关键词**：`sendRedirect(`、`"redirect:"` + 用户输入拼接
2. **测试**：修改 `url`/`redirect`/`return` 参数为外部域名，观察是否跳转
3. **绕过测试**：尝试 `//evil.com`、`https://evil.com@example.com`

## 防护措施

1. **避免用户控制重定向目标**：优先用固定跳转逻辑
2. **白名单域名校验**：使用 `URI.getHost()` 精确匹配，不用 `contains`
3. **只允许相对路径**：`returnUrl` 只接受 `/` 开头且不以 `//` 开头的路径
4. **Spring Security 配置**：使用 `DefaultRedirectStrategy` 并设置 `contextRelative=true`

## 参考资料

- [OWASP Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
