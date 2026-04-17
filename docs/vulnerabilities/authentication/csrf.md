---
id: CSRF
name: 跨站请求伪造
severity: high
owasp: "A01:2025"
cwe: ["CWE-352"]
category: authentication
frameworks: [Spring Security, Spring MVC, Servlet]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# 跨站请求伪造（CSRF）

> 最后更新：2026-04-17

## 概述

跨站请求伪造（Cross-Site Request Forgery，CSRF）是指攻击者诱导已登录用户的浏览器向目标网站发送恶意请求，利用用户已认证的身份执行非预期操作（如转账、改密码、删除数据）。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-352 |
| 严重程度 | 高危 |

## 攻击类型

| 类型 | 说明 |
|------|------|
| GET 型 CSRF | 敏感操作用 GET 请求，攻击者用 `<img src="...">` 触发 |
| POST 型 CSRF | 攻击者构造自动提交的 HTML 表单 |
| JSON CSRF | Content-Type 为 `text/plain` 绕过同源限制 |
| Flash CSRF | 利用 Flash 发送跨域请求（已基本消亡） |

## Java 场景

### 未启用 CSRF 防护

```java
// [VULNERABLE] Spring Security 关闭了 CSRF 保护
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .csrf(csrf -> csrf.disable()); // 危险：完全禁用 CSRF 保护
        return http.build();
    }
}
```

```java
// [VULNERABLE] 敏感操作使用 GET 请求
@GetMapping("/transfer")
public String transfer(@RequestParam String toAccount,
                       @RequestParam BigDecimal amount,
                       Principal principal) {
    // 危险：转账操作使用 GET，攻击者可构造链接诱导点击
    accountService.transfer(principal.getName(), toAccount, amount);
    return "转账成功";
}
// 攻击：<img src="https://bank.com/transfer?toAccount=evil&amount=10000">
```

```java
// [SECURE] Spring Security 默认启用 CSRF，前端传递 Token
@Configuration
@EnableWebSecurity
public class SecureSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            // 默认启用 CSRF，使用 CookieCsrfTokenRepository 支持前后端分离
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        return http.build();
    }
}
```

### 前后端分离场景

```java
// [VULNERABLE] REST API 未校验 CSRF Token
@RestController
public class UserController {

    @PostMapping("/api/user/password")
    public ResponseEntity<?> changePassword(@RequestBody PasswordRequest req,
                                            Principal principal) {
        // 危险：仅凭 Cookie 中的 Session 认证，无 CSRF Token 校验
        userService.changePassword(principal.getName(), req.getNewPassword());
        return ResponseEntity.ok().build();
    }
}
```

```java
// [SECURE] 前后端分离使用双重提交 Cookie 模式
@Configuration
public class CsrfConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf
            // 将 CSRF token 写入 Cookie，前端从 Cookie 读取并放入请求头
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            // 忽略不需要 CSRF 保护的端点（如 OAuth 回调）
            .ignoringRequestMatchers("/oauth/**")
        );
        return http.build();
    }
}

// 前端 JavaScript（示例）：
// const csrfToken = document.cookie.match(/XSRF-TOKEN=([^;]+)/)[1];
// fetch('/api/user/password', {
//   method: 'POST',
//   headers: { 'X-XSRF-TOKEN': csrfToken },
//   body: JSON.stringify({ newPassword: '...' })
// });
```

### REST API CSRF 防护

```java
// [SECURE] 纯 API 服务使用 SameSite Cookie + 检查 Origin/Referer
@Configuration
public class ApiSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Stateless API 可使用 JWT + 检查 Origin Header 替代 CSRF Token
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable()) // 无状态 JWT API 可禁用
            .addFilterBefore(new OriginCheckFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

// Origin 来源校验过滤器
public class OriginCheckFilter extends OncePerRequestFilter {

    private static final Set<String> ALLOWED_ORIGINS = Set.of(
        "https://app.example.com",
        "https://www.example.com"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!isSafeMethod(request.getMethod())) {
            String origin = request.getHeader("Origin");
            if (origin != null && !ALLOWED_ORIGINS.contains(origin)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "非法来源");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean isSafeMethod(String method) {
        return "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
    }
}
```

## 检测方法

1. **检查 Spring Security 配置**：确认未调用 `csrf.disable()`
2. **测试敏感操作**：删除请求中的 CSRF Token，观察是否仍成功执行
3. **检查 Cookie 属性**：确认 `SameSite=Strict` 或 `SameSite=Lax`

## 防护措施

1. **启用 Spring Security CSRF 保护**（默认已启用，不要关闭）
2. **敏感操作使用 POST/PUT/DELETE**，不用 GET
3. **前后端分离使用 `CookieCsrfTokenRepository`**
4. **设置 Cookie `SameSite=Strict`**
5. **校验 `Origin` 或 `Referer` 请求头**
6. **无状态 API 使用 JWT + Origin 校验**

## 参考资料

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: CSRF](https://cwe.mitre.org/data/definitions/352.html)
- [Spring Security CSRF](https://docs.spring.io/spring-security/reference/features/exploits/csrf.html)
