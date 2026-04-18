---
id: AUTHENTICATION-BYPASS
name: 身份认证绕过
severity: critical
owasp: "A07:2025"
cwe: ["CWE-287", "CWE-306"]
category: authentication
frameworks: [Spring Security, Shiro, JWT, OAuth2]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 身份认证绕过

> 最后更新：2026-04-18

## 概述

身份认证绕过（Authentication Bypass）是指攻击者通过各种手段绕过系统的身份验证机制，未经授权地访问受保护资源。这是最严重的安全问题之一，可导致系统被完全控制。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A07:2025 - Authentication Failures |
| CWE | CWE-287 / CWE-306 |
| 严重程度 | 严重 |

## 攻击类型

| 攻击方式 | 说明 | 危害 |
|---------|------|------|
| 默认凭证 | 使用默认用户名/密码登录 | 未授权访问 |
| Session 固定 | 强制用户使用攻击者指定的 Session ID | 会话劫持 |
| 认证逻辑绕过 | 利用逻辑缺陷跳过认证步骤 | 未授权访问 |
| 密码暴力破解 | 无限制地尝试密码 | 账户接管 |
| 多因素认证绕过 | 绕过 MFA 验证步骤 | 账户接管 |

## Java 场景

### 认证逻辑缺陷

```java
// [VULNERABLE] 认证逻辑可被绕过
@PostMapping("/login")
public String login(String username, String password, HttpSession session) {
    User user = userService.findByUsername(username);
    // 危险：当用户不存在时未正确处理，可能绕过认证
    if (user != null && user.getPassword().equals(password)) {
        session.setAttribute("user", user);
    }
    // 危险：无论认证是否成功都重定向到首页，仅靠前端判断
    return "redirect:/home";
}
```

```java
// [SECURE] 严格的认证逻辑
@PostMapping("/login")
public String login(String username, String password, HttpSession session) {
    User user = userService.findByUsername(username);
    if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
        // 安全：认证失败时拒绝访问
        return "redirect:/login?error";
    }
    session.setAttribute("user", user);
    // 安全：重新生成 Session ID，防止 Session 固定攻击
    session.invalidate();
    return "redirect:/home";
}
```

### Spring Security 配置遗漏

```java
// [VULNERABLE] 忽略了关键路径的认证
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/public/**").permitAll()
        // 危险：/api/admin/** 未被任何规则匹配，可能默认放行
        .anyRequest().authenticated()
    );
    return http.build();
}
```

```java
// [SECURE] 明确配置所有路径权限
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/public/**").permitAll()
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()
    )
    .sessionManagement(session -> session
        .sessionFixation().migrateSession()  // 防止 Session 固定
        .maximumSessions(1)                  // 限制并发会话
    );
    return http.build();
}
```

### Remember-Me 不安全实现

```java
// [VULNERABLE] 不安全的 Remember-Me 实现
@PostMapping("/login")
public String login(@RequestParam(required = false) String rememberMe,
                    HttpServletResponse response) {
    // 危险：使用可预测的 Cookie 值
    Cookie cookie = new Cookie("remember", userId + ":" + username);
    cookie.setMaxAge(365 * 24 * 3600);
    response.addCookie(cookie);
    return "redirect:/home";
}
```

```java
// [SECURE] 使用 Spring Security 内置的 Remember-Me 机制
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.rememberMe(remember -> remember
        .key("uniqueAndSecret")           // 安全的签名密钥
        .tokenValiditySeconds(86400)      // 合理的有效期
        .userDetailsService(userDetailsService)
    );
    return http.build();
}
```

## 检测方法

1. **静态分析**：检查认证逻辑是否完整、是否存在跳过认证的路径
2. **渗透测试**：尝试使用错误凭证访问受保护接口
3. **Session 测试**：测试 Session 固定、并发会话等场景
4. **配置审计**：审查 Spring Security/Shiro 过滤链配置

## 防护措施

1. **使用成熟框架**：优先使用 Spring Security、Shiro 等经过验证的框架
2. **密码安全存储**：使用 BCrypt 等强哈希算法存储密码
3. **MFA 多因素认证**：对敏感操作启用多因素认证
4. **登录保护**：限制登录失败次数、启用账户锁定机制
5. **Session 安全**：登录后重新生成 Session ID，设置合理的超时时间
6. **默认拒绝**：所有接口默认需要认证，显式标记公开接口

## 参考资料

- [OWASP Authentication Bypass](https://owasp.org/www-community/attacks/Authentication_Bypass)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [Spring Security Authentication](https://docs.spring.io/spring-security/reference/authentication.html)
