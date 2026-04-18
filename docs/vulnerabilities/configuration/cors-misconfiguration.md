---
id: CORS-MISCONFIGURATION
name: CORS 配置错误
severity: high
owasp: "A05:2025"
cwe: ["CWE-942", "CWE-346"]
category: configuration
frameworks: [Spring MVC, Spring Boot, Spring Security, Servlet]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# CORS 配置错误

> 最后更新：2026-04-17

## 概述

跨域资源共享（Cross-Origin Resource Sharing，CORS）配置错误会导致恶意网站可以访问目标 API，造成敏感数据泄露。常见错误包括：信任任意来源、动态反射 Origin、忽略 `null` Origin 等。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Security Misconfiguration |
| CWE | CWE-942 / CWE-346 |
| 严重程度 | 高危 |

## 攻击类型

| 类型 | 说明 |
|------|------|
| 通配符 + 凭证 | `Access-Control-Allow-Origin: *` 同时允许携带 Cookie |
| 动态反射 Origin | 直接将请求的 Origin 回显，无白名单校验 |
| `null` Origin 信任 | 信任 `null` Origin，沙箱 iframe 可利用 |
| 子域名信任过宽 | 允许 `*.example.com`，攻击者控制子域即可利用 |

## Java 场景

### Spring MVC 全局 CORS 配置错误

```java
// [VULNERABLE] 允许所有来源且允许携带凭证
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("*")           // 危险：允许任意来源
            .allowCredentials(true)        // 危险：允许凭证（与 * 组合无效，但配置意图危险）
            .allowedMethods("*");
    }
}
```

```java
// [VULNERABLE] 动态反射 Origin，无白名单
@Component
public class CorsFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // 危险：直接将请求的 Origin 回写，任何来源都被信任
        String origin = request.getHeader("Origin");
        response.setHeader("Access-Control-Allow-Origin", origin);
        response.setHeader("Access-Control-Allow-Credentials", "true");

        chain.doFilter(req, res);
    }
}
```

```java
// [SECURE] 严格白名单校验
@Configuration
public class SecureWebConfig implements WebMvcConfigurer {

    private static final List<String> ALLOWED_ORIGINS = List.of(
        "https://app.example.com",
        "https://www.example.com"
    );

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins(ALLOWED_ORIGINS.toArray(new String[0]))
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowedHeaders("Authorization", "Content-Type", "X-XSRF-TOKEN")
            .allowCredentials(true)         // 凭证仅对白名单域名有效
            .maxAge(3600);
    }
}
```

### Spring Security CORS 配置

```java
// [VULNERABLE] Spring Security 中错误配置 CORS
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.cors(cors -> cors.configurationSource(request -> {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("*");  // 危险：通配符
        config.addAllowedMethod("*");
        config.setAllowCredentials(true); // 危险：* 与凭证组合会被浏览器拒绝，但体现不安全意图
        return config;
    }));
    return http.build();
}
```

```java
// [SECURE] Spring Security 集成严格 CORS
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of(
        "https://app.example.com",
        "https://www.example.com"
    ));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setAllowCredentials(true);
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
    return http.build();
}
```

### 动态 Origin 白名单（正确实现）

```java
// [SECURE] 需要动态校验时，使用精确匹配
@Component
public class StrictCorsFilter extends OncePerRequestFilter {

    private static final Set<String> ALLOWED_ORIGINS = Set.of(
        "https://app.example.com",
        "https://www.example.com"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String origin = request.getHeader("Origin");

        if (origin != null && ALLOWED_ORIGINS.contains(origin)) {
            // 安全：仅对白名单 Origin 设置响应头
            response.setHeader("Access-Control-Allow-Origin", origin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Vary", "Origin"); // 必须设置 Vary，防止缓存污染
        }

        if ("OPTIONS".equals(request.getMethod())) {
            response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
            response.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type");
            response.setHeader("Access-Control-Max-Age", "3600");
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        chain.doFilter(request, response);
    }
}
```

## 检测方法

1. **发送跨域请求**：在请求中添加 `Origin: https://evil.com`，检查响应头
2. **测试 null Origin**：`Origin: null`，观察是否被信任
3. **检查配置**：搜索 `allowedOrigins("*")`、`addAllowedOrigin("*")`

## 防护措施

1. **明确白名单**：不使用 `*`，列出具体允许的域名
2. **设置 `Vary: Origin`**：防止 CORS 响应被缓存并用于其他 Origin
3. **不信任 `null` Origin**：沙箱 iframe 和本地文件会发送 `null`
4. **凭证与来源配合**：`allowCredentials(true)` 必须配合明确的 Origin，不能与 `*` 同用
5. **限制 HTTP 方法**：只允许必要的方法，不使用 `*`

## 参考资料

- [OWASP CORS Security](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [CWE-942: Overly Permissive CORS Policy](https://cwe.mitre.org/data/definitions/942.html)
- [PortSwigger CORS Vulnerabilities](https://portswigger.net/web-security/cors)
