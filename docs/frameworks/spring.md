# Spring 框架安全

> 最后更新：2026-04-17

## 概述

Spring 是 Java 生态中最流行的框架之一，其安全问题影响面广。本文档整理 Spring 框架相关的安全问题。

## 历史漏洞

### Spring4Shell (CVE-2022-22965)

| 属性 | 值 |
|------|------|
| CVE | CVE-2022-22965 |
| 影响版本 | Spring Framework 5.3.0 - 5.3.17, 5.2.0 - 5.2.19 |
| 严重程度 | 严重 |
| 利用条件 | JDK 9+、Tomcat 容器、WAR 包部署 |

**漏洞原理**：利用 JDK 9+ 的模块访问特性，通过类加载器修改 Tomcat 的 AccessLogValve，写入恶意 JSP 文件。

**检测方法**：
```bash
# 检测 Spring 版本
curl -s http://target/actuator/info | jq '.version'

# 使用检测工具
python spring4shell_scanner.py -u http://target
```

**修复措施**：
```xml
<!-- 升级 Spring 到安全版本 -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-framework-bom</artifactId>
    <version>5.3.18+</version>
</dependency>
```

```java
// 临时修复：禁用 data binding
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setDisallowedFields("class.*", "classLoader", "context");
}
```

---

### Spring Cloud Function SpEL 注入 (CVE-2022-22963)

| 属性 | 值 |
|------|------|
| CVE | CVE-2022-22963 |
| 影响版本 | Spring Cloud Function 3.1.6 及之前, 3.2.1 及之前 |
| 严重程度 | 严重 |

**漏洞原理**：通过 `spring.cloud.function.routing-expression` 头注入 SpEL 表达式执行任意代码。

**攻击示例**：
```http
POST /functionRouter HTTP/1.1
spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")
```

**修复措施**：
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-function-context</artifactId>
    <version>3.1.7+</version>
</dependency>
```

---

### Spring Cloud Gateway RCE (CVE-2022-22947)

| 属性 | 值 |
|------|------|
| CVE | CVE-2022-22947 |
| 影响版本 | Spring Cloud Gateway 3.1.0, 3.0.0 - 3.0.6 |
| 严重程度 | 严重 |

**漏洞原理**：通过 Actuator 端点注入恶意路由配置，利用 SpEL 表达式执行任意代码。

**攻击示例**：
```http
POST /actuator/gateway/routes/newroute HTTP/1.1
Content-Type: application/json

{
  "predicates": [
    {
      "name": "Path",
      "args": {"pattern": "/newroute/**"}
    }
  ],
  "filters": [
    {
      "name": "RewritePath",
      "args": {
        "regexp": "/newroute/(?<segment>.*)",
        "replacement": "/${T(java.lang.Runtime).getRuntime().exec('id')}"
      }
    }
  ]
}
```

**修复措施**：
1. 升级到安全版本
2. 禁用 Actuator 或限制访问
3. 使用 Spring Security 保护端点

---

## 常见安全问题

### 1. SpEL 表达式注入

```java
// 漏洞代码
@GetMapping("/eval")
public String evaluate(@RequestParam String expression) {
    ExpressionParser parser = new SpelExpressionParser();
    Expression exp = parser.parseExpression(expression);
    return exp.getValue().toString();
}
```

```java
// 安全代码：禁用危险功能
SpelParserConfiguration config = new SpelParserConfiguration(
    false,  // autoGrowNullReferences
    false   // autoGrowCollections
);
ExpressionParser parser = new SpelExpressionParser(config);
```

### 2. 未授权 Actuator 端点

```yaml
# 漏洞配置
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

```yaml
# 安全配置
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: never
```

### 3. 敏感配置泄露

```yaml
# 漏洞配置：密码明文
spring:
  datasource:
    password: admin123
```

```yaml
# 安全配置：使用加密
spring:
  datasource:
    password: ENC(加密后的密码)
```

## 安全配置建议

### 1. Spring Security 配置

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            );
        return http.build();
    }
}
```

### 2. 安全响应头

```java
@Configuration
public class SecurityHeadersConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.httpHeaders(headers -> headers
            .contentSecurityPolicy("default-src 'self'")
            .xssProtection(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
            .frameOptions(FrameOptionsHeaderWriter.XFrameOptionsMode.DENY)
            .httpStrictTransportSecurity()
        );
    }
}
```

### 3. 禁用危险端点

```yaml
management:
  endpoints:
    enabled-by-default: false
  endpoint:
    health:
      enabled: true
    info:
      enabled: true
```

## 参考资料

- [Spring Security 官方文档](https://docs.spring.io/spring-security/reference/)
- [Spring Security Advisories](https://spring.io/security)
- [CVE-2022-22965 分析](https://www.lunasec.io/docs/blog/spring-rce-vulnerability/)
