---
id: SECURITY-MISCONFIGURATION
name: 安全配置错误
severity: medium
owasp: "A02:2025"
cwe: ["CWE-16", "CWE-260"]
category: configuration
frameworks: ["Spring Boot", Tomcat, "application.properties/yml"]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 安全配置错误

> 最后更新：2026-04-18

## 概述

安全配置错误（Security Misconfiguration）是最常见的安全问题之一，包括使用不安全的默认配置、不完整的临时配置、开放的云存储、未修复的漏洞框架、不必要的功能启用、默认账户和密码等。几乎所有应用、服务器、框架和平台都存在配置问题。

在 Java 应用中，Spring Boot 的默认配置、Tomcat 的默认设置、`application.properties/yml` 中的不当配置都是常见的安全配置错误来源。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A02:2025 - Security Misconfiguration |
| CWE | CWE-16 / CWE-260 |
| 严重程度 | 中危 |

## 攻击类型

### 1. 默认凭证利用

应用或中间件使用默认用户名和密码（如 admin/admin），攻击者可直接登录获取管理权限。

```
# Spring Boot 默认用户
user / user
# Tomcat 默认管理账户
tomcat / tomcat
# 数据库默认账户
sa / (空密码)
```

### 2. 调试模式泄露

生产环境启用了调试模式或详细错误信息，泄露应用内部结构、堆栈跟踪、配置信息等。

```
# Spring Boot 开发模式配置
spring.devtools.restart.enabled=true
server.error.include-stacktrace=always
```

### 3. 不必要的服务暴露

启用了不需要的功能模块或端口，扩大了攻击面。如 Actuator 全端点暴露、管理端口对外开放等。

```
# 暴露所有 Actuator 端点
management.endpoints.web.exposure.include=*
```

### 4. HTTP 安全头缺失

未配置必要的安全响应头，使应用易受点击劫持、MIME 嗅探、XSS 等攻击。

```
# 缺失的安全头
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

## Java场景

### [VULNERABLE] Spring Boot 不安全默认配置

```yaml
# [VULNERABLE] application.yml - 不安全的生产环境配置

# 漏洞 1：暴露所有 Actuator 端点
management:
  endpoints:
    web:
      exposure:
        include: "*"

# 漏洞 2：H2 控制台可远程访问
spring:
  h2:
    console:
      enabled: true
      settings:
        web-allow-others: true

# 漏洞 3：显示完整错误信息和堆栈跟踪
server:
  error:
    include-stacktrace: always
    include-message: always

# 漏洞 4：默认 H2 数据库连接，使用内存模式
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password:
```

### [VULNERABLE] Spring Security 不安全配置

```java
// [VULNERABLE] Spring Security 禁用了所有安全防护
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;

@Configuration
public class InsecureSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 漏洞：禁用了所有安全机制
        http.csrf().disable()           // 禁用 CSRF 防护
            .headers().disable()        // 禁用安全头
            .authorizeRequests()
            .anyRequest().permitAll()   // 允许所有请求无需认证
            .and()
            .httpBasic().disable()      // 禁用基本认证
            .formLogin().disable();     // 禁用表单登录
    }
}
```

### [SECURE] Spring Boot 安全基线配置

```yaml
# [SECURE] application-prod.yml - 安全的生产环境配置

# 安全配置 1：最小化 Actuator 端点暴露
management:
  endpoints:
    web:
      exposure:
        include: "health,info,metrics"
  endpoint:
    health:
      show-details: when-authorized
  server:
    port: 8081  # 使用独立管理端口

# 安全配置 2：禁用 H2 控制台和 DevTools
spring:
  h2:
    console:
      enabled: false
  devtools:
    restart:
      enabled: false

# 安全配置 3：最小化错误信息
server:
  error:
    include-stacktrace: never
    include-message: never
    include-binding-errors: never

# 安全配置 4：安全数据源配置
  datasource:
    url: jdbc:postgresql://db.internal:5432/appdb
    username: ${DB_USERNAME}  # 从环境变量读取
    password: ${DB_PASSWORD}  # 从环境变量读取
```

### [SECURE] Spring Security 安全配置

```java
// [SECURE] Spring Security 安全基线配置
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.web.header.writers.*;

@Configuration
public class SecureSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 安全配置 1：启用 CSRF 防护
            .csrf(csrf -> csrf.csrfTokenRepository(
                CookieCsrfTokenRepository.withHttpOnlyFalse()))

            // 安全配置 2：配置安全响应头
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; script-src 'self'; style-src 'self'"))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .contentTypeOptions(Customizer.withDefaults())
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)))

            // 安全配置 3：严格的访问控制
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                .anyRequest().authenticated())

            // 安全配置 4：启用表单登录
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll());

        return http.build();
    }
}
```

## 检测方法

1. **配置审计**：使用 Spring Boot Actuator `/configprops` 端点或直接审查 `application.yml/properties` 文件
2. **漏洞扫描**：使用 OWASP ZAP、Nessus 等工具扫描默认凭证、暴露端点和缺失安全头
3. **依赖扫描**：使用 OWASP Dependency-Check、Snyk 检测含有已知漏洞的依赖
4. **自动化基线检查**：使用 SecHub、DevSecOps 流水线中的安全扫描阶段

## 防护措施

1. **安全基线配置**：为每个环境建立安全配置基线，生产环境必须使用最严格的配置
2. **删除默认账户**：修改或删除所有默认用户名和密码，使用强密码策略
3. **最小化暴露面**：关闭不需要的功能模块、端口和端点，只启用业务必需的功能
4. **配置安全响应头**：配置 CSP、HSTS、X-Frame-Options、X-Content-Type-Options 等安全头
5. **自动化配置验证**：在 CI/CD 流水线中加入配置安全检查，防止不安全配置上线

## 参考资料

- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2017-Security_Misconfiguration/)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [Spring Boot Security Best Practices](https://docs.spring.io/spring-boot/reference/actuator/security.html)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
