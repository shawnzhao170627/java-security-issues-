---
id: SWAGGER-INFO-DISCLOSURE
name: Swagger/API 文档信息泄露
severity: low
owasp: A05:2025
cwe: [CWE-200, CWE-16]
category: configuration
frameworks: [Swagger, SpringDoc, SpringFox, OpenAPI]
last_updated: 2026-04-17
doc_version: "1.0"
---

# Swagger/API 文档信息泄露

> 最后更新：2026-04-17

## 概述

Swagger（OpenAPI）文档在开发和测试阶段非常有用，但如果在生产环境暴露，会泄露 API 接口结构、参数定义、数据模型、认证方式等关键信息，为攻击者提供完整的攻击面地图。常见问题包括：生产环境未禁用 Swagger UI、API 文档端点未做访问控制、文档中包含敏感字段说明等。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Security Misconfiguration |
| CWE | CWE-200 (Information Exposure), CWE-16 (Configuration) |
| 严重程度 | 低危 |

## 攻击类型

### 1. Swagger UI 直接访问

```
# 常见 Swagger 文档路径
GET /swagger-ui.html HTTP/1.1
GET /swagger-ui/index.html HTTP/1.1
GET /v2/api-docs HTTP/1.1
GET /v3/api-docs HTTP/1.1
GET /swagger-resources HTTP/1.1
GET /doc.html HTTP/1.1          # knife4j
```

### 2. 通过 API 文档发现攻击面

```
# 从 API 文档获取信息
GET /v3/api-docs HTTP/1.1

# 返回完整 API 定义，包含：
# - 所有接口路径和参数
# - 数据模型定义（含敏感字段如 password、token）
# - 认证方式（API Key 位置、OAuth2 配置）
# - 内部服务名称和接口
```

### 3. API 文档中的敏感信息

```yaml
# OpenAPI 文档中可能泄露的信息
components:
  schemas:
    User:
      properties:
        password:           # 泄露密码字段名
          type: string
        internalId:         # 泄露内部 ID 格式
          type: string
          pattern: "^EMP-[0-9]{6}$"

  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header           # 泄露认证方式
      name: X-API-Key

# 泄露内部微服务接口
paths:
  /internal/admin/users:    # 泄露内部管理接口
```

## Java 场景

### 漏洞代码

```yaml
# [VULNERABLE] application.yml - 生产环境暴露 Swagger
springdoc:
  api-docs:
    enabled: true           # [VULNERABLE] 生产环境启用
    path: /v3/api-docs      # [VULNERABLE] 默认路径
  swagger-ui:
    enabled: true           # [VULNERABLE] 生产环境启用
    path: /swagger-ui.html  # [VULNERABLE] 默认路径
```

```java
// [VULNERABLE] 文件说明：演示 Swagger 信息泄露漏洞
// 漏洞类型：SWAGGER-INFO-DISCLOSURE
// 风险等级：low
// 对应文档：docs/vulnerabilities/configuration/swagger-info-disclosure.md

import io.swagger.v3.oas.annotations.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class SwaggerVulnerable {

    // [VULNERABLE] Swagger 注解暴露内部实现细节
    @Operation(summary = "获取用户信息",
               description = "内部管理员接口，通过 internalToken 认证")
    @Parameter(name = "internalToken",
               description = "内部认证令牌，格式: INT-XXXX",
               required = true)
    @GetMapping("/admin/users")
    public Object getAdminUsers(@RequestHeader String internalToken) {
        return "admin users";
    }
}
```

### 安全代码

```yaml
# [SECURE] application.yml - 生产环境禁用 Swagger

# 方案1：通过 Profile 控制
---
spring:
  profiles: prod
springdoc:
  api-docs:
    enabled: false        # [SECURE] 生产环境禁用
  swagger-ui:
    enabled: false        # [SECURE] 生产环境禁用

---
spring:
  profiles: dev
springdoc:
  api-docs:
    enabled: true         # 开发环境启用
    path: /internal/api-docs   # [SECURE] 修改默认路径
  swagger-ui:
    enabled: true
    path: /internal/swagger-ui  # [SECURE] 修改默认路径
```

```java
// [SECURE] 方案2：Spring Security 保护文档端点
@Configuration
public class SwaggerSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/internal/api-docs/**").hasRole("DEVELOPER")
                .antMatchers("/internal/swagger-ui/**").hasRole("DEVELOPER")
                // [SECURE] 仍然拦截默认路径
                .antMatchers("/v3/api-docs/**", "/swagger-ui/**",
                             "/swagger-resources/**", "/v2/api-docs/**")
                    .denyAll()
                .anyRequest().permitAll();
    }
}

// [SECURE] 方案3：注解中不暴露敏感信息
@RestController
@RequestMapping("/api")
public class SwaggerSecure {

    @Operation(summary = "获取用户信息")  // [SECURE] 简化描述
    @GetMapping("/admin/users")
    public Object getAdminUsers(@RequestHeader String authorization) {
        // [SECURE] 使用通用参数名，不暴露内部细节
        return "admin users";
    }
}
```

## 检测方法

1. **路径扫描**：访问常见 Swagger 文档路径
2. **配置审计**：检查 `springdoc` / `springfox` 配置是否在生产环境禁用
3. **依赖扫描**：检查是否引入了 `springdoc-openapi` 或 `springfox` 依赖

**Semgrep 规则**：

```yaml
rules:
  - id: java-swagger-prod-enabled
    patterns:
      - pattern: |
          enabled: true
    paths:
      - "application-prod.yml"
      - "application-prod.yaml"
      - "application-prod.properties"
    message: |
      检测到生产环境配置中 Swagger 可能启用，建议禁用 API 文档和 UI。
    severity: WARNING
    languages: [yaml]
    metadata:
      category: security
      subcategory: configuration
      cwe: CWE-200

  - id: java-swagger-sensitive-param
    patterns:
      - pattern: |
          @Parameter(name = "password", ...)
      - pattern: |
          @Parameter(name = "secret", ...)
      - pattern: |
          @Parameter(name = "token", ...)
    message: |
      检测到 Swagger 注解中包含敏感参数名，避免在 API 文档中暴露。
    severity: INFO
    languages: [java]
    metadata:
      category: security
      subcategory: configuration
      cwe: CWE-200
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 生产环境禁用 | 通过 Spring Profile 控制，生产环境禁用文档和 UI |
| P0 | 修改默认路径 | 将文档路径从 `/v3/api-docs` 改为不易猜测的路径 |
| P1 | 访问控制 | 文档端点需要认证，限制为开发/测试角色 |
| P1 | 拦截默认路径 | 对 `/swagger-ui.html`、`/v2/api-docs` 等默认路径返回 404 |
| P2 | 清理敏感注解 | 注解描述中不包含内部实现细节 |
| P2 | 使用 API Gateway | 在网关层统一拦截文档路径 |

### 默认路径拦截清单

| 框架 | 默认路径 | 应对 |
|------|---------|------|
| SpringFox (Swagger 2) | `/swagger-ui.html`, `/v2/api-docs`, `/swagger-resources` | 禁用或限制 |
| SpringDoc (OpenAPI 3) | `/swagger-ui.html`, `/v3/api-docs` | 禁用或限制 |
| Knife4j | `/doc.html` | 禁用或限制 |
| Spring REST Docs | 无默认 UI | 相对安全 |

## 参考资料

- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
- [SpringDoc Configuration](https://springdoc.org/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Spring Boot Actuator + Swagger Security](https://docs.spring.io/spring-boot/reference/actuator/security.html)
