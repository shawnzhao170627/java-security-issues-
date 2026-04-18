---
id: ACTUATOR
name: Actuator 未授权访问
severity: high
owasp: "A05:2025"
cwe: ["CWE-16", "CWE-200"]
category: configuration
frameworks: [Spring Boot Actuator]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# Actuator 未授权访问

> 最后更新：2026-04-17

## 概述

Spring Boot Actuator 提供了一系列生产级监控和管理端点（如 `/actuator/env`、`/actuator/health`、`/actuator/heapdump` 等）。如果未正确配置端点暴露策略和访问控制，攻击者可获取敏感配置信息（数据库密码、API 密钥）、下载堆转储、触发应用重启，甚至通过 `/actuator/gateway/routes` 等端点获取路由信息进行进一步攻击。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Security Misconfiguration |
| CWE | CWE-16 (Configuration), CWE-200 (Information Exposure) |
| 严重程度 | 高危 |

## 攻击类型

### 1. 敏感配置泄露（/actuator/env）

```
GET /actuator/env HTTP/1.1

# 返回所有环境变量，包含：
# - 数据库密码
# - API 密钥
# - 加密密钥
# - 内网地址
```

### 2. 堆转储下载（/actuator/heapdump）

```
GET /actuator/heapdump HTTP/1.1

# 下载 JVM 堆转储文件（可能数十 MB 到数 GB）
# 可从中提取：
# - 内存中的密码、Token
# - 数据库连接字符串
# - 加密密钥
# - 业务敏感数据
```

### 3. 端点列表发现（/actuator）

```
GET /actuator HTTP/1.1

# 返回所有可用端点列表，帮助攻击者发现攻击面
{
  "_links": {
    "self": { "href": "/actuator", "templated": false },
    "env": { "href": "/actuator/env", "templated": false },
    "heapdump": { "href": "/actuator/heapdump", "templated": false },
    "configprops": { "href": "/actuator/configprops", "templated": false }
  }
}
```

### 4. Gateway 路由泄露（/actuator/gateway/routes）

```
GET /actuator/gateway/routes HTTP/1.1

# 返回所有 Spring Cloud Gateway 路由配置
# 可发现内部服务地址和路由规则
```

### 5. Log 配置修改（/actuator/loggers）

```
# 提升日志级别获取更多调试信息
POST /actuator/loggers/org.springframework
Content-Type: application/json

{ "configuredLevel": "DEBUG" }
```

## Java 场景

### 漏洞代码

```yaml
# [VULNERABLE] application.yml - 默认暴露所有端点
management:
  endpoints:
    web:
      exposure:
        include: "*"    # [VULNERABLE] 暴露所有端点
  endpoint:
    health:
      show-details: always  # [VULNERABLE] 显示健康检查详情
    env:
      enabled: true          # [VULNERABLE] 暴露环境变量
    heapdump:
      enabled: true          # [VULNERABLE] 允许堆转储下载
```

```java
// [VULNERABLE] 文件说明：演示 Actuator 未授权访问漏洞
// 漏洞类型：ACTUATOR
// 风险等级：high
// 对应文档：docs/vulnerabilities/configuration/actuator.md

import org.springframework.boot.actuate.endpoint.web.annotation.*;
import org.springframework.stereotype.Component;

// [VULNERABLE] 自定义 Actuator 端点无访问控制
@Component
@Endpoint(id = "internal-info")
public class InternalInfoEndpoint {

    @ReadOperation
    public String getInfo() {
        // 暴露内部信息，无权限检查
        return "Database: jdbc:mysql://internal-db:3306/app";
    }
}
```

### 安全代码

```yaml
# [SECURE] application.yml - 最小暴露 + 访问控制

# 方案1：最小化暴露端点
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus  # [SECURE] 仅暴露必要端点
      base-path: /mgmt-actuator  # [SECURE] 修改默认路径，避免被扫描
  endpoint:
    health:
      show-details: when-authorized  # [SECURE] 仅授权用户可见详情
    env:
      enabled: false      # [SECURE] 禁用 env 端点
    heapdump:
      enabled: false      # [SECURE] 禁用堆转储
    configprops:
      enabled: false      # [SECURE] 禁用配置属性
    loggers:
      enabled: false      # [SECURE] 禁用日志级别修改
  security:
    enabled: true         # [SECURE] 启用 Actuator 安全

# 方案2：独立管理端口（推荐）
---
management:
  server:
    port: 8081              # [SECURE] 管理端点使用独立端口
    address: 127.0.0.1      # [SECURE] 仅本地访问
```

```java
// [SECURE] 方案3：Spring Security 保护 Actuator 端点
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;

@Configuration
public class ActuatorSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .requestMatchers()
                .antMatchers("/mgmt-actuator/**")  // [SECURE] 匹配管理端点
                .and()
            .authorizeRequests()
                .antMatchers("/mgmt-actuator/health", "/mgmt-actuator/info")
                    .permitAll()                    // [SECURE] 健康检查和信息端点公开
                .antMatchers("/mgmt-actuator/**")
                    .hasRole("ADMIN")               // [SECURE] 其他端点需要 ADMIN 角色
                .and()
            .csrf().disable()
            .httpBasic();                           // [SECURE] 使用 Basic 认证
    }
}
```

## 检测方法

1. **路径扫描**：访问 `/actuator`、`/actuator/env`、`/actuator/heapdump` 等常见路径
2. **配置审计**：检查 `management.endpoints.web.exposure.include` 配置
3. **依赖扫描**：检查是否引入 `spring-boot-starter-actuator` 依赖

**Semgrep 规则**：

```yaml
rules:
  - id: java-actuator-expose-all
    patterns:
      - pattern: |
          include: "*"
    paths:
      - "application.yml"
      - "application.yaml"
      - "application.properties"
    message: |
      检测到 Actuator 端点暴露所有（include: "*"），可能导致敏感信息泄露。
      建议：仅暴露必要端点（health,info,metrics）。
    severity: ERROR
    languages: [yaml]
    metadata:
      category: security
      subcategory: configuration
      cwe: CWE-16

  - id: java-actuator-heapdump-enabled
    patterns:
      - pattern: |
          heapdump:
            enabled: true
    paths:
      - "application.yml"
      - "application.yaml"
    message: |
      检测到 heapdump 端点已启用，攻击者可下载 JVM 堆转储获取敏感数据。
    severity: ERROR
    languages: [yaml]
    metadata:
      category: security
      subcategory: configuration
      cwe: CWE-200
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 最小化暴露端点 | 仅暴露 `health`、`info`、`metrics` 等必要端点 |
| P0 | 禁用高危端点 | 禁用 `env`、`heapdump`、`configprops`、`loggers` |
| P0 | 配置访问控制 | Spring Security 保护 Actuator 端点 |
| P1 | 独立管理端口 | 使用 `management.server.port` 和 `address=127.0.0.1` |
| P1 | 修改默认路径 | 将 `base-path` 从 `/actuator` 改为随机路径 |
| P2 | 网络隔离 | 管理端口仅在内网可访问 |
| P2 | 审计日志 | 记录所有 Actuator 端点访问 |

### 端点风险分级

| 端点 | 风险 | 建议 |
|------|------|------|
| `/actuator/health` | 低 | 可公开，但关闭 `show-details` |
| `/actuator/info` | 低 | 可公开 |
| `/actuator/metrics` | 低 | 可公开 |
| `/actuator/env` | 严重 | 禁用或严格访问控制 |
| `/actuator/heapdump` | 严重 | 禁用 |
| `/actuator/configprops` | 高 | 禁用或严格访问控制 |
| `/actuator/loggers` | 高 | 禁用或严格访问控制 |
| `/actuator/gateway/routes` | 高 | 禁用或严格访问控制 |
| `/actuator/trace` | 中 | 禁用 |

## 参考资料

- [Spring Boot Actuator Security](https://docs.spring.io/spring-boot/reference/actuator/security.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP Spring Boot Security](https://cheatsheetseries.owasp.org/cheatsheets/Spring_Boot_Cheat_Sheet.html)
