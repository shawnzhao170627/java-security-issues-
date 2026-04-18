---
id: BROKEN-ACCESS-CONTROL
name: 访问控制失效
severity: high
owasp: "A01:2025"
cwe: ["CWE-862", "CWE-863", "CWE-284"]
category: authentication
frameworks: [Spring Security, Shiro]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 访问控制失效

> 最后更新：2026-04-18

## 概述

访问控制失效（Broken Access Control）是指应用未能正确实施权限限制，导致用户可以执行超出其权限范围的操作。这是 OWASP Top 10 中排名第一的安全风险，涵盖未授权访问、越权操作、IDOR 等多种子类型。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-862 / CWE-863 / CWE-284 |
| 严重程度 | 高危 |

## 攻击类型

| 攻击方式 | 说明 | 危害 |
|---------|------|------|
| 未授权访问 | 缺少权限校验，直接访问受保护资源 | 数据泄露 |
| 纵向越权 | 普通用户执行管理员操作 | 权限提升 |
| 横向越权（IDOR） | 访问同级别其他用户的数据 | 数据泄露 |
| 功能级越权 | 访问未授权的 API 端点 | 业务逻辑破坏 |
| 强制浏览 | 直接输入 URL 绕过前端权限控制 | 信息泄露 |

## Java 场景

### 缺少权限校验

```java
// [VULNERABLE] 接口未配置权限校验
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/users")
    public List<User> listUsers() {
        // 危险：任何人都可以访问管理员接口
        return userService.findAll();
    }
}
```

```java
// [SECURE] 使用 Spring Security 注解进行权限控制
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> listUsers() {
        return userService.findAll();
    }
}
```

### IDOR 横向越权

```java
// [VULNERABLE] 只校验登录状态，不校验数据归属
@GetMapping("/order/{id}")
public Order getOrder(@PathVariable Long id) {
    // 危险：任何登录用户可查看任意订单
    return orderService.findById(id);
}
```

```java
// [SECURE] 校验数据归属
@GetMapping("/order/{id}")
public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {
    Order order = orderService.findById(id);
    // 安全：验证当前用户是否为订单所有者
    if (!order.getUserId().equals(user.getId())) {
        throw new AccessDeniedException("无权访问此订单");
    }
    return order;
}
```

### Shiro 权限配置遗漏

```java
// [VULNERABLE] Shiro 过滤链配置遗漏
@Bean
public ShiroFilterChainDefinition shiroFilterChainDefinition() {
    DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
    chain.addPathDefinition("/api/public/**", "anon");
    // 危险：/api/admin/** 未配置任何过滤规则，默认放行
    chain.addPathDefinition("/api/**", "authc");
    return chain;
}
```

```java
// [SECURE] 明确配置所有路径的权限
@Bean
public ShiroFilterChainDefinition shiroFilterChainDefinition() {
    DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
    chain.addPathDefinition("/api/public/**", "anon");
    chain.addPathDefinition("/api/admin/**", "authc,roles[admin]");
    chain.addPathDefinition("/api/**", "authc");
    return chain;
}
```

## 检测方法

1. **静态分析**：检查 `@RequestMapping` 等注解是否缺少 `@PreAuthorize` 等权限注解
2. **权限测试**：使用低权限账号访问高权限接口
3. **IDOR 测试**：修改 URL 中的 ID 参数，访问其他用户数据
4. **Shiro 配置审计**：检查过滤链是否覆盖所有敏感路径

## 防护措施

1. **默认拒绝**：所有接口默认需要认证，显式标记公开接口
2. **RBAC 权限模型**：使用基于角色的访问控制
3. **数据归属校验**：服务端验证当前用户是否有权访问请求数据
4. **集中权限管理**：使用 Spring Security 或 Shiro 统一管理权限
5. **最小权限原则**：每个角色只授予必要的权限

## 参考资料

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [Spring Security Authorization](https://docs.spring.io/spring-security/reference/authorization.html)
