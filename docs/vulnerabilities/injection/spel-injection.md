---
id: SPEL-INJECTION
name: SpEL 表达式注入
severity: critical
owasp: "A05:2025"
cwe: ["CWE-94"]
category: injection
frameworks: [Spring Framework, Spring Data, Spring Security, Spring Cloud]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# SpEL 表达式注入

> 最后更新：2026-04-17

## 概述

Spring Expression Language（SpEL）注入是指用户可控输入被传入 SpEL 解析器执行，导致任意代码执行（RCE）。Spring 全生态广泛使用 SpEL，是 Java 应用中高危且高频的漏洞类型。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Injection |
| CWE | CWE-94 |
| 严重程度 | 严重 |

## 攻击类型

| 入口 | 说明 | 典型 CVE |
|------|------|---------|
| `@Value` 注解 | 配置值注入 SpEL | — |
| `ExpressionParser.parseExpression()` | 直接解析用户输入 | — |
| Spring Data `@Query` | JPQL/SpEL 混用 | — |
| Spring Cloud Gateway | 路由过滤器 SpEL | CVE-2022-22947 |
| Spring Cloud Function | 函数路由 SpEL | CVE-2022-22963 |
| Spring Security `@PreAuthorize` | 权限表达式 SpEL | — |

## Java 场景

### 直接解析用户输入

```java
// [VULNERABLE] 直接解析用户提供的表达式
@GetMapping("/calc")
public Object calc(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    // 危险：用户输入直接作为 SpEL 表达式解析
    return parser.parseExpression(expr).getValue();
}
// 攻击输入：T(java.lang.Runtime).getRuntime().exec('id')
// 攻击输入：T(java.lang.ProcessBuilder).new(new String[]{'id'}).start()
```

```java
// [SECURE] 使用 SimpleEvaluationContext 限制表达式能力
@GetMapping("/calc")
public Object calc(@RequestParam String expr) {
    ExpressionParser parser = new SpelExpressionParser();
    // 安全：SimpleEvaluationContext 禁止访问类型、构造器等危险操作
    EvaluationContext context = SimpleEvaluationContext
        .forReadOnlyDataBinding()
        .withInstanceMethods()
        .build();
    return parser.parseExpression(expr).getValue(context);
}
```

### Spring Data Repository 注入

```java
// [VULNERABLE] SpEL 拼接用户输入
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // 危险：?#{} 中使用用户可控变量拼接
    @Query("select u from User u where u.name = ?#{[0]}")
    List<User> findByName(String name);
}
```

```java
// [SECURE] 使用命名参数，不使用 SpEL 插值
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("select u from User u where u.name = :name")
    List<User> findByName(@Param("name") String name);
}
```

### Spring Security 权限注解注入

```java
// [VULNERABLE] 动态构造权限表达式
@Service
public class DataService {
    public String getData(String role) {
        // 危险：role 由用户传入，动态拼入 @PreAuthorize
        // 这种场景通常出现在 AOP 动态代理中
        return processWithRole(role);
    }

    // 危险：如果 permission 参数来自用户输入
    @PreAuthorize("hasPermission(#id, '" + "admin" + "')")
    public Data findById(Long id) {
        return dataRepository.findById(id).orElseThrow();
    }
}
```

```java
// [SECURE] 权限值来自枚举或常量，不接受用户输入
@PreAuthorize("hasRole('ADMIN')")  // 常量字符串，安全
public Data findById(Long id) {
    return dataRepository.findById(id).orElseThrow();
}
```

### Spring Cloud Gateway（CVE-2022-22947）

```java
// [VULNERABLE] 动态添加包含 SpEL 的路由过滤器（已修复版本前的行为）
// 攻击者通过 /actuator/gateway/routes 端点注入恶意路由：
// {
//   "filters": [{
//     "name": "AddResponseHeader",
//     "args": {"name": "X-Response", "value": "#{T(java.lang.Runtime).getRuntime().exec('id')}"}
//   }]
// }
```

```java
// [SECURE] 禁用 Gateway Actuator 端点 / 升级到修复版本
// application.yml
// management:
//   endpoints:
//     web:
//       exposure:
//         exclude: gateway
```

## 检测方法

1. **静态分析**：搜索 `parseExpression(`、`SpelExpressionParser`
2. **探测 Payload**：`#{7*7}`、`T(java.lang.Math).random()`
3. **依赖扫描**：检查 `spring-cloud-gateway` < 3.1.1、`spring-cloud-function` < 3.1.7

## 防护措施

1. **使用 `SimpleEvaluationContext`**：限制 SpEL 可访问的类型和方法
2. **禁止用户控制表达式字符串**：表达式应为编译期常量
3. **升级 Spring Cloud 组件**：修复已知 CVE
4. **禁用危险 Actuator 端点**：Gateway、Env 等端点不对外暴露

```java
// 安全的 EvaluationContext 配置
EvaluationContext safeContext = SimpleEvaluationContext
    .forReadOnlyDataBinding()   // 仅允许属性读取
    .build();
// 不允许：T() 类型访问、new 构造器、系统属性访问
```

## 参考资料

- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [CVE-2022-22947: Spring Cloud Gateway RCE](https://nvd.nist.gov/vuln/detail/CVE-2022-22947)
- [CVE-2022-22963: Spring Cloud Function RCE](https://nvd.nist.gov/vuln/detail/CVE-2022-22963)
- [Spring SpEL 安全文档](https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#expressions-evaluation)
