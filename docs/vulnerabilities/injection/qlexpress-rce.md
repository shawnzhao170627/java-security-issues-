---
id: QLEXPRESS-RCE
name: QLExpress 远程代码执行
severity: high
owasp: "A05:2025"
cwe: ["CWE-94", "CWE-917"]
category: injection
frameworks: [QLExpress, Drools, Aviator]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# QLExpress 远程代码执行

> 最后更新：2026-04-17

## 概述

QLExpress 是阿里巴巴开源的动态脚本引擎，广泛应用于电商规则引擎、营销活动规则、风控策略等场景。如果将用户输入直接传入 QLExpress 执行，攻击者可以通过 QLExpress 的 Java 互操作特性执行任意代码。类似风险也存在于其他规则引擎（Drools、Aviator、MVEL 等）。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Security Misconfiguration |
| CWE | CWE-94 (Code Injection), CWE-917 (Expression Language Injection) |
| 严重程度 | 高危 |

## 攻击类型

### 1. 直接执行用户输入的 QLExpress 表达式

```java
// [VULNERABLE] 用户输入直接执行
String userInput = request.getParameter("rule");
Object result = engine.execute(userInput);
// 攻击者可执行: import java.lang.Runtime; Runtime.getRuntime().exec("id");
```

### 2. 利用 QLExpress 的 Java 互操作

```java
// QLExpress 可以直接调用 Java 类
import java.lang.Runtime;
Runtime runtime = Runtime.getRuntime();
runtime.exec("calc");

// 或通过反射
Class.forName("java.lang.Runtime").getMethod("exec", String.class)
    .invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null), "id");
```

### 3. 通过规则引擎绕过

```java
// 风控/营销规则引擎场景
// 正常规则: orderAmount > 100 && userLevel >= 3
// 恶意规则: import java.lang.*; Runtime.getRuntime().exec("id"); true
```

### 4. Aviator 表达式注入

```java
// [VULNERABLE] Aviator 表达式注入
String userInput = request.getParameter("expr");
Object result = AviatorEvaluator.execute(userInput);
// 攻击者可使用 Aviator 的函数调用特性
```

### 5. Drools 规则注入

```java
// [VULNERABLE] Drools 规则注入
String userInput = request.getParameter("rule");
// 动态编译用户提供的 DRL 规则
KieSession session = kieBase.newKieSession();
```

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 QLExpress RCE 漏洞，仅用于教学目的
// 漏洞类型：QLEXPRESS-RCE
// 风险等级：high
// 对应文档：docs/vulnerabilities/injection/qlexpress-rce.md

import com.ql.util.express.ExpressRunner;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rule")
public class QlExpressVulnerable {

    private final ExpressRunner runner = new ExpressRunner();

    // [VULNERABLE] 用户输入直接作为规则执行
    @PostMapping("/evaluate")
    public Object evaluateRule(@RequestParam String rule,
                                @RequestParam Map<String, Object> context) throws Exception {
        return runner.execute(rule, context, null, false, false);
    }

    // [VULNERABLE] 营销规则引擎，运营配置的规则未做安全校验
    @PostMapping("/promo/check")
    public boolean checkPromo(@RequestParam String promoRule,
                               @RequestParam double orderAmount) throws Exception {
        DefaultContext<String, Object> context = new DefaultContext<>();
        context.put("orderAmount", orderAmount);
        // 运营人员可配置任意 QLExpress 表达式
        Object result = runner.execute(promoRule, context, null, false, false);
        return Boolean.TRUE.equals(result);
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 QLExpress RCE 漏洞的安全修复方案
// 修复方式：沙箱配置 / 白名单函数 / 预定义规则模板
// 对应文档：docs/vulnerabilities/injection/qlexpress-rce.md

import com.ql.util.express.ExpressRunner;
import com.ql.util.express.InstructionSet;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rule")
public class QlExpressSecure {

    private final ExpressRunner runner;

    public QlExpressSecure() {
        runner = new ExpressRunner();

        // [SECURE] 方案1：禁止 import 语句和 Java 类访问
        // QLExpress 默认不允许 import，需确保不被开启

        // [SECURE] 方案2：仅注册安全的自定义函数
        runner.addFunction("isVip", (context, list) -> {
            // 自定义安全函数，不暴露 Java 运行时
            return Boolean.TRUE.equals(list.get(0));
        });

        runner.addFunction("discount", (context, list) -> {
            double price = (double) list.get(0);
            double rate = (double) list.get(1);
            return price * rate;
        });
    }

    // [SECURE] 方案3：使用预定义规则模板
    private static final Map<String, String> RULE_TEMPLATES = Map.of(
        "vip_discount", "orderAmount * 0.8",
        "new_user_coupon", "orderAmount > 50 ? 20 : 0",
        "bulk_discount", "orderAmount * (quantity > 10 ? 0.7 : 1.0)"
    );

    @PostMapping("/evaluate")
    public Object evaluateRule(@RequestParam String templateName,
                                @RequestParam Map<String, Object> context) throws Exception {
        // [SECURE] 只允许使用预定义模板
        String rule = RULE_TEMPLATES.get(templateName);
        if (rule == null) {
            throw new IllegalArgumentException("Unknown rule template: " + templateName);
        }
        return runner.execute(rule, context, null, false, false);
    }

    // [SECURE] 方案4：如果必须执行动态规则，添加安全校验
    @PostMapping("/promo/check")
    public boolean checkPromo(@RequestParam String promoRule,
                               @RequestParam double orderAmount) throws Exception {
        // [SECURE] 检查规则中是否包含危险关键字
        validateRuleSafety(promoRule);

        DefaultContext<String, Object> context = new DefaultContext<>();
        context.put("orderAmount", orderAmount);
        Object result = runner.execute(promoRule, context, null, false, false);
        return Boolean.TRUE.equals(result);
    }

    private void validateRuleSafety(String rule) {
        String lower = rule.toLowerCase();
        // [SECURE] 检测危险关键字
        if (lower.contains("runtime") || lower.contains("processbuilder")
            || lower.contains("class.forname") || lower.contains("import ")
            || lower.contains("reflect") || lower.contains("exec(")
            || lower.contains("getruntime")) {
            throw new SecurityException("Rule contains forbidden operations");
        }
    }
}
```

## 检测方法

1. **静态分析**：搜索 `ExpressRunner.execute()`、`AviatorEvaluator.execute()` 调用
2. **代码审计**：检查规则引擎输入来源是否可控
3. **动态测试**：构造 QLExpress 表达式注入 payload

**Semgrep 规则**：

```yaml
rules:
  - id: java-qlexpress-user-input
    patterns:
      - pattern: |
          $RUNNER.execute($INPUT, ...)
      - pattern-not: |
          $RUNNER.execute("...", ...)
    message: |
      检测到 QLExpress 执行非常量表达式，如果参数来自用户输入，可能导致 RCE。
      建议：使用预定义规则模板，或添加安全校验。
    severity: ERROR
    languages: [java]
    metadata:
      category: security
      subcategory: injection
      cwe: CWE-94

  - id: java-aviator-user-input
    patterns:
      - pattern: |
          AviatorEvaluator.execute($INPUT)
      - pattern-not: |
          AviatorEvaluator.execute("...")
    message: |
      检测到 Aviator 执行非常量表达式，如果参数来自用户输入，可能导致代码注入。
    severity: ERROR
    languages: [java]
    metadata:
      category: security
      subcategory: injection
      cwe: CWE-94
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 使用预定义模板 | 用白名单模板替代动态规则，仅允许参数替换 |
| P0 | 禁止 import 和 Java 类访问 | 确保 QLExpress 不开启 Java 类访问能力 |
| P1 | 注册安全自定义函数 | 仅暴露业务所需的安全函数 |
| P1 | 规则安全校验 | 检测规则中的危险关键字（runtime、exec、reflect 等） |
| P2 | 操作审计 | 记录所有规则变更和执行日志 |
| P2 | 运营权限控制 | 规则配置需要审批流程，不直接信任运营输入 |

### 规则引擎安全对比

| 引擎 | Java 互操作 | 安全配置 | 推荐度 |
|------|-----------|---------|--------|
| QLExpress | 默认关闭，可开启 | 需手动配置 | 中 |
| Aviator | 有限 | 相对安全 | 较高 |
| MVEL | 完全 | 需沙箱配置 | 低 |
| Drools | 完全 | 需安全配置 | 低 |
| Spring EL | 完全 | SimpleEvaluationContext | 较高 |

## 参考资料

- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [QLExpress GitHub](https://github.com/alibaba/QLExpress)
- [Aviator GitHub](https://github.com/killme2008/aviator)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
