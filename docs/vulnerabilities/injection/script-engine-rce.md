---
id: SCRIPT-ENGINE-RCE
name: ScriptEngine/Groovy 远程代码执行
severity: critical
owasp: "A05:2025"
cwe: ["CWE-94", "CWE-917"]
category: injection
frameworks: [ScriptEngine, Groovy, Nashorn, JShell]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# ScriptEngine/Groovy 远程代码执行

> 最后更新：2026-04-17

## 概述

Java 的 `ScriptEngine` API（JSR 223）允许在 JVM 中执行脚本语言（Groovy、JavaScript/Nashorn、Python/Jython 等）。如果应用将用户输入直接传入 `ScriptEngine.eval()`，攻击者可执行任意代码。Groovy 的动态特性同样存在代码注入风险，如 `GroovyShell.evaluate()`、`GroovyClassLoader` 等。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Security Misconfiguration |
| CWE | CWE-94 (Code Injection), CWE-917 (Expression Language Injection) |
| 严重程度 | 严重 |

## 攻击类型

### 1. ScriptEngine eval 注入

用户输入直接传入 `ScriptEngine.eval()`，执行任意脚本。

```java
// [VULNERABLE] ScriptEngine eval 注入
ScriptEngineManager manager = new ScriptEngineManager();
ScriptEngine engine = manager.getEngineByName("groovy");
// 用户输入直接传入 eval
String userInput = request.getParameter("expr");
engine.eval(userInput); // 攻击者可执行任意 Groovy 代码
```

### 2. GroovyShell 代码注入

```java
// [VULNERABLE] GroovyShell 代码注入
GroovyShell shell = new GroovyShell();
String userInput = request.getParameter("script");
shell.evaluate(userInput); // 执行任意 Groovy 脚本
```

### 3. Nashorn JavaScript 注入

```java
// [VULNERABLE] Nashorn JavaScript 注入
ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
String userInput = request.getParameter("code");
engine.eval(userInput); // 执行任意 JavaScript（可调用 Java 类）
```

### 4. MVEL/OGNL 表达式注入

```java
// [VULNERABLE] MVEL 表达式注入
String userInput = request.getParameter("condition");
Object result = MVEL.eval(userInput); // 执行任意 MVEL 表达式
```

### 5. JShell 远程代码执行

```java
// [VULNERABLE] JShell 代码注入
import jdk.jshell.JShell;
import jdk.jshell.SnippetEvent;

JShell jshell = JShell.create();
String userInput = request.getParameter("snippet");
List<SnippetEvent> events = jshell.eval(userInput); // 执行任意 Java 代码
```

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 ScriptEngine RCE 漏洞，仅用于教学目的
// 漏洞类型：SCRIPT-ENGINE-RCE
// 风险等级：critical
// 对应文档：docs/vulnerabilities/injection/script-engine-rce.md

import javax.script.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/script")
public class ScriptEngineVulnerable {

    // [VULNERABLE] 用户输入直接传入 eval
    @PostMapping("/eval")
    public Object evaluateScript(@RequestParam String engineName,
                                  @RequestParam String script) throws ScriptException {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName(engineName);
        return engine.eval(script); // 任意脚本执行
    }

    // [VULNERABLE] GroovyShell 直接执行用户输入
    @PostMapping("/groovy")
    public Object evaluateGroovy(@RequestParam String script) {
        GroovyShell shell = new GroovyShell();
        return shell.evaluate(script); // 任意 Groovy 代码执行
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 ScriptEngine RCE 漏洞的安全修复方案
// 修复方式：禁用动态脚本执行 / 白名单限制
// 对应文档：docs/vulnerabilities/injection/script-engine-rce.md

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/script")
public class ScriptEngineSecure {

    // [SECURE] 方案1：完全禁止动态脚本执行（推荐）
    // 如果业务不需要动态脚本，直接移除 ScriptEngine 相关功能

    // [SECURE] 方案2：使用预定义表达式模板，仅允许参数替换
    private static final Map<String, String> ALLOWED_TEMPLATES = Map.of(
        "discount", "price * 0.9",
        "tax", "price * 0.13"
    );

    @PostMapping("/calculate")
    public Object safeCalculate(@RequestParam String templateName,
                                 @RequestParam double value) {
        String expression = ALLOWED_TEMPLATES.get(templateName);
        if (expression == null) {
            throw new IllegalArgumentException("Unknown template: " + templateName);
        }
        // 使用安全的计算引擎，而非 ScriptEngine
        return evaluateSafeExpression(expression, value);
    }

    // [SECURE] 方案3：如果必须使用脚本，配置严格沙箱
    private Object evaluateInSandbox(String script) {
        // 使用 SecurityManager 限制权限（已废弃，仅供参考）
        // 推荐使用容器级隔离（Docker、gVisor 等）
        throw new UnsupportedOperationException(
            "Dynamic script execution is disabled. Use predefined templates.");
    }

    private double evaluateSafeExpression(String expression, double value) {
        // 使用自实现的简单数学表达式解析器
        // 不依赖任何脚本引擎
        return value * 0.9; // 简化示例
    }
}
```

## 检测方法

1. **静态分析**：搜索 `ScriptEngine.eval()`、`GroovyShell.evaluate()`、`MVEL.eval()` 调用
2. **动态测试**：构造脚本注入 payload（如 `Runtime.getRuntime().exec("id")`）
3. **代码审计**：检查是否有用户输入流入脚本引擎

**Semgrep 规则**：

```yaml
rules:
  - id: java-script-engine-rce
    patterns:
      - pattern: |
          $ENGINE.eval($INPUT);
      - pattern-not: |
          $ENGINE.eval("...");
    message: |
      检测到 ScriptEngine.eval() 调用，如果参数来自用户输入，可能导致远程代码执行。
      建议：禁止将用户输入传入 eval()，使用预定义模板替代。
    severity: ERROR
    languages: [java]
    metadata:
      category: security
      subcategory: injection
      cwe: CWE-94
      references:
        - https://cwe.mitre.org/data/definitions/94.html

  - id: java-groovy-shell-evaluate
    patterns:
      - pattern: |
          $SHELL.evaluate($INPUT);
    message: |
      检测到 GroovyShell.evaluate() 调用，如果参数来自用户输入，可能导致远程代码执行。
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
| P0 | 禁止动态脚本执行 | 业务上尽量避免动态执行用户提供的脚本 |
| P0 | 使用预定义模板 | 用白名单模板替代动态脚本，仅允许参数替换 |
| P1 | 沙箱隔离 | 使用 Docker/gVisor 等容器级隔离执行环境 |
| P1 | SecurityManager（已废弃） | Java 17+ 已移除，不推荐依赖 |
| P2 | 输入严格校验 | 对传入脚本引擎的输入进行白名单校验 |
| P2 | 限制引擎功能 | 配置 `GroovyShell` 的 `CompilerConfiguration` 限制可执行的语句类型 |

### Groovy 沙箱配置示例

```java
// 限制 GroovyShell 可执行的语句类型
import org.codehaus.groovy.control.CompilerConfiguration;
import groovy.security.GroovyCodeSource;

CompilerConfiguration config = new CompilerConfiguration();
// 禁用以下特性
config.setDisabledGlobalASTTransformations(
    Set.of("org.codehaus.groovy.transform.ThreadInterruptASTTransformation")
);
```

## 参考资料

- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Groovy Security](https://groovy-lang.org/security.html)
- [JEP 335: Deprecate Nashorn](https://openjdk.org/jeps/335)
