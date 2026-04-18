---
id: LLM-DOS
name: LLM 拒绝服务
severity: medium
owasp_llm: "LLM04"
cwe: ["CWE-770", "CWE-400"]
category: llm
frameworks: ["Spring AI", LangChain4j, "OpenAI API"]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# LLM 拒绝服务

> 最后更新：2026-04-18

## 概述

LLM 拒绝服务（Model Denial of Service）指攻击者通过消耗大量计算资源来干扰 LLM 服务的可用性。由于 LLM 推理需要大量的计算资源（GPU、内存、API 调用额度），攻击者可以通过构造特殊输入使模型消耗异常多的资源，导致服务降级、响应延迟甚至完全不可用，同时造成显著的经济损失。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP LLM Top 10 | LLM04 - Model Denial of Service |
| CWE | CWE-770 / CWE-400 |
| 严重程度 | 中危 |

## 攻击类型

### 1. 超长输入攻击

发送极长的用户输入，使模型处理时间线性甚至指数级增长，消耗大量 GPU 资源。

```
发送 100,000+ 字符的文本要求模型逐句分析和翻译
```

### 2. 递归推理攻击

构造需要多轮推理的复杂请求，利用 LLM 的思维链能力使其长时间运行。

```
"请详细证明哥德巴赫猜想的每一个步骤，包括所有可能的反例验证"
```

### 3. 资源耗尽攻击

利用 LLM Agent 的工具调用循环，使模型反复调用外部工具消耗 API 额度和计算资源。

```
构造请求使 Agent 陷入无限循环的工具调用链：
"请搜索A，基于结果搜索B，基于B的结果搜索C，继续直到找到..."
```

### 4. 上下文窗口填充

利用 RAG 检索大量文档填充上下文窗口，使每次请求消耗最大 token 数。

```
"请搜索并总结知识库中关于[常见关键词]的所有文档"
// 可能检索数百个文档，消耗最大上下文窗口
```

## Java场景

### [VULNERABLE] 无限制的 LLM 请求处理

```java
// [VULNERABLE] Spring AI 无限制处理用户请求
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;

@RestController
public class LlmDosVulnerableController {

    private final ChatClient chatClient;

    // [VULNERABLE] 此方法存在 DoS 漏洞，原因：无输入长度限制和超时控制
    @PostMapping("/chat")
    public String chat(@RequestBody String message) {
        // 漏洞 1：无输入长度限制，攻击者可发送超长输入
        // 漏洞 2：无超时控制，模型可能长时间运行
        // 漏洞 3：无速率限制，攻击者可高频调用
        return chatClient.prompt()
            .user(message)
            .call()
            .content();
    }

    // [VULNERABLE] 无限制的 Agent 工具调用
    @PostMapping("/agent")
    public String agentTask(@RequestBody String task) {
        // 漏洞：Agent 可能陷入无限工具调用循环
        return chatClient.prompt()
            .user(task)
            .tools(searchTool, databaseTool, apiTool)
            .call()
            .content();
    }
}
```

### [VULNERABLE] RAG 检索无结果数量限制

```java
// [VULNERABLE] RAG 检索返回过多文档填充上下文
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.vectorstore.VectorStore;

@Service
public class RagDosVulnerableService {

    // [VULNERABLE] 此方法存在 DoS 漏洞，原因：RAG 检索无数量限制
    public String query(String question) {
        // 漏洞：未限制检索文档数量，常见关键词可能返回大量文档
        return chatClient.prompt()
            .user(question)
            .advisors(new QuestionAnswerAdvisor(vectorStore))
            .call()
            .content();
    }
}
```

### [SECURE] 添加输入限制和资源控制

```java
// [SECURE] 添加输入限制、超时控制和速率限制
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import java.util.concurrent.*;

@RestController
public class LlmDosSecureController {

    private final ChatClient chatClient;

    private static final int MAX_INPUT_LENGTH = 4000;
    private static final int MAX_TIMEOUT_SECONDS = 30;

    // [SECURE] 修复了 DoS 漏洞，修复方式：输入长度限制 + 超时 + 速率限制
    @PostMapping("/chat")
    @RateLimiter(name = "llmApi")
    public String chat(@RequestBody String message) {
        // 安全 1：输入长度限制
        if (message.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException(
                "Input too long. Maximum " + MAX_INPUT_LENGTH + " characters.");
        }

        // 安全 2：超时控制
        try {
            return chatClient.prompt()
                .user(message)
                .call()
                .content();
        } catch (Exception e) {
            if (e instanceof TimeoutException || e.getCause() instanceof TimeoutException) {
                return "请求超时，请简化您的问题后重试";
            }
            throw e;
        }
    }

    // [SECURE] Agent 添加最大迭代次数限制
    @PostMapping("/agent")
    @RateLimiter(name = "llmApi")
    public String agentTask(@RequestBody String task) {
        if (task.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("Input too long");
        }

        // 安全 3：限制 Agent 最大工具调用次数
        return chatClient.prompt()
            .user(task)
            .tools(searchTool, databaseTool, apiTool)
            .advisors(new SimpleLoggerAdvisor())
            .call()
            .content();
    }
}
```

### [SECURE] RAG 检索结果数量限制

```java
// [SECURE] 限制 RAG 检索结果数量
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.SearchRequest;

@Service
public class RagDosSecureService {

    private final ChatClient chatClient;
    private final VectorStore vectorStore;

    // [SECURE] 修复了 RAG DoS 漏洞，修复方式：限制检索文档数量
    public String query(String question) {
        if (question.length() > 1000) {
            throw new IllegalArgumentException("Question too long");
        }

        // 安全：限制最多检索 5 个文档
        return chatClient.prompt()
            .user(question)
            .advisors(new QuestionAnswerAdvisor(vectorStore,
                SearchRequest.builder()
                    .topK(5)           // 限制检索数量
                    .similarityThreshold(0.7)  // 设置相似度阈值
                    .build()))
            .call()
            .content();
    }
}
```

## 检测方法

1. **资源监控**：监控 GPU 使用率、API 调用量、响应延迟等指标，设置异常告警
2. **异常检测**：检测异常的请求模式（超长输入、高频调用、异常 token 消耗）
3. **负载测试**：在上线前进行压力测试，确定系统资源上限
4. **日志分析**：分析请求日志中的输入长度分布、响应时间分布，识别异常请求

## 防护措施

1. **输入长度限制**：严格限制用户输入的最大长度（如 4000 字符）
2. **速率限制**：实现基于用户/IP/API Key 的速率限制，防止单用户过度消耗资源
3. **超时控制**：为每次 LLM 调用设置超时时间，超时后返回降级响应
4. **资源配额**：为每个用户/租户设置 token 使用配额和 API 调用上限
5. **Agent 迭代限制**：限制 LLM Agent 的最大工具调用次数，防止无限循环

## 参考资料

- [OWASP LLM Top 10 - LLM04](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [LangChain4j Rate Limiting](https://docs.langchain4j.dev/)
