---
id: HARDCODED-API-KEY
name: 硬编码 API 密钥
severity: critical
owasp: "A07:2025"
cwe: ["CWE-798"]
category: llm
frameworks: ["Spring AI", LangChain4j, "OpenAI SDK"]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 硬编码 API 密钥

> 最后更新：2026-04-18

## 概述

硬编码 API 密钥（Hardcoded API Key）指将 LLM 服务的 API 密钥（如 OpenAI API Key、Anthropic API Key）直接硬编码在 Java 源代码、配置文件或 Docker 镜像中。这是最常见但也最危险的安全问题之一——一旦代码仓库泄露或被访问，API 密钥即被暴露，攻击者可利用这些密钥冒用身份、消耗 API 额度、访问敏感数据。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A07:2025 - Identification and Authentication Failures |
| CWE | CWE-798 |
| 严重程度 | 严重 |

## 攻击类型

### 1. 源代码泄露

代码仓库（GitHub/GitLab）公开或被攻击后，硬编码的 API 密钥直接暴露。

```java
// 源代码中硬编码 OpenAI API Key
String apiKey = "sk-proj-abc123def456ghi789jkl012mno345";
```

### 2. 配置文件泄露

`application.properties/yml` 中包含明文 API 密钥，随应用包或 Docker 镜像一起分发。

```yaml
# application.yml 中明文存储 API Key
spring:
  ai:
    openai:
      api-key: sk-proj-abc123def456ghi789jkl012mno345
```

### 3. 反编译获取

Java 应用编译后的 class 文件中仍然包含硬编码的字符串常量，攻击者通过反编译即可获取密钥。

```bash
# 反编译 class 文件后可直接看到硬编码的密钥
javap -c -p AppConfig.class
# String apiKey = "sk-proj-abc123def456ghi789jkl012mno345";
```

### 4. 日志泄露

应用日志中意外打印了 API 密钥（如调试日志、异常堆栈中的配置信息）。

```
2026-04-18 10:00:00 DEBUG - Initializing OpenAI client with key: sk-proj-abc123...
```

## Java场景

### [VULNERABLE] 硬编码 OpenAI API Key

```java
// [VULNERABLE] 在源代码中硬编码 OpenAI API Key
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.web.bind.annotation.*;

@RestController
public class HardcodedKeyVulnerableController {

    // [VULNERABLE] 此代码存在硬编码密钥漏洞，原因：API Key 直接写在源代码中
    private static final String OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345";

    private final ChatClient chatClient;

    public HardcodedKeyVulnerableController() {
        // 漏洞：API Key 硬编码在源代码中，代码泄露即密钥泄露
        OpenAiApi api = OpenAiApi.builder()
            .apiKey(OPENAI_API_KEY)
            .build();
        OpenAiChatModel model = OpenAiChatModel.builder()
            .openAiApi(api)
            .build();
        this.chatClient = ChatClient.builder(model).build();
    }

    @GetMapping("/chat")
    public String chat(@RequestParam String message) {
        return chatClient.prompt().user(message).call().content();
    }
}
```

### [VULNERABLE] 配置文件明文存储密钥

```yaml
# [VULNERABLE] application.yml - 明文存储 API Key
spring:
  ai:
    openai:
      api-key: sk-proj-abc123def456ghi789jkl012mno345
      base-url: https://api.openai.com
    anthropic:
      api-key: sk-ant-api03-xyz789abc456def012ghi345
```

```java
// [VULNERABLE] 直接使用配置属性（明文存储在配置文件中）
@Configuration
public class HardcodedKeyVulnerableConfig {

    @Value("${spring.ai.openai.api-key}")
    private String openaiApiKey;  // 漏洞：从明文配置文件读取

    @Bean
    public ChatClient chatClient() {
        OpenAiApi api = OpenAiApi.builder()
            .apiKey(openaiApiKey)
            .build();
        return ChatClient.builder(
            OpenAiChatModel.builder().openAiApi(api).build()
        ).build();
    }
}
```

### [SECURE] 使用环境变量管理密钥

```java
// [SECURE] 使用环境变量注入 API Key
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.context.annotation.*;

@Configuration
public class HardcodedKeySecureConfig {

    // [SECURE] 修复了硬编码密钥漏洞，修复方式：从环境变量读取密钥
    @Bean
    public ChatClient chatClient() {
        // 安全 1：从环境变量读取 API Key，不在代码或配置文件中明文存储
        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(
                "OPENAI_API_KEY environment variable is not set");
        }

        OpenAiApi api = OpenAiApi.builder()
            .apiKey(apiKey)
            .build();
        OpenAiChatModel model = OpenAiChatModel.builder()
            .openAiApi(api)
            .build();
        return ChatClient.builder(model).build();
    }
}
```

### [SECURE] 使用 Spring 配置 + 密钥管理服务

```yaml
# [SECURE] application.yml - 使用环境变量占位符
spring:
  ai:
    openai:
      api-key: ${OPENAI_API_KEY}  # 安全：从环境变量注入
      base-url: ${OPENAI_BASE_URL:https://api.openai.com}
```

```java
// [SECURE] 使用 AWS Secrets Manager 等密钥管理服务
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

@Configuration
public class HardcodedKeySecureKmsConfig {

    private final SecretsManagerClient secretsClient;

    // [SECURE] 修复了硬编码密钥漏洞，修复方式：使用 KMS 动态获取密钥
    @Bean
    public ChatClient chatClient() {
        // 安全 2：从密钥管理服务动态获取 API Key
        String apiKey = getSecret("prod/openai-api-key");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("Failed to retrieve API key from KMS");
        }

        OpenAiApi api = OpenAiApi.builder()
            .apiKey(apiKey)
            .build();
        OpenAiChatModel model = OpenAiChatModel.builder()
            .openAiApi(api)
            .build();
        return ChatClient.builder(model).build();
    }

    private String getSecret(String secretName) {
        try {
            GetSecretValueRequest request = GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();
            return secretsClient.getSecretValue(request).secretString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve secret: " + secretName, e);
        }
    }
}
```

### [SECURE] 日志脱敏

```java
// [SECURE] 确保日志中不打印 API Key
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
public class SecureLoggingConfig {

    private static final Logger log = LoggerFactory.getLogger(SecureLoggingConfig.class);

    @Bean
    public ChatClient chatClient() {
        String apiKey = System.getenv("OPENAI_API_KEY");

        // 安全 3：日志中只打印密钥前4位，其余用星号替代
        if (apiKey != null) {
            log.info("OpenAI API Key loaded: {}...{}",
                apiKey.substring(0, 4),
                "*".repeat(Math.max(0, apiKey.length() - 4)));
        } else {
            log.error("OPENAI_API_KEY environment variable is not set");
            throw new IllegalStateException("API key not configured");
        }

        // ... 初始化 ChatClient
        OpenAiApi api = OpenAiApi.builder().apiKey(apiKey).build();
        OpenAiChatModel model = OpenAiChatModel.builder().openAiApi(api).build();
        return ChatClient.builder(model).build();
    }
}
```

## 检测方法

1. **静态分析**：使用 Semgrep、SonarQube 扫描代码中的硬编码字符串，检测 API Key 模式（如 `sk-proj-`、`sk-ant-`）
2. **密钥扫描**：使用 TruffleHog、GitLeaks 等工具扫描 Git 历史记录中的泄露密钥
3. **配置文件审计**：检查 `application.properties/yml`、Docker 环境文件中是否存在明文密钥
4. **日志审计**：检查应用日志中是否意外打印了 API Key

## 防护措施

1. **环境变量**：通过环境变量注入 API Key，代码和配置文件中不存储明文密钥
2. **密钥管理服务**：使用 AWS Secrets Manager、HashiCorp Vault、Azure Key Vault 等密钥管理服务
3. **配置加密**：如必须在配置文件中存储，使用 Jasypt 等工具对配置值加密
4. **Git 预提交钩子**：安装 GitLeaks 等预提交钩子，阻止包含密钥的代码提交
5. **密钥轮换**：定期轮换 API Key，限制每个密钥的权限和有效期

## 参考资料

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Hardcoded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [TruffleHog - 密钥扫描工具](https://github.com/trufflesecurity/trufflehog)
- [Spring Boot Externalized Configuration](https://docs.spring.io/spring-boot/reference/features/external-config.html)
