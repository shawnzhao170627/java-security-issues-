---
id: LLM-SUPPLY-CHAIN
name: LLM 供应链漏洞
severity: critical
owasp_llm: "LLM05"
cwe: ["CWE-1104", "CWE-502"]
category: llm
frameworks: [LangChain4j, DJL, "ONNX Runtime", 预训练模型]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# LLM 供应链漏洞

> 最后更新：2026-04-18

## 概述

LLM 供应链漏洞（LLM Supply Chain Vulnerabilities）指在使用 LLM 相关组件（预训练模型、框架、库、插件）的过程中，因使用了含有漏洞或恶意的组件而导致的安全风险。LLM 应用的供应链比传统软件更复杂，涵盖了模型权重、训练数据、推理框架、插件系统等多个环节。

在 Java 生态中，LangChain4j、DJL（Deep Java Library）、ONNX Runtime、TensorFlow Java 等框架的依赖安全，以及 HuggingFace 等模型仓库中预训练模型的可信度，都是供应链安全的关键关注点。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP LLM Top 10 | LLM05 - Supply Chain Vulnerabilities |
| CWE | CWE-1104 / CWE-502 |
| 严重程度 | 严重 |

## 攻击类型

### 1. 恶意预训练模型

攻击者在模型仓库（如 HuggingFace）上传含有后门的预训练模型，当应用加载该模型时触发恶意行为。

```
模型后门：当输入包含特定关键词时，模型输出攻击者预设的内容
如：当用户输入"安全审计"时，模型回复"系统安全，无任何漏洞"
```

### 2. 恶意依赖包（Typosquatting）

攻击者发布与热门 LLM 库名称相似的恶意包，开发者误安装后导致代码执行。

```
合法包：langchain4j
恶意包：langchain4j-core（名称相似，含恶意代码）
```

### 3. 过时依赖漏洞

使用含有已知安全漏洞的旧版本 LLM 框架或推理引擎，攻击者可利用公开漏洞进行攻击。

```
使用旧版 TensorFlow Java 存在已知的反序列化漏洞 CVE-20XX-XXXXX
```

### 4. 模型文件篡改

在模型下载或传输过程中，中间人攻击篡改模型文件，植入恶意权重或代码。

```
通过 MITM 攻击替换模型文件中的权重层，使模型在特定输入时产生异常输出
```

## Java场景

### [VULNERABLE] 加载未验证来源的模型

```java
// [VULNERABLE] DJL 加载未验证来源的预训练模型
import ai.djl.ModelException;
import ai.djl.repository.zoo.*;
import ai.djl.translate.TranslateException;

public class SupplyChainVulnerableService {

    // [VULNERABLE] 此方法存在供应链漏洞，原因：加载未验证来源和完整性的模型
    public String predict(String input) throws ModelException, TranslateException {
        // 漏洞：从任意 URL 加载模型，未验证来源和签名
        Criteria<String, String> criteria = Criteria.builder()
            .setTypes(String.class, String.class)
            .optModelUrls("https://untrusted-model-repo.com/models/sentiment/")
            .optEngine("PyTorch")
            .build();

        try (ZooModel<String, String> model = criteria.loadModel();
             Predictor<String, String> predictor = model.newPredictor()) {
            return predictor.predict(input);
        }
    }
}
```

### [VULNERABLE] 使用未固定版本的依赖

```xml
<!-- [VULNERABLE] pom.xml 使用不固定版本和不可信仓库 -->
<dependencies>
    <!-- 漏洞 1：使用 LATEST 版本，可能引入含漏洞的新版本 -->
    <dependency>
        <groupId>dev.langchain4j</groupId>
        <artifactId>langchain4j</artifactId>
        <version>LATEST</version>
    </dependency>

    <!-- 漏洞 2：使用不可信的第三方仓库 -->
</dependencies>

<repositories>
    <repository>
        <id>untrusted-repo</id>
        <url>https://untrusted-maven-repo.com/</url>
    </repository>
</repositories>
```

### [SECURE] 验证模型来源和完整性

```java
// [SECURE] 加载经过验证的模型，检查签名和哈希
import ai.djl.ModelException;
import ai.djl.repository.zoo.*;
import ai.djl.translate.TranslateException;
import java.security.*;

public class SupplyChainSecureService {

    // 模型哈希白名单
    private static final Map<String, String> MODEL_HASH_WHITELIST = Map.of(
        "sentiment-analysis-v1", "sha256:a1b2c3d4e5f6..."
    );

    // [SECURE] 修复了供应链漏洞，修复方式：验证模型来源 + 完整性校验
    public String predict(String input) throws ModelException, TranslateException {
        // 安全 1：只从官方/可信仓库加载模型
        Criteria<String, String> criteria = Criteria.builder()
            .setTypes(String.class, String.class)
            .optModelUrls("https://huggingface.co/official-org/sentiment-model")
            .optEngine("PyTorch")
            .optFilter("name", "sentiment-analysis-v1")
            .build();

        try (ZooModel<String, String> model = criteria.loadModel();
             Predictor<String, String> predictor = model.newPredictor()) {

            // 安全 2：验证模型文件哈希
            String modelPath = model.getModelPath().toString();
            String actualHash = calculateSHA256(modelPath);
            String expectedHash = MODEL_HASH_WHITELIST.get("sentiment-analysis-v1");
            if (!expectedHash.equals(actualHash)) {
                throw new SecurityException("Model integrity check failed");
            }

            return predictor.predict(input);
        }
    }

    private String calculateSHA256(String filePath) throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        byte[] hashBytes = digest.digest(fileBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return "sha256:" + sb;
    }
}
```

### [SECURE] 固定依赖版本 + 安全扫描

```xml
<!-- [SECURE] pom.xml 固定版本 + 安全扫描插件 -->
<dependencies>
    <!-- 安全：使用固定版本号 -->
    <dependency>
        <groupId>dev.langchain4j</groupId>
        <artifactId>langchain4j</artifactId>
        <version>1.0.0-beta1</version>
    </dependency>

    <dependency>
        <groupId>ai.djl.onnxruntime</groupId>
        <artifactId>onnxruntime-engine</artifactId>
        <version>0.26.0</version>
    </dependency>
</dependencies>

<!-- 安全：集成 OWASP Dependency-Check -->
<plugins>
    <plugin>
        <groupId>org.owasp</groupId>
        <artifactId>dependency-check-maven</artifactId>
        <version>9.0.0</version>
        <executions>
            <execution>
                <goals>
                    <goal>check</goal>
                </goals>
            </execution>
        </executions>
        <configuration>
            <failBuildOnCVSS>7</failBuildOnCVSS>
        </configuration>
    </plugin>
</plugins>
```

## 检测方法

1. **依赖扫描**：使用 OWASP Dependency-Check、Snyk、Trivy 等工具扫描项目依赖中的已知漏洞
2. **模型签名验证**：验证预训练模型的数字签名或哈希值，确保模型未被篡改
3. **行为分析**：对加载的模型进行对抗性测试，检测是否存在后门行为
4. **软件物料清单（SBOM）**：生成和维护 SBOM，追踪所有组件的来源和版本

## 防护措施

1. **固定依赖版本**：始终使用固定版本号（禁止 LATEST/SNAPSHOT），定期更新到安全版本
2. **来源验证**：只从官方仓库和可信来源获取模型和依赖，验证数字签名
3. **完整性校验**：对下载的模型文件计算哈希值并与官方公布的哈希对比
4. **私有仓库**：建立内部模型仓库和 Maven 仓库，所有组件经过安全审核后才可使用
5. **自动化安全扫描**：在 CI/CD 流水线中集成依赖漏洞扫描，阻止含漏洞的构建上线

## 参考资料

- [OWASP LLM Top 10 - LLM05](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
- [HuggingFace Model Security](https://huggingface.co/docs/hub/security)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
