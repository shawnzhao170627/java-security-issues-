---
id: XSTREAM-DESERIALIZATION
name: XStream 反序列化 RCE
severity: critical
owasp: "A08:2025"
cwe: ["CWE-502"]
category: deserialization
frameworks: [XStream]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# XStream 反序列化 RCE

> 最后更新：2026-04-17

## 概述

XStream 是 Java 生态中广泛使用的 XML 序列化/反序列化库。其默认配置允许反序列化任意 Java 类，攻击者可构造恶意 XML 触发任意代码执行。历史上 XStream 存在大量 CVE 漏洞（CVE-2020-26217、CVE-2021-21341~21351、CVE-2021-39139~39154 等），利用链涉及 `ProcessBuilder`、`Runtime.exec()`、JNDI 注入等。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A08:2025 - Software and Data Integrity Failures |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| 严重程度 | 严重 |

## 攻击类型

### 1. ProcessBuilder RCE（CVE-2020-26217）

```xml
<!-- [VULNERABLE] 利用 ProcessBuilder 执行系统命令 -->
<java.lang.ProcessBuilder>
  <command>
    <string>calc</string>
  </command>
</java.lang.ProcessBuilder>
```

### 2. EventHandler JNDI 注入

```xml
<!-- [VULNERABLE] 利用 EventHandler 触发 JNDI 注入 -->
<java.beans.EventHandler>
  <target class="java.lang.ProcessBuilder">
    <command>
      <string>bash</string>
      <string>-c</string>
      <string>id</string>
    </command>
  </target>
  <action>start</action>
</java.beans.EventHandler>
```

### 3. TreeSet/TreeMap 利用链

```xml
<!-- [VULNERABLE] 利用 TreeSet 比较器触发代码执行 -->
<sorted-set>
  <java.lang.ProcessBuilder>
    <command>
      <string>id</string>
    </command>
    <redirectErrorStream>false</redirectErrorStream>
  </java.lang.ProcessBuilder>
</sorted-set>
```

### 4. ImageIO 利用链（CVE-2021-39154）

利用 `javax.imageio.ImageIO` 的内部类触发代码执行。

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 XStream 反序列化 RCE 漏洞，仅用于教学目的
// 漏洞类型：XSTREAM-DESERIALIZATION
// 风险等级：critical
// 对应文档：docs/vulnerabilities/deserialization/xstream-deserialization.md

import com.thoughtworks.xstream.XStream;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/xstream")
public class XStreamVulnerable {

    private final XStream xstream = new XStream(); // [VULNERABLE] 默认配置无安全限制

    // [VULNERABLE] 直接反序列化用户输入的 XML
    @PostMapping("/deserialize")
    public Object deserializeXml(@RequestBody String xml) {
        return xstream.fromXML(xml); // 任意类可被反序列化
    }

    // [VULNERABLE] 使用不安全的 XStream 实例
    @PostMapping("/parse")
    public Object parseXml(@RequestBody String xml) {
        XStream xs = new XStream();
        // 没有配置安全框架
        return xs.fromXML(xml);
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 XStream 反序列化漏洞的安全修复方案
// 修复方式：配置安全框架 / 白名单 / 升级版本
// 对应文档：docs/vulnerabilities/deserialization/xstream-deserialization.md

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/xstream")
public class XStreamSecure {

    private final XStream xstream;

    public XStreamSecure() {
        xstream = new XStream();

        // [SECURE] 方案1：使用 XStream 安全框架（XStream 1.4.18+）
        // 清除默认权限，仅允许特定类
        xstream.addPermission(NoTypePermission.NONE); // 禁止所有类
        xstream.addPermission(new WildcardTypePermission(
            new String[]{"com.example.dtos.**"} // 仅允许自己的 DTO
        ));
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES); // 允许基本类型
        xstream.addPermission(ArrayTypePermission.ARRAYS); // 允许数组
        xstream.addPermission(CollectionTypePermission.COLLECTIONS); // 允许集合
        xstream.addPermission(MapTypePermission.MAPS); // 允许 Map

        // [SECURE] 方案2：显式允许特定类
        xstream.allowTypes(new Class[]{
            com.example.dto.UserRequest.class,
            com.example.dto.OrderRequest.class
        });
    }

    @PostMapping("/deserialize")
    public Object deserializeXml(@RequestBody String xml) {
        // [SECURE] 安全框架会在反序列化时检查类是否在白名单中
        return xstream.fromXML(xml);
    }
}
```

## 检测方法

1. **静态分析**：搜索 `new XStream()` 无安全配置的实例，以及 `xstream.fromXML()` 调用
2. **依赖扫描**：检查 XStream 版本是否低于 1.4.18
3. **动态测试**：发送恶意 XML payload 测试

**Semgrep 规则**：

```yaml
rules:
  - id: java-xstream-unsafe
    patterns:
      - pattern: |
          new XStream()
      - pattern-not-inside: |
          $XS.addPermission(...)
    message: |
      检测到 XStream 实例未配置安全框架，可能导致任意类反序列化 RCE。
      建议：使用 xstream.addPermission() 配置白名单，或升级到 1.4.18+。
    severity: ERROR
    languages: [java]
    metadata:
      category: security
      subcategory: deserialization
      cwe: CWE-502
      references:
        - https://x-stream.github.io/security.html

  - id: java-xstream-fromxml-user-input
    patterns:
      - pattern: |
          $XS.fromXML($INPUT)
    message: |
      检测到 xstream.fromXML() 调用，确保输入来源可信且 XStream 已配置安全框架。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: deserialization
      cwe: CWE-502
```

## 防护措施

| 优先级 | 措施 | 说明 |
|--------|------|------|
| P0 | 升级 XStream 版本 | 升级到 1.4.20+，该版本默认启用安全框架 |
| P0 | 配置安全框架 | 使用 `addPermission(NoTypePermission.NONE)` + 白名单 |
| P1 | 限制允许的类型 | 使用 `allowTypes()` 或 `allowTypeHierarchy()` |
| P1 | 禁用危险类 | 使用 `xstream.denyTypes()` 禁止已知利用链 |
| P2 | 输入验证 | 对 XML 输入进行 Schema 验证 |
| P2 | 替换方案 | 考虑使用 Jackson XML 等更安全的序列化方案 |

### 版本对照表

| XStream 版本 | 安全状态 | 建议 |
|-------------|---------|------|
| < 1.4.18 | 不安全，默认无安全框架 | 必须升级 |
| 1.4.18 - 1.4.19 | 默认启用安全框架，但仍有绕过 | 建议升级 |
| >= 1.4.20 | 安全框架更完善 | 推荐使用 |

## 参考资料

- [XStream Security Page](https://x-stream.github.io/security.html)
- [CVE-2020-26217](https://nvd.nist.gov/vuln/detail/CVE-2020-26217)
- [CVE-2021-21341~21351](https://x-stream.github.io/security.html#CVE-2021-21341)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
