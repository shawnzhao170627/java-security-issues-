---
id: JAVA-RMI
name: Java RMI 反序列化攻击
severity: high
owasp: A08:2025
cwe: [CWE-502, CWE-976]
category: deserialization
frameworks: [Java RMI, JMX, Spring RMI]
last_updated: 2026-04-17
doc_version: "1.0"
---

# Java RMI 反序列化攻击

> 最后更新：2026-04-17

## 概述

Java RMI（Remote Method Invocation）使用 Java 原生序列化进行远程通信。如果 RMI Registry 或 RMI 服务暴露在不可信网络中，攻击者可以通过绑定恶意对象或利用 RMI 协议的反序列化缺陷实现远程代码执行。常见攻击面包括 RMI Registry（1099 端口）、JMX RMI（默认 9010 端口）、Spring HTTP Invoker 等。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A08:2025 - Software and Data Integrity Failures |
| CWE | CWE-502 (Deserialization of Untrusted Data), CWE-976 (Security Misconfiguration) |
| 严重程度 | 高危 |

## 攻击类型

### 1. RMI Registry 绑定恶意对象

攻击者连接 RMI Registry 后，可以绑定一个恶意 Remote 对象，当客户端 lookup 并调用时触发反序列化。

```java
// [VULNERABLE] 未配置安全的 RMI Registry
import java.rmi.registry.*;

Registry registry = LocateRegistry.createRegistry(1099);
// 无认证、无 SSL、无安全策略，任何人都可以 bind/rebind
```

### 2. ysoserial RMI 攻击

使用 ysoserial 工具利用 RMI 通信中的反序列化：

```bash
# 攻击 RMI Registry
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit target_host 1099 CommonsCollections6 "id"

# 攻击 JMX
java -cp ysoserial.jar ysoserial.exploit.JMXInvokerMBean target_host 9010 CommonsCollections6 "id"
```

### 3. JMX RMI 反序列化

JMX 默认使用 RMI 协议通信，如果 JMX 端口暴露且未配置认证：

```bash
# JMX 未认证访问
java -jar jmx-client.jar service:jmx:rmi:///jndi/rmi://target:9010/jmxrmi
```

### 4. Spring HTTP Invoker 反序列化

Spring HTTP Invoker 使用 Java 原生序列化进行远程调用：

```java
// [VULNERABLE] Spring HTTP Invoker 无安全配置
@Bean
public HttpInvokerServiceExporter userService() {
    HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter();
    exporter.setService(userService);
    exporter.setServiceInterface(UserService.class);
    return exporter; // 无反序列化过滤
}
```

### 5. DGC（Distributed Garbage Collection）攻击

RMI 的 DGC 层使用反序列化，即使不经过 Registry 也可以通过 DGC 层发起攻击。

## Java 场景

### 漏洞代码

```java
// [VULNERABLE] 文件说明：演示 Java RMI 反序列化攻击，仅用于教学目的
// 漏洞类型：JAVA-RMI
// 风险等级：high
// 对应文档：docs/vulnerabilities/deserialization/java-rmi.md

import java.rmi.*;
import java.rmi.registry.*;
import org.springframework.remoting.httpinvoker.*;

// [VULNERABLE] 无安全配置的 RMI Registry
public class RmiVulnerable {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        // 没有配置 SSL、认证、安全策略
        // 任何人都可以 bind/rebind/lookup
        UserService service = new UserServiceImpl();
        Naming.rebind("rmi://0.0.0.0:1099/UserService", service);
    }
}

// [VULNERABLE] Spring HTTP Invoker 无过滤
@RestController
public class InvokerVulnerable {
    @Bean
    public HttpInvokerServiceExporter userServiceExporter() {
        HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter();
        exporter.setService(new UserServiceImpl());
        exporter.setServiceInterface(UserService.class);
        return exporter; // 无反序列化过滤器
    }
}
```

### 安全代码

```java
// [SECURE] 文件说明：演示 Java RMI 反序列化攻击的安全修复方案
// 修复方式：JEP 290 过滤器 / SSL / 认证 / 网络隔离
// 对应文档：docs/vulnerabilities/deserialization/java-rmi.md

import java.rmi.*;
import java.rmi.registry.*;
import java.io.*;

// [SECURE] 方案1：配置 JEP 290 反序列化过滤（Java 9+）
public class RmiSecure {
    public static void main(String[] args) throws Exception {
        // JVM 级别配置反序列化过滤器
        // 在启动参数中添加：
        // -Djava.rmi.server.useCodebaseOnly=true
        // -Dsun.rmi.registry.registry.filter=com.example.**
        // -Djdk.serialFilter=!com.mchange.**,!org.apache.commons.**,com.example.**

        // [SECURE] 方案2：使用 SSL 加密 RMI 通信
        // 设置 RMI Socket Factory
        RMISocketFactory sf = new SslRMISocketFactory();
        RMISocketFactory.setSocketFactory(sf);

        Registry registry = LocateRegistry.createRegistry(1099, sf, sf);

        // [SECURE] 方案3：限制 Registry bind 权限
        // 使用自定义 Registry 实现，只允许本地 bind
        UserService service = new UserServiceImpl();
        Naming.rebind("rmi://127.0.0.1:1099/UserService", service);
    }
}

// [SECURE] Spring HTTP Invoker 替换方案
@Configuration
public class SecureInvokerConfig {
    // [SECURE] 推荐替换为 REST/gRPC，不再使用 HTTP Invoker
    // 如果必须使用，配置反序列化过滤器

    // JEP 290 过滤器配置（在 application.properties 中）
    // -Djdk.serialFilter=com.example.dto.**;!*
}
```

## 检测方法

1. **端口扫描**：检测 1099（RMI Registry）、9010（JMX）等端口暴露
2. **静态分析**：搜索 `LocateRegistry.createRegistry()`、`HttpInvokerServiceExporter`
3. **动态测试**：使用 ysoserial 工具测试 RMI 反序列化

**Semgrep 规则**：

```yaml
rules:
  - id: java-rmi-unsafe-registry
    patterns:
      - pattern: |
          LocateRegistry.createRegistry(...)
    message: |
      检测到 RMI Registry 创建，确保配置了 JEP 290 过滤器和网络安全策略。
      建议：使用 -Djdk.serialFilter 配置反序列化白名单。
    severity: WARNING
    languages: [java]
    metadata:
      category: security
      subcategory: deserialization
      cwe: CWE-502

  - id: java-spring-http-invoker
    patterns:
      - pattern: |
          new HttpInvokerServiceExporter()
    message: |
      检测到 Spring HTTP Invoker 使用，其基于 Java 原生序列化，存在反序列化风险。
      建议：替换为 REST API 或 gRPC。
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
| P0 | 配置 JEP 290 过滤器 | 限制 RMI 可反序列化的类白名单 |
| P0 | 网络隔离 | RMI 端口不暴露到公网，仅限内网访问 |
| P1 | 启用 SSL | 使用 `SslRMISocketFactory` 加密通信 |
| P1 | 配置认证 | JMX 配置密码认证，Registry 限制 bind 权限 |
| P1 | 设置 useCodebaseOnly | `-Djava.rmi.server.useCodebaseOnly=true` |
| P2 | 替换协议 | 使用 REST/gRPC 替代 RMI/HTTP Invoker |
| P2 | 升级 JDK | JDK 9+ 默认包含 JEP 290 过滤器支持 |

### JEP 290 配置参考

```properties
# JDK 全局反序列化过滤器（JDK 9+）
# 允许 com.example 包下的类，禁止其他所有类
-Djdk.serialFilter=com.example.**;!*

# RMI Registry 专用过滤器
-Dsun.rmi.registry.registry.filter=com.example.rmi.**

# RMI DGC 过滤器
-Dsun.rmi.transport.dgc.filter=com.example.**

# 禁止远程代码加载
-Djava.rmi.server.useCodebaseOnly=true
```

## 参考资料

- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [ysoserial RMI Exploit](https://github.com/frohoff/ysoserial)
- [Java RMI Security](https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/security.html)
- [Spring HTTP Invoker Security](https://docs.spring.io/spring-framework/reference/remoting.html)
