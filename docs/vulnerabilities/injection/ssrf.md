---
id: SSRF
name: 服务端请求伪造
severity: high
owasp: "A10:2025"
cwe: ["CWE-918"]
category: injection
frameworks: [HttpClient, HttpURLConnection, OkHttp, RestTemplate]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 服务端请求伪造（SSRF）

> 最后更新：2026-04-18

## 概述

服务端请求伪造（Server-Side Request Forgery，SSRF）是一种攻击方式，攻击者利用服务端发起网络请求的能力，诱导服务端访问内网资源或其他受保护的服务。通过 SSRF，攻击者可以扫描内网端口、访问内部服务、读取云元数据，甚至进一步渗透内网。

在 Java 应用中，`HttpClient`、`HttpURLConnection`、`OkHttp`、`RestTemplate`、`WebClient` 等 HTTP 客户端如果不正确校验用户提供的 URL，都可能导致 SSRF 漏洞。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A10:2025 - Server-Side Request Forgery |
| CWE | CWE-918 |
| 严重程度 | 高危 |

## 攻击类型

### 1. 内网端口扫描

攻击者通过修改 URL 参数中的 IP 和端口，探测内网存活服务和开放端口。

```
https://example.com/fetch?url=http://192.168.1.1:8080/
https://example.com/fetch?url=http://10.0.0.1:3306/
```

### 2. 云元数据访问

利用 SSRF 访问云服务商的元数据接口，获取临时凭证、实例信息等敏感数据。

```
# AWS 元数据
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP 元数据
http://metadata.google.internal/computeMetadata/v1/
# Azure 元数据
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### 3. 本地文件读取

通过 `file://` 协议读取服务端本地文件。

```
https://example.com/fetch?url=file:///etc/passwd
https://example.com/fetch?url=file:///proc/self/environ
```

### 4. 协议绕过与 DNS 重绑定

利用 URL 解析差异、DNS 重绑定等技术绕过 SSRF 防护。

```
# 十进制 IP 绕过
http://0x7f000001/  → 127.0.0.1
# DNS 重绑定：首次解析为外部 IP，后续解析为内网 IP
http://attacker-rebind.evil.com/
```

## Java场景

### [VULNERABLE] RestTemplate 未校验 URL

```java
// [VULNERABLE] RestTemplate 直接使用用户提供的 URL 发起请求
import org.springframework.web.client.RestTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class SsrfVulnerableController {

    private final RestTemplate restTemplate = new RestTemplate();

    // [VULNERABLE] 此方法存在 SSRF 漏洞，原因：用户可控制请求目标 URL
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) {
        // 漏洞：直接使用用户输入的 URL 发起请求，可访问内网资源
        // 攻击者可传入 http://169.254.169.254/ 获取云元数据
        // 攻击者可传入 http://192.168.1.1:8080/ 扫描内网
        return restTemplate.getForObject(url, String.class);
    }
}
```

### [VULNERABLE] HttpURLConnection 未校验目标地址

```java
// [VULNERABLE] HttpURLConnection 直接使用用户输入 URL
import java.io.*;
import java.net.*;

public class SsrfVulnerableService {

    // [VULNERABLE] 此方法存在 SSRF 漏洞，原因：未校验目标地址是否为内网
    public String fetchContent(String urlString) throws IOException {
        URL url = new URL(urlString);
        // 漏洞：未检查协议和目标 IP，可访问内网和本地文件
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }
}
```

### [SECURE] URL 白名单 + 内网 IP 过滤

```java
// [SECURE] 使用 URL 白名单和内网 IP 过滤防止 SSRF
import org.springframework.web.client.RestTemplate;
import org.springframework.web.bind.annotation.*;
import java.net.*;
import java.util.*;

@RestController
public class SsrfSecureController {

    private final RestTemplate restTemplate = new RestTemplate();

    // 允许的域名白名单
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.example.com",
        "cdn.example.com"
    );

    // [SECURE] 修复了 SSRF 漏洞，修复方式：URL 白名单 + 内网 IP 过滤
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) throws Exception {
        URL parsedUrl = new URL(url);

        // 1. 协议白名单：只允许 https
        if (!"https".equals(parsedUrl.getProtocol())) {
            throw new IllegalArgumentException("Only HTTPS protocol is allowed");
        }

        // 2. 域名白名单校验
        String host = parsedUrl.getHost();
        if (!ALLOWED_DOMAINS.contains(host)) {
            throw new IllegalArgumentException("Domain not in whitelist");
        }

        // 3. DNS 解析后校验 IP，防止 DNS 重绑定
        InetAddress address = InetAddress.getByName(host);
        if (isInternalIp(address)) {
            throw new IllegalArgumentException("Internal IP addresses are not allowed");
        }

        return restTemplate.getForObject(url, String.class);
    }

    private boolean isInternalIp(InetAddress address) {
        byte[] bytes = address.getAddress();
        // 10.0.0.0/8
        if (bytes[0] == 10) return true;
        // 172.16.0.0/12
        if (bytes[0] == (byte) 172 && (bytes[1] & 0xF0) == 16) return true;
        // 192.168.0.0/16
        if (bytes[0] == (byte) 192 && bytes[1] == (byte) 168) return true;
        // 127.0.0.0/8
        if (bytes[0] == 127) return true;
        // 169.254.0.0/16 (云元数据)
        if (bytes[0] == (byte) 169 && bytes[1] == (byte) 254) return true;
        // 0.0.0.0
        if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) return true;
        return false;
    }
}
```

## 检测方法

1. **静态分析**：使用 Semgrep 扫描 `RestTemplate`、`HttpClient`、`HttpURLConnection` 等调用中使用了用户可控 URL 的代码
2. **动态测试**：在 URL 参数中注入内网地址（如 `http://127.0.0.1:8080/`）、云元数据地址，观察响应
3. **Burp Suite SSRF 插件**：使用 Burp Suite 的 SSRF 检测插件自动化测试
4. **日志分析**：检查应用日志中是否存在异常的出站请求记录

## 防护措施

1. **URL 白名单**：只允许请求预定义的域名或 IP 列表，拒绝所有未授权的目标
2. **禁止内网访问**：DNS 解析后校验目标 IP，拒绝私有 IP 地址段（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、127.0.0.0/8、169.254.0.0/16）
3. **协议限制**：只允许 HTTPS 协议，禁止 `file://`、`gopher://`、`dict://` 等危险协议
4. **DNS 重绑定防护**：在发起请求前和连接建立后两次校验目标 IP，确保 DNS 解析结果一致
5. **网络隔离**：在防火墙层面限制应用服务器的出站连接，只允许访问必要的公共服务

## 参考资料

- [OWASP SSRF 攻击说明](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger: SSRF 攻击详解](https://portswigger.net/web-security/ssrf)
- [AWS Security: SSRF 防护指南](https://aws.amazon.com/blogs/security/defense-in-depth-aws-best-practices-for-ssrf-mitigation/)
