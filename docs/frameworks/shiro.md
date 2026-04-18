---
id: SHIRO
name: Shiro 安全
severity: critical
cwe: ["CWE-502"]
category: frameworks
frameworks: [Apache Shiro]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# Shiro 安全

> 最后更新：2026-04-18

## 概述

Apache Shiro 是 Java 生态中广泛使用的安全框架，提供认证、授权、加密和会话管理功能。Shiro 的 RememberMe 功能使用 AES 加密序列化的用户身份信息存储在 Cookie 中，但由于历史上使用硬编码默认密钥且未对反序列化数据进行完整性校验，攻击者可构造恶意 Cookie 触发反序列化 RCE。本文档整理 Shiro 框架相关的安全问题。

## 历史漏洞

### Shiro RememberMe 反序列化 RCE (CVE-2016-4437 / SHIRO-550)

| 属性 | 值 |
|------|------|
| CVE | CVE-2016-4437 |
| Bug ID | SHIRO-550 |
| 影响版本 | Apache Shiro < 1.2.5 |
| 严重程度 | 严重 |
| 利用条件 | 使用默认 RememberMe 密钥且 classpath 中存在可利用的 Gadget 链 |

**漏洞原理**：Shiro 的 CookieRememberMeManager 使用 AES-128-CBC 模式加密 RememberMe Cookie。在 1.2.4 及之前版本中，加密密钥为硬编码的默认值 `kPH+bIxk5D2deZiIxcaaaA==`。攻击者可以：

1. 使用已知默认密钥加密恶意序列化数据
2. 将加密后的数据设置为 `rememberMe` Cookie
3. Shiro 解密 Cookie 后反序列化数据
4. 利用 classpath 中的 Gadget 链（如 CommonsCollections、CommonsBeanutils 等）实现 RCE

**攻击流程**：
1. 探测目标是否使用 Shiro（检查 `rememberMe=deleteMe` 响应头）
2. 检测可用的加密密钥（常见默认密钥或泄露密钥）
3. 使用 ysoserial 等工具生成恶意序列化 Gadget
4. 使用已知密钥 AES 加密恶意数据
5. Base64 编码后设置为 `rememberMe` Cookie
6. 发送请求触发反序列化

**检测方法**：
```bash
# 检测 Shiro 框架（响应中含 rememberMe=deleteMe）
curl -I http://target
# 或发送无效 rememberMe Cookie
curl -b "rememberMe=1" -I http://target
# 若返回 Set-Cookie: rememberMe=deleteMe，则确认使用 Shiro

# 使用 Shiro 漏洞检测工具
python shiro_exploit.py -u http://target -k kPH+bIxk5D2deZiIxcaaaA==
```

**修复措施**：
```xml
<!-- 升级 Shiro 到安全版本 -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.13.0</version>
</dependency>
```

---

### Shiro Padding Oracle 攻击 (CVE-2019-12422 / SHIRO-682)

| 属性 | 值 |
|------|------|
| CVE | CVE-2019-12422 |
| Bug ID | SHIRO-682 |
| 影响版本 | Apache Shiro < 1.4.2 |
| 严重程度 | 高危 |
| 利用条件 | 使用 CBC 模式的 RememberMe 加密 |

**漏洞原理**：Shiro 使用 AES-CBC 模式加密 RememberMe Cookie，但没有使用 HMAC 等机制验证密文完整性。攻击者可以利用 Padding Oracle 攻击：通过向服务器发送修改后的 Cookie 并观察服务器的不同响应（正常解密 vs 填充错误），逐字节推断出明文或构造合法密文，从而在不知道密钥的情况下也能伪造恶意 RememberMe Cookie。

**攻击条件**：
- Shiro 使用 CBC 模式加密（默认行为）
- 服务器对填充错误和正常错误有不同的响应（区分 Oracle）
- 攻击者可以获取一个有效的 RememberMe Cookie

**修复措施**：
```xml
<!-- 升级 Shiro 到 1.4.2+，使用 GCM 模式替代 CBC -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.4.2</version>
</dependency>
```

---

## 常见安全问题

### 1. 使用默认 RememberMe 密钥

```java
// [VULNERABLE] 使用默认密钥（或常见泄露密钥）
@Bean
public CookieRememberMeManager rememberMeManager() {
    CookieRememberMeManager manager = new CookieRememberMeManager();
    // 默认密钥 kPH+bIxk5D2deZiIxcaaaA== 或其他常见密钥
    return manager;
}
```

```java
// [SECURE] 使用强随机密钥，且定期轮换
@Bean
public CookieRememberMeManager rememberMeManager() {
    CookieRememberMeManager manager = new CookieRememberMeManager();
    // 使用安全的随机密钥（至少 128 位）
    byte[] cipherKey = org.apache.shiro.codec.Base64.decode("YourSecureRandomBase64KeyHere==");
    manager.setCipherKey(cipherKey);
    return manager;
}
```

### 2. 未配置反序列化过滤器

```java
// [VULNERABLE] Shiro < 1.4.2 默认不限制反序列化类
// 攻击者可利用 classpath 中的 Gadget 链
```

```java
// [SECURE] 升级 Shiro 并配置反序列化过滤器
@Bean
public CookieRememberMeManager rememberMeManager() {
    CookieRememberMeManager manager = new CookieRememberMeManager();
    // Shiro 1.4.2+ 支持配置反序列化过滤器
    manager.setCipherKey(generateSecureKey());
    // 限制可反序列化的类
    // Shiro 2.x 默认使用反序列化过滤器
    return manager;
}
```

### 3. Shiro 版本过旧

```xml
<!-- [VULNERABLE] 使用存在漏洞的旧版本 -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.2.4</version>
</dependency>
```

```xml
<!-- [SECURE] 使用安全版本 -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.13.0</version>
</dependency>
```

### 4. RememberMe Cookie 配置不安全

```java
// [VULNERABLE] RememberMe Cookie 配置不安全
@Bean
public SimpleCookie rememberMeCookie() {
    SimpleCookie cookie = new SimpleCookie("rememberMe");
    cookie.setMaxAge(2592000);  // 30 天
    cookie.setHttpOnly(false);  // 允许 JS 访问
    cookie.setSecure(false);    // 允许 HTTP 传输
    return cookie;
}
```

```java
// [SECURE] 安全的 Cookie 配置
@Bean
public SimpleCookie rememberMeCookie() {
    SimpleCookie cookie = new SimpleCookie("rememberMe");
    cookie.setMaxAge(86400);    // 缩短为 1 天
    cookie.setHttpOnly(true);   // 禁止 JS 访问
    cookie.setSecure(true);     // 仅 HTTPS 传输
    cookie.setSameSite(SimpleCookie.SameSiteOptions.LAX);  // 防止 CSRF
    return cookie;
}
```

## 安全配置建议

### 1. 生成并配置安全密钥

```java
// 生成安全的 AES 密钥
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class ShiroKeyGenerator {
    public static String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);  // 使用 256 位密钥
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}
```

```yaml
# 将密钥配置在环境变量或密钥管理服务中
shiro:
  cipherKey: ${SHIRO_CIPHER_KEY}
```

### 2. 完整的安全 Shiro 配置

```java
@Configuration
public class ShiroConfig {

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(customRealm());
        securityManager.setRememberMeManager(rememberMeManager());
        return securityManager;
    }

    @Bean
    public CookieRememberMeManager rememberMeManager() {
        CookieRememberMeManager manager = new CookieRememberMeManager();
        // 使用安全的随机密钥
        byte[] cipherKey = org.apache.shiro.codec.Base64.decode(
            System.getenv("SHIRO_CIPHER_KEY")
        );
        manager.setCipherKey(cipherKey);
        return manager;
    }

    @Bean
    public SimpleCookie rememberMeCookie() {
        SimpleCookie cookie = new SimpleCookie("rememberMe");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(86400);
        return cookie;
    }
}
```

### 3. 考虑禁用 RememberMe 功能

```java
// 如果业务不需要"记住我"功能，直接禁用
@Bean
public SecurityManager securityManager() {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    securityManager.setRealm(customRealm());
    // 不设置 RememberMeManager
    return securityManager;
}
```

### 4. 清理 classpath 中的危险 Gadget

```xml
<!-- 检查并移除不必要的依赖，减少 Gadget 链可用性 -->
<!-- 常见危险 Gadget 来源 -->
<!-- commons-collections3.x / 4.x -->
<!-- commons-beanutils -->
<!-- spring-core / spring-beans -->
<!-- 确保仅保留必要的依赖 -->
```

## 参考资料

- [Apache Shiro 安全公告](https://shiro.apache.org/security-reports.html)
- [CVE-2016-4437 详情](https://nvd.nist.gov/vuln/detail/CVE-2016-4437)
- [SHIRO-550 Issue](https://issues.apache.org/jira/browse/SHIRO-550)
- [CVE-2019-12422 详情](https://nvd.nist.gov/vuln/detail/CVE-2019-12422)
- [Shiro Padding Oracle 攻击分析](https://blog.zsec.uk/shiro-rememberme-1/)
- [Apache Shiro 官方文档](https://shiro.apache.org/reference.html)
