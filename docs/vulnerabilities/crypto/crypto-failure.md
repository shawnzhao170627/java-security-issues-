---
id: CRYPTO-FAILURE
name: 加密机制失效
severity: high
owasp: "A04:2025"
cwe: ["CWE-327", "CWE-798", "CWE-311"]
category: crypto
frameworks: [MessageDigest, Cipher, KeyStore, SecretKey]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 加密机制失效

> 最后更新：2026-04-18

## 概述

加密机制失效（Cryptographic Failures）指应用在数据保护方面使用了弱加密算法、不当的密钥管理或不安全的加密实现，导致敏感数据（如密码、个人信息、金融数据）可被攻击者获取或篡改。此类问题涵盖传输层加密不足、存储加密缺失、弱算法使用、密钥硬编码等多个方面。

在 Java 应用中，`MessageDigest`、`Cipher`、`KeyStore`、`SecretKey` 等加密 API 的不当使用是常见的安全隐患。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A04:2025 - Cryptographic Failures |
| CWE | CWE-327 / CWE-798 / CWE-311 |
| 严重程度 | 高危 |

## 攻击类型

### 1. 弱哈希算法

使用 MD5、SHA-1 等已被证明不安全的哈希算法存储密码或校验数据完整性，攻击者可利用彩虹表或碰撞攻击破解。

```java
// 弱算法：MD5 可被碰撞攻击
MessageDigest md = MessageDigest.getInstance("MD5");
```

### 2. 弱加密算法

使用 DES、3DES、RC4、AES-ECB 等已被证明不安全的加密算法，攻击者可通过已知攻击方法解密数据。

```java
// 弱算法：DES 密钥长度仅 56 位，可被暴力破解
Cipher cipher = Cipher.getInstance("DES");
```

### 3. 密钥硬编码与管理不当

将加密密钥硬编码在源代码或配置文件中，或使用默认密钥，导致密钥泄露后加密形同虚设。

```java
// 密钥硬编码：代码泄露即密钥泄露
String key = "MySecretKey12345";
```

### 4. 不安全的加密模式

使用 ECB 模式（相同明文产生相同密文）、缺少 IV/Nonce 初始化、未使用认证加密（AEAD）等导致数据可被推断或篡改。

```java
// 不安全模式：ECB 模式相同明文产生相同密文块
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

## Java场景

### [VULNERABLE] 使用 MD5 存储密码

```java
// [VULNERABLE] 使用 MD5 哈希存储密码，无盐值
import java.security.*;
import java.util.*;

public class CryptoVulnerableHash {

    // [VULNERABLE] 此方法存在加密机制失效漏洞，原因：使用 MD5 且无盐值
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        // 漏洞 1：MD5 已被证明不安全，存在碰撞攻击
        // 漏洞 2：未使用盐值，相同密码产生相同哈希，易被彩虹表破解
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashBytes = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}
```

### [VULNERABLE] 使用 DES/ECB 加密

```java
// [VULNERABLE] 使用弱加密算法和不安全模式
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

public class CryptoVulnerableCipher {

    private static final String KEY = "12345678"; // 8 字节 DES 密钥

    // [VULNERABLE] 此方法存在加密机制失效漏洞，原因：DES 弱算法 + ECB 模式 + 硬编码密钥
    public String encrypt(String plaintext) throws Exception {
        // 漏洞 1：DES 密钥长度仅 56 位，可被暴力破解
        // 漏洞 2：ECB 模式相同明文产生相同密文
        // 漏洞 3：密钥硬编码在源代码中
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
```

### [SECURE] 使用 bcrypt 和 AES-GCM

```java
// [SECURE] 使用安全算法和正确的加密实践
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import org.mindrot.jbcrypt.BCrypt;

public class CryptoSecure {

    // [SECURE] 修复了密码存储漏洞，修复方式：使用 bcrypt 自适应哈希
    public String hashPassword(String password) {
        // 安全：bcrypt 自动生成盐值，且工作因子可调节以抵御暴力破解
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    public boolean verifyPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }

    // [SECURE] 修复了加密漏洞，修复方式：使用 AES-GCM 认证加密 + 随机 IV
    public String encrypt(String plaintext, SecretKey key) throws Exception {
        // 安全：AES-256 + GCM 模式提供机密性和完整性保护
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // 安全：每次加密使用随机 IV
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // 将 IV 和密文一起存储（IV 不需要保密但需要唯一）
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + encrypted.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(encrypted);
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
}
```

## 检测方法

1. **静态分析**：使用 Semgrep、SonarQube 扫描代码中使用的加密算法和模式，检测 MD5、SHA-1、DES、ECB 等弱算法
2. **配置审计**：检查 `application.properties/yml` 中的加密配置，确认是否使用安全算法
3. **密钥扫描**：使用 TruffleHog、GitLeaks 等工具扫描代码仓库中的硬编码密钥和凭证
4. **协议分析**：使用 Wireshark 等工具检查网络通信是否使用 TLS 1.2+ 加密

## 防护措施

1. **使用强加密算法**：对称加密使用 AES-256-GCM，哈希使用 SHA-256+，密码存储使用 bcrypt/scrypt/Argon2
2. **正确使用加密模式**：使用 GCM/CCM 等认证加密模式，避免 ECB，每次加密使用随机 IV
3. **密钥安全管理**：使用 KMS（如 AWS KMS、HashiCorp Vault）管理密钥，禁止硬编码密钥
4. **传输层加密**：强制使用 TLS 1.2+，禁用弱密码套件
5. **密钥长度**：RSA 使用 2048+ 位密钥，AES 使用 256 位密钥，ECDSA 使用 P-256+ 曲线

## 参考资料

- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP Crypto Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
