# OWASP Top 10:2025 中文详解

> 最后更新：2026-04-17

## 概述

OWASP Top 10 是由开放 Web 应用安全项目（OWASP）发布的 Web 应用安全风险 Top 10 排名，代表了当前最常见和最严重的 Web 应用安全风险。

## 2025 版完整列表

| 排名 | 编号 | 名称 | 说明 |
|------|------|------|------|
| 1 | A01:2025 | Broken Access Control | 访问控制失效 |
| 2 | A02:2025 | Security Misconfiguration | 安全配置错误 |
| 3 | A03:2025 | Software Supply Chain Failures | 软件供应链失效 |
| 4 | A04:2025 | Cryptographic Failures | 加密机制失效 |
| 5 | A05:2025 | Injection | 注入攻击 |
| 6 | A06:2025 | Insecure Design | 不安全设计 |
| 7 | A07:2025 | Authentication Failures | 身份认证失效 |
| 8 | A08:2025 | Software or Data Integrity Failures | 软件/数据完整性失效 |
| 9 | A09:2025 | Security Logging and Alerting Failures | 安全日志与告警失效 |
| 10 | A10:2025 | Mishandling of Exceptional Conditions | 异常条件处理不当 |

---

## A01:2025 - Broken Access Control（访问控制失效）

### 描述

访问控制失效是指系统未能正确实施对认证用户的权限限制，导致用户可以越权访问资源或执行操作。

### 常见场景

- 越权访问其他用户的数据（水平越权）
- 越权访问管理功能（垂直越权）
- 通过修改 URL、参数或会话状态绕过访问控制
- API 接口未做权限校验

### Java 相关示例

```java
// 漏洞代码：未校验用户是否有权限访问该订单
@GetMapping("/order/{id}")
public Order getOrder(@PathVariable Long id) {
    return orderRepository.findById(id);
}

// 安全代码：校验当前用户是否有权限
@GetMapping("/order/{id}")
public Order getOrder(@PathVariable Long id, Principal principal) {
    Order order = orderRepository.findById(id);
    if (!order.getOwner().equals(principal.getName())) {
        throw new AccessDeniedException("无权访问此订单");
    }
    return order;
}
```

### 防护措施

1. 实施基于角色的访问控制（RBAC）
2. 默认拒绝所有访问，仅开放必要权限
3. 在服务端进行权限校验，不依赖前端控制
4. 使用成熟的权限框架（如 Spring Security）

### 相关 CWE

- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-284: Improper Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key

---

## A02:2025 - Security Misconfiguration（安全配置错误）

### 描述

安全配置错误是最常见的安全问题之一，通常由于不安全的默认配置、不完整的配置、开放的存储、错误的 HTTP 头部配置等导致。

### 常见场景

- 使用默认账户和密码
- 目录列表未关闭
- 生产环境开启调试模式
- 错误信息暴露堆栈细节
- 不必要的功能或服务未关闭

### Java 相关示例

```yaml
# 漏洞配置：生产环境开启调试模式
spring:
  profiles:
    active: dev
  devtools:
    add-properties: false

# 安全配置：生产环境配置
spring:
  profiles:
    active: prod
  devtools:
    restart:
      enabled: false
```

```java
// 漏洞代码：禁用 SSL 证书验证
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
```

### 防护措施

1. 删除或禁用默认账户
2. 关闭目录列表和调试模式
3. 自定义错误页面，不暴露堆栈信息
4. 定期审计配置
5. 使用配置管理工具

### 相关 CWE

- CWE-16: Configuration
- CWE-260: Default Password
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory

---

## A03:2025 - Software Supply Chain Failures（软件供应链失效）

### 描述

软件供应链失效是指在使用第三方组件、库或服务时引入的安全风险，包括使用含有已知漏洞的依赖、未经授权的依赖更新等。

### 常见场景

- 使用含有已知漏洞的第三方库（如 Log4j2 2.14.1）
- 依赖被恶意篡改
- 未验证依赖的完整性
- 使用不受信任的依赖源

### Java 相关示例

```xml
<!-- 漏洞配置：使用含有漏洞的版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version> <!-- 存在 CVE-2021-44228 -->
</dependency>

<!-- 安全配置：使用修复后的版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.24.3</version>
</dependency>
```

### 防护措施

1. 使用 OWASP Dependency-Check 或 Snyk 检测依赖漏洞
2. 锁定依赖版本，使用 dependency-lock
3. 使用私有仓库和代理
4. 验证依赖签名和完整性
5. 定期更新依赖

### 相关 CWE

- CWE-1104: Use of Unmaintained Third Party Components
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere

---

## A04:2025 - Cryptographic Failures（加密机制失效）

### 描述

加密机制失效（原 A02:2017 Sensitive Data Exposure）涉及敏感数据的保护不足，包括传输中和存储中的数据。

### 常见场景

- 使用弱加密算法（MD5、SHA1、DES）
- 密钥硬编码在代码中
- 密钥管理不当
- 敏感数据明文传输或存储

### Java 相关示例

```java
// 漏洞代码：使用 MD5 存储密码
public String hashPassword(String password) {
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(password.getBytes()));
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

// 安全代码：使用 BCrypt 加密
public String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
}
```

### 防护措施

1. 使用强加密算法（AES-256-GCM、SHA-256+）
2. 密码使用 BCrypt/Argon2 加密
3. 密钥使用密钥管理服务（KMS）
4. 传输层使用 TLS 1.2+
5. 敏感数据最小化存储

### 相关 CWE

- CWE-327: Use of Broken or Risky Cryptographic Algorithm
- CWE-798: Use of Hard-coded Credentials
- CWE-311: Missing Encryption of Sensitive Data

---

## A05:2025 - Injection（注入攻击）

### 描述

注入攻击是指用户输入被解释为代码执行，包括 SQL 注入、XSS、命令注入等。

### 常见场景

- SQL 注入：用户输入拼接到 SQL 语句
- XSS：用户输入未转义输出到页面
- 命令注入：用户输入拼接到系统命令
- LDAP/XPath/NoSQL 注入

### Java 相关示例

```java
// 漏洞代码：SQL 拼接
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, User.class);
}

// 安全代码：参数化查询
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = ?";
    return jdbcTemplate.queryForObject(sql, User.class, username);
}
```

### 防护措施

1. 使用参数化查询/预编译语句
2. 对用户输入进行校验和转义
3. 使用 ORM 框架的安全 API
4. 最小权限原则（数据库用户权限）
5. 输出编码（防 XSS）

### 相关 CWE

- CWE-89: SQL Injection
- CWE-79: Cross-site Scripting (XSS)
- CWE-78: OS Command Injection
- CWE-94: Code Injection

---

## A06:2025 - Insecure Design（不安全设计）

### 描述

不安全设计是指在系统设计阶段未能考虑安全需求，导致架构层面存在安全缺陷。

### 常见场景

- 业务流程可被绕过
- 缺乏安全控制设计
- 威胁建模不完整
- 安全需求未纳入设计

### 防护措施

1. 安全设计原则（最小权限、纵深防御）
2. 威胁建模（STRIDE）
3. 安全需求分析
4. 安全架构评审

### 相关 CWE

- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-693: Protection Mechanism Failure

---

## A07:2025 - Authentication Failures（身份认证失效）

### 描述

身份认证失效涉及用户身份验证机制的缺陷，导致攻击者可以冒充合法用户。

### 常见场景

- 弱密码策略
- 暴力破解无防护
- Session 管理不当
- 认证绕过

### Java 相关示例

```java
// 漏洞代码：无登录失败限制
@PostMapping("/login")
public String login(String username, String password) {
    if (userService.authenticate(username, password)) {
        return "redirect:/home";
    }
    return "login?error=1";
}

// 安全代码：登录失败限制
@PostMapping("/login")
public String login(String username, String password) {
    if (rateLimiter.isBlocked(username)) {
        return "login?error=locked";
    }
    if (userService.authenticate(username, password)) {
        rateLimiter.reset(username);
        return "redirect:/home";
    }
    rateLimiter.recordFailure(username);
    return "login?error=1";
}
```

### 防护措施

1. 强密码策略
2. 多因素认证（MFA）
3. 登录失败锁定
4. Session 安全管理
5. 使用成熟认证框架

### 相关 CWE

- CWE-306: Missing Authentication for Critical Function
- CWE-384: Session Fixation
- CWE-287: Improper Authentication

---

## A08:2025 - Software or Data Integrity Failures（软件/数据完整性失效）

### 描述

软件/数据完整性失效涉及代码或数据来源未经验证的安全问题，包括反序列化漏洞、CI/CD 管道安全等。

### 常见场景

- 不安全的反序列化
- 未验证的代码更新
- CI/CD 管道被攻击
- 自动更新被劫持

### Java 相关示例

```java
// 漏洞代码：不安全的反序列化
public Object deserialize(byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    return ois.readObject();
}

// 安全代码：白名单反序列化
public Object deserialize(byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) {
            if (!ALLOWED_CLASSES.contains(desc.getName())) {
                throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
            }
            return super.resolveClass(desc);
        }
    };
    return ois.readObject();
}
```

### 防护措施

1. 避免反序列化不可信数据
2. 使用白名单限制反序列化类
3. 验证代码/数据签名
4. CI/CD 管道安全加固

### 相关 CWE

- CWE-502: Deserialization of Untrusted Data
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere

---

## A09:2025 - Security Logging and Alerting Failures（安全日志与告警失效）

### 描述

安全日志与告警失效是指未能正确记录和响应安全事件，导致攻击行为无法被检测和追溯。

### 常见场景

- 关键操作未记录日志
- 日志被篡改或删除
- 无告警机制
- 日志包含敏感信息

### 防护措施

1. 记录关键操作日志
2. 日志集中存储
3. 设置实时告警
4. 日志脱敏处理

### 相关 CWE

- CWE-778: Insufficient Logging
- CWE-117: Improper Output Neutralization for Logs

---

## A10:2025 - Mishandling of Exceptional Conditions（异常条件处理不当）

### 描述

异常条件处理不当是指系统在遇到异常情况时未能正确处理，导致安全问题或系统不稳定。

### 常见场景

- 异常暴露敏感信息
- 异常导致系统状态不一致
- 异常未被正确捕获
- 异常处理流程被利用

### 防护措施

1. 统一异常处理
2. 异常信息脱敏
3. 异常后状态回滚
4. 记录异常日志

### 相关 CWE

- CWE-755: Improper Handling of Exceptional Conditions
- CWE-392: Missing Report of Error Condition

---

## 参考资料

- [OWASP Top 10:2025 官方文档](https://owasp.org/Top10/2025/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE - MITRE](https://cwe.mitre.org/)
