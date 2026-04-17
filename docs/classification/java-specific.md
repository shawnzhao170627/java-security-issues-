# Java 专项安全问题分类

> 最后更新：2026-04-17

## 概述

本文档整理 Java 生态特有的安全问题，这些问题的根源在于 Java 语言特性、JVM 机制或 Java 框架组件。

---

## 一、注入类漏洞

### 1.1 SQL 注入

| 类型 | 说明 | Java 相关 |
|------|------|----------|
| JDBC 拼接 | 字符串拼接 SQL | `Statement.executeQuery()` |
| MyBatis 动态 SQL | `${}` 拼接 | `select * from users where name = '${name}'` |
| JPA/JPQL | 字符串拼接 | `createQuery("... where name = '" + name + "'")` |
| HQL 注入 | Hibernate 查询语言 | 类似 SQL 注入 |

**安全编码**：
```java
// MyBatis 安全用法
select * from users where name = #{name}

// JPA 安全用法
TypedQuery<User> query = em.createQuery("SELECT u FROM User u WHERE u.name = :name", User.class);
query.setParameter("name", name);
```

---

### 1.2 XSS (Cross-Site Scripting)

| 类型 | 说明 | Java 相关 |
|------|------|----------|
| 反射型 XSS | 参数直接输出 | JSP `${param.xxx}` |
| 存储型 XSS | 存储后输出 | 富文本编辑器内容 |
| DOM型 XSS | 前端渲染 | 后端返回 JSON 未转义 |

**安全编码**：
```jsp
<!-- JSP 安全输出 -->
<c:out value="${userInput}" />
${fn:escapeXml(userInput)}
```

---

### 1.3 命令注入

```java
// 漏洞代码
Runtime.getRuntime().exec("ping " + ip);

// 安全代码：使用数组形式
Runtime.getRuntime().exec(new String[]{"ping", ip});
```

---

### 1.4 表达式注入

| 表达式引擎 | 注入方式 | 影响 |
|-----------|---------|------|
| SpEL | `T(java.lang.Runtime)` | Spring 应用 |
| OGNL | Struts2 框架 | RCE |
| EL | JSP 表达式语言 | 信息泄露 |
| MVEL | 规则引擎 | RCE |

**示例**：
```java
// SpEL 漏洞
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput); // 危险

// 安全做法：禁用危险功能
SpelParserConfiguration config = new SpelParserConfiguration(false, false);
```

---

### 1.5 JNDI 注入

```java
// 漏洞代码：用户可控的 JNDI 查找
Context ctx = new InitialContext();
Object obj = ctx.lookup(userInput); // LDAP/RMI 注入

// 安全代码：白名单校验
if (!ALLOWED_JNDI_NAMES.contains(userInput)) {
    throw new SecurityException("Invalid JNDI name");
}
```

---

## 二、文件操作类漏洞

### 2.1 路径遍历

```java
// 漏洞代码
String filename = request.getParameter("file");
File file = new File("/var/www/files/" + filename);
FileInputStream fis = new FileInputStream(file);

// 安全代码：规范化和校验
Path basePath = Paths.get("/var/www/files/").normalize().toAbsolutePath();
Path filePath = basePath.resolve(filename).normalize().toAbsolutePath();
if (!filePath.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}
```

---

### 2.2 任意文件上传

```java
// 漏洞代码：无校验
MultipartFile file = request.getFile("file");
file.transferTo(new File("/uploads/" + file.getOriginalFilename()));

// 安全代码：白名单校验
String filename = file.getOriginalFilename();
String ext = FilenameUtils.getExtension(filename).toLowerCase();
if (!ALLOWED_EXTENSIONS.contains(ext)) {
    throw new SecurityException("Invalid file type");
}
// 重命名文件，不使用原始文件名
String safeName = UUID.randomUUID() + "." + ext;
file.transferTo(new File("/uploads/" + safeName));
```

---

## 三、反序列化漏洞

### 3.1 Java 原生反序列化

```java
// 漏洞代码
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

// 安全代码：白名单过滤
ObjectInputStream ois = new ObjectInputStream(input) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization", desc.getName());
        }
        return super.resolveClass(desc);
    }
};
```

### 3.2 Fastjson 反序列化

```java
// 漏洞配置：开启 AutoType
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

// 安全配置：关闭 AutoType，使用白名单
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
ParserConfig.getGlobalInstance().addAccept("com.example.");
```

### 3.3 Jackson 反序列化

```java
// 漏洞配置：开启默认类型
objectMapper.enableDefaultTyping();

// 安全配置：禁用默认类型
objectMapper.disableDefaultTyping();
// 或使用白名单
objectMapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
```

### 3.4 反序列化漏洞影响范围

| 库/组件 | 漏洞入口 | 攻击方式 |
|---------|---------|---------|
| Java 原生 | ObjectInputStream | ysoserial gadget chain |
| Fastjson | JSON.parseObject | AutoType 触发恶意类 |
| Jackson | ObjectMapper.readValue | enableDefaultTyping |
| Hessian | HessianInput.readObject | gadget chain |
| XStream | XStream.fromXML | 任意对象实例化 |
| SnakeYAML | Yaml.load | 任意类实例化 |
| Kryo | Kryo.readClassAndObject | 任意类实例化 |

---

## 四、框架组件漏洞

### 4.1 Spring 框架

| 漏洞 | CVE | 影响 |
|------|-----|------|
| Spring4Shell | CVE-2022-22965 | JDK9+ RCE |
| Spring Cloud Function SpEL | CVE-2022-22963 | RCE |
| Spring Cloud Gateway | CVE-2022-22947 | RCE |
| Spring Data MongoDB | CVE-2022-22980 | SpEL RCE |

### 4.2 Struts2 框架

| 漏洞编号 | 类型 | 影响 |
|---------|------|------|
| S2-045 | OGNL 注入 | RCE |
| S2-046 | OGNL 注入 | RCE |
| S2-048 | OGNL 注入 | RCE |
| S2-057 | OGNL 注入 | RCE |

### 4.3 Apache Shiro

| 漏洞 | CVE | 影响 |
|------|-----|------|
| RememberMe 反序列化 | CVE-2016-4437 | RCE |
| 权限绕过 | CVE-2020-1957 | 授权绕过 |
| 认证绕过 | CVE-2022-32532 | 认证绕过 |

### 4.4 Log4j2

| 漏洞 | CVE | 影响 |
|------|-----|------|
| Log4Shell | CVE-2021-44228 | JNDI 注入 RCE |
| DoS 攻击 | CVE-2021-45046 | 拒绝服务 |

---

## 五、加密安全类

### 5.1 弱加密算法

| 算法类型 | 不安全算法 | 安全替代 |
|---------|-----------|---------|
| 哈希 | MD5、SHA1 | SHA-256、SHA-3 |
| 对称加密 | DES、3DES、Blowfish | AES-256-GCM |
| 非对称加密 | RSA-1024 | RSA-2048、ECC |
| 密码存储 | 明文、MD5 | BCrypt、Argon2 |

### 5.2 密码安全存储

```java
// 漏洞代码：MD5 存储密码
String hashed = DigestUtils.md5Hex(password);

// 安全代码：BCrypt
String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));
```

### 5.3 随机数安全

```java
// 漏洞代码：不安全的随机数
Random random = new Random();
String token = String.valueOf(random.nextInt());

// 安全代码：安全随机数
SecureRandom secureRandom = new SecureRandom();
byte[] token = new byte[32];
secureRandom.nextBytes(token);
```

---

## 六、配置安全类

### 6.1 常见配置问题

| 问题 | 风险 | 修复 |
|------|------|------|
| 硬编码密钥 | 密钥泄露 | 使用密钥管理服务 |
| 默认账户 | 未授权访问 | 删除/修改默认账户 |
| 调试模式开启 | 信息泄露 | 生产环境关闭 |
| 错误堆栈暴露 | 信息泄露 | 自定义错误页面 |
| 目录列表 | 信息泄露 | 关闭目录列表 |

### 6.2 敏感配置加密

```properties
# 漏洞配置：明文存储密码
spring.datasource.password=admin123

# 安全配置：使用 Jasypt 加密
spring.datasource.password=ENC(加密后的密码)
```

---

## 七、业务逻辑漏洞

### 7.1 越权操作

```java
// 漏洞代码：未校验订单归属
@PostMapping("/order/{id}/cancel")
public void cancelOrder(@PathVariable Long id) {
    orderService.cancel(id);
}

// 安全代码：校验订单归属
@PostMapping("/order/{id}/cancel")
public void cancelOrder(@PathVariable Long id, Principal principal) {
    Order order = orderService.findById(id);
    if (!order.getUserId().equals(principal.getName())) {
        throw new AccessDeniedException("无权操作此订单");
    }
    orderService.cancel(id);
}
```

### 7.2 并发竞争

```java
// 漏洞代码：无锁操作
@PostMapping("/coupon/{code}/claim")
public void claimCoupon(@PathVariable String code) {
    Coupon coupon = couponService.findByCode(code);
    if (coupon.getRemaining() > 0) {
        couponService.claim(coupon);
    }
}

// 安全代码：使用乐观锁或分布式锁
@PostMapping("/coupon/{code}/claim")
@Transactional
public void claimCoupon(@PathVariable String code) {
    Coupon coupon = couponService.findByCodeWithLock(code);
    if (coupon.getRemaining() > 0) {
        couponService.claim(coupon);
    }
}
```

---

## 八、资源消耗类

### 8.1 ReDoS（正则表达式拒绝服务）

```java
// 漏洞代码：回溯爆炸的正则
Pattern pattern = Pattern.compile("^(a+)+$");

// 安全代码：避免嵌套量词，限制输入长度
Pattern pattern = Pattern.compile("^[a]+$");
if (input.length() > 100) {
    throw new IllegalArgumentException("Input too long");
}
```

### 8.2 OOM（内存溢出攻击）

```java
// 漏洞代码：无限制的文件上传大小
@PostMapping("/upload")
public void upload(MultipartFile file) {
    byte[] bytes = file.getBytes(); // 可能 OOM
}

// 安全代码：限制大小
@PostMapping("/upload")
public void upload(MultipartFile file) {
    if (file.getSize() > MAX_FILE_SIZE) {
        throw new IllegalArgumentException("File too large");
    }
}
```

---

## 参考资料

- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [JavaSec](https://www.javasec.org/)
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
