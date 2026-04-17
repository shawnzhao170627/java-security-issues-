# 代码示例贡献指南

## 目录结构

```
examples/
├── vulnerable/     # 漏洞代码示例
│   ├── SqlInjectionVulnerable.java
│   ├── XssVulnerable.java
│   └── ...
└── secure/         # 安全代码示例
    ├── SqlInjectionSecure.java
    ├── XssSecure.java
    └── ...
```

## 命名规范

| 类型 | 命名格式 | 示例 |
|------|---------|------|
| 漏洞代码 | `{Issue}Vulnerable.java` | `SqlInjectionVulnerable.java` |
| 安全代码 | `{Issue}Secure.java` | `SqlInjectionSecure.java` |

## 代码要求

### 1. 完整性

代码应该是可编译的，包含必要的：
- package 声明
- import 语句
- 类定义
- 方法签名

```java
package com.example.vulnerable;

import java.sql.*;

/**
 * 漏洞代码示例：SQL 注入
 * Vulnerable Code Example: SQL Injection
 */
public class SqlInjectionVulnerable {

    public User findByUsername(String username) throws SQLException {
        // ... 漏洞代码
    }
}
```

### 2. 注释规范

每个文件应该包含：
- 类级别的 Javadoc 说明漏洞类型
- 方法级别的注释说明漏洞点
- 中英双语说明

```java
/**
 * 漏洞代码示例：SQL 注入
 * Vulnerable Code Example: SQL Injection
 */
public class SqlInjectionVulnerable {

    /**
     * 漏洞：JDBC 字符串拼接
     * Vulnerability: JDBC String Concatenation
     */
    public User findByUsername(String username) {
        // 漏洞代码...
    }
}
```

### 3. 对应关系

每个漏洞代码应该有对应的安全代码：
- 相同的功能场景
- 清晰的对比
- 修复说明注释

### 4. 不包含敏感信息

- 不使用真实的 IP 地址、域名
- 不使用真实的用户名、密码
- 不使用真实的业务数据
- 使用示例数据如：`example.com`、`testuser`、`password123`

## 示例模板

### 漏洞代码模板

```java
package com.example.vulnerable;

/**
 * 漏洞代码示例：{漏洞名称}
 * Vulnerable Code Example: {Vulnerability Name}
 */
public class {Issue}Vulnerable {

    /**
     * 漏洞：{漏洞描述}
     * Vulnerability: {Vulnerability Description}
     */
    public void vulnerableMethod(String userInput) {
        // 漏洞代码
    }
}
```

### 安全代码模板

```java
package com.example.secure;

/**
 * 安全代码示例：{漏洞名称}防护
 * Secure Code Example: {Vulnerability Name} Prevention
 */
public class {Issue}Secure {

    /**
     * 安全：{防护措施描述}
     * Secure: {Mitigation Description}
     */
    public void secureMethod(String userInput) {
        // 安全代码
    }
}
```

## 提交前检查清单

- [ ] 代码可以编译
- [ ] 包含必要的 import 语句
- [ ] 包含中英双语注释
- [ ] 不包含敏感信息
- [ ] 漏洞代码和安全代码对应
- [ ] 文件命名符合规范

## 依赖说明

如果代码示例需要额外的依赖，请在文件头部注明：

```java
/**
 * 依赖：org.springframework.boot:spring-boot-starter-web:2.7.0
 * Dependencies: org.springframework.boot:spring-boot-starter-web:2.7.0
 */
```
