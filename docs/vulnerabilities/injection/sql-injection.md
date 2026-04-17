---
id: SQL-INJECTION
name: SQL 注入
severity: critical
owasp: "A05:2025"
cwe: ["CWE-89"]
category: injection
frameworks: [JDBC, MyBatis, JPA, Hibernate]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# SQL 注入漏洞

> 最后更新：2026-04-17

## 概述

SQL 注入（SQL Injection）是一种代码注入攻击，攻击者通过在应用程序的输入字段中插入恶意 SQL 代码，操纵后端数据库执行非预期的命令。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Injection |
| CWE | CWE-89 |
| 严重程度 | 高危/严重 |

## 漏洞类型

### 1. 基于 Boolean 的盲注

```sql
' AND 1=1 --
' AND 1=2 --
```

### 2. 基于 Union 的注入

```sql
' UNION SELECT username, password FROM users --
```

### 3. 基于 Time 的盲注

```sql
' AND SLEEP(5) --
```

### 4. 堆叠查询

```sql
'; DROP TABLE users; --
```

## Java 场景

### JDBC 拼接注入

```java
// 漏洞代码
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    // ...
}

// 攻击输入: ' OR '1'='1
// 实际执行: SELECT * FROM users WHERE username = '' OR '1'='1'
```

### MyBatis 动态 SQL 注入

```xml
<!-- 漏洞代码：使用 ${} 会直接拼接 -->
<select id="findByUsername" resultType="User">
    SELECT * FROM users WHERE username = '${username}'
</select>

<!-- 安全代码：使用 #{} 会预编译 -->
<select id="findByUsername" resultType="User">
    SELECT * FROM users WHERE username = #{username}
</select>
```

### JPA/JPQL 注入

```java
// 漏洞代码
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.username = '" + username + "'", User.class);

// 安全代码
TypedQuery<User> query = em.createQuery(
    "SELECT u FROM User u WHERE u.username = :username", User.class);
query.setParameter("username", username);
```

## 检测方法

### 静态检测

1. **关键词搜索**：查找 SQL 拼接模式
   ```bash
   grep -rn "executeQuery.*+" src/
   grep -rn '\${' src/
   ```

2. **使用 Semgrep 规则**：
   ```bash
   semgrep --config ./semgrep-rules/sql-injection.yml src/
   ```

### 动态检测

1. **SQLMap**：自动化 SQL 注入检测工具
   ```bash
   sqlmap -u "http://example.com/user?id=1" --batch
   ```

2. **Burp Suite**：Web 应用安全测试

## 防护措施

### 1. 参数化查询（首选）

```java
// JDBC
String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);

// MyBatis
SELECT * FROM users WHERE username = #{username}

// JPA
@Query("SELECT u FROM User u WHERE u.username = :username")
User findByUsername(@Param("username") String username);
```

### 2. 输入验证

```java
// 白名单校验
if (!username.matches("^[a-zA-Z0-9_]{3,20}$")) {
    throw new IllegalArgumentException("Invalid username");
}
```

### 3. 最小权限原则

```sql
-- 应用程序数据库用户只授予必要权限
GRANT SELECT, INSERT, UPDATE ON app_db.* TO 'app_user'@'localhost';
```

### 4. ORM 安全 API

```java
// Spring Data JPA
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username); // 自动参数化
}

// 安全的动态查询
Specification<User> spec = (root, query, cb) ->
    cb.equal(root.get("username"), username);
```

### 5. WAF 防护

配置 Web 应用防火墙过滤 SQL 注入攻击特征。

## 参考资料

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
