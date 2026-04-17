# Semgrep 检测规则

本目录包含用于检测 Java 安全漏洞的 Semgrep 规则。

## 规则列表

| 规则文件 | 检测漏洞 |
|---------|---------|
| sql-injection.yml | SQL 注入 |
| command-injection.yml | 命令注入 |
| path-traversal.yml | 路径遍历 |
| xxe.yml | XXE 外部实体注入 |
| deserialization.yml | 反序列化漏洞 |
| xss.yml | XSS 跨站脚本 |

## 使用方法

### 检测单个规则

```bash
semgrep --config sql-injection.yml ./src
```

### 检测所有规则

```bash
semgrep --config . ./src
```

### 输出格式

```bash
# JSON 格式
semgrep --config . --json ./src > results.json

# SARIF 格式（用于 GitHub Code Scanning）
semgrep --config . --sarif ./src > results.sarif
```

## 规则编写规范

### 基本结构

```yaml
rules:
  - id: java-sql-injection
    patterns:
      - pattern: |
          String $SQL = "..." + $VAR;
          ...
          $STMT.executeQuery($SQL);
    message: 检测到 SQL 注入风险，请使用参数化查询
    severity: ERROR
    languages:
      - java
    metadata:
      category: security
      cwe: CWE-89
      owasp: A03:2021 - Injection
      references:
        - https://owasp.org/www-community/attacks/SQL_Injection
```

### 元数据规范

| 字段 | 说明 |
|------|------|
| id | 唯一标识符，格式：`java-{漏洞类型}-{场景}` |
| message | 发现漏洞时的提示信息 |
| severity | 严重程度：ERROR、WARNING、INFO |
| languages | 固定为 `java` |
| metadata.category | 固定为 `security` |
| metadata.cwe | CWE 编号 |
| metadata.owasp | OWASP Top 10 映射 |
| metadata.references | 参考链接 |

## 规则测试

每个规则应该有对应的测试文件：

```
tests/
├── sql-injection.test.yaml
└── sql-injection.js
```

测试文件格式：

```yaml
rules:
  - id: java-sql-injection
    # ... 规则定义

tests:
  - test_id: sql-injection-1
    code: |
      String sql = "SELECT * FROM users WHERE id = " + userId;
      stmt.executeQuery(sql);
    expected_outcome: FIND

  - test_id: sql-injection-safe-1
    code: |
      String sql = "SELECT * FROM users WHERE id = ?";
      pstmt.setString(1, userId);
      pstmt.executeQuery();
    expected_outcome: NO_FIND
```

## 参考资源

- [Semgrep 官方文档](https://semgrep.dev/docs/)
- [Semgrep 规则仓库](https://github.com/returntocorp/semgrep-rules)
- [Semgrep Playground](https://semgrep.dev/editor)
