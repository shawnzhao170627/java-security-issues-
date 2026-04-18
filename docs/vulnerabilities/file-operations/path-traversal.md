---
id: PATH-TRAVERSAL
name: 路径遍历
severity: high
owasp: "A01:2025"
cwe: ["CWE-22"]
category: file-operations
frameworks: [FileInputStream, Files, File API]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# 路径遍历漏洞

> 最后更新：2026-04-17

## 概述

路径遍历（Path Traversal）是一种攻击技术，攻击者通过操作路径引用，访问预期目录之外的文件。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A01:2025 - Broken Access Control |
| CWE | CWE-22 |
| 严重程度 | 高危 |

## 攻击类型

### 1. 相对路径遍历

```
../../../etc/passwd
....//....//....//etc/passwd
```

### 2. 绝对路径访问

```
/etc/passwd
C:\Windows\System32\config\SAM
```

### 3. URL 编码绕过

```
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F (双重编码)
```

## Java 场景

```java
// 漏洞代码：直接拼接路径
@GetMapping("/download")
public void download(@RequestParam String filename, HttpServletResponse response) {
    File file = new File("/var/www/files/" + filename);
    // 攻击输入: ../../etc/passwd
    // 实际路径: /var/www/files/../../etc/passwd → /etc/passwd
}
```

```java
// 安全代码：路径规范化和校验
@GetMapping("/download")
public void download(@RequestParam String filename, HttpServletResponse response) {
    // 1. 定义基础目录
    Path basePath = Paths.get("/var/www/files/").normalize().toAbsolutePath();

    // 2. 规范化目标路径
    Path targetPath = basePath.resolve(filename).normalize().toAbsolutePath();

    // 3. 校验目标路径在基础目录内
    if (!targetPath.startsWith(basePath)) {
        throw new SecurityException("Path traversal detected");
    }

    // 4. 检查文件存在
    if (!Files.exists(targetPath)) {
        throw new FileNotFoundException("File not found");
    }
}
```

## 检测方法

### 静态检测

1. **关键词搜索**：查找路径拼接模式
   ```bash
   grep -rn "new File.*+" src/
   grep -rn "Paths.get.*+" src/
   grep -rn "FileInputStream.*+" src/
   ```

2. **使用 Semgrep 规则**：
   ```bash
   semgrep --config ./semgrep-rules/file-operations.yml src/
   ```

### 动态检测

1. **Burp Suite**：使用 Path Traversal 模块测试
2. **OWASP ZAP**：主动扫描路径遍历漏洞
3. **手动测试**：在文件参数中注入 `../../../etc/passwd` 等遍历序列

## 防护措施

| 措施 | 说明 |
|------|------|
| 路径规范化 | 使用 `Path.normalize()` 或 `File.getCanonicalPath()` |
| 边界校验 | 确保最终路径在允许的目录内 |
| 白名单 | 只允许预定义的文件名 |
| 沙箱隔离 | 将文件访问限制在特定目录 |
| 禁用软链接 | 避免通过软链接绕过 |

## 参考资料

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
