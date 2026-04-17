---
id: FILE-UPLOAD
name: 任意文件上传
severity: critical
owasp: "A04:2025"
cwe: ["CWE-434"]
category: file-operations
frameworks: [MultipartFile, "Servlet FileUpload", "Commons IO"]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# 文件上传漏洞

> 最后更新：2026-04-17

## 概述

文件上传漏洞是指应用程序对用户上传的文件缺乏足够的校验，导致攻击者可以上传恶意文件（如 WebShell）并在服务器上执行。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A04:2021 - Insecure Design |
| CWE | CWE-434 |
| 严重程度 | 高危/严重 |

## 漏洞类型

### 1. 无校验上传

```java
// 漏洞代码：直接保存上传文件
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    file.transferTo(new File("/uploads/" + filename));
    return "uploaded";
}
```

**攻击**：上传 `shell.jsp` 直接执行任意命令。

### 2. MIME 类型校验绕过

```java
// 漏洞代码：仅校验 MIME 类型
if (!file.getContentType().equals("image/jpeg")) {
    throw new Exception("Invalid file type");
}
```

**攻击**：修改请求的 `Content-Type` 头即可绕过。

### 3. 扩展名黑名单绕过

```java
// 漏洞代码：黑名单过滤
String ext = FilenameUtils.getExtension(filename);
if (Arrays.asList("jsp", "jspx", "php").contains(ext)) {
    throw new Exception("Invalid extension");
}
```

**绕过方式**：
- 大小写绕过：`JSP`、`JsP`
- 双写绕过：`jjspp`、`pphp`
- 空字节绕过：`shell.jsp%00.jpg`
- 特殊扩展名：`jspx`、`jspf`、`jspa`、`jsw`、`jsv`

### 4. 路径穿越

```java
// 漏洞代码：未过滤文件名中的路径字符
file.transferTo(new File("/uploads/" + filename));
```

**攻击**：`filename = "../../../webapps/ROOT/shell.jsp"`，文件被保存到 Web 目录。

## 安全代码示例

```java
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    // 1. 检查文件是否为空
    if (file.isEmpty()) {
        throw new IllegalArgumentException("File is empty");
    }

    // 2. 白名单校验扩展名
    String originalFilename = file.getOriginalFilename();
    String ext = FilenameUtils.getExtension(originalFilename).toLowerCase();
    Set<String> ALLOWED_EXTENSIONS = Set.of("jpg", "jpeg", "png", "gif", "pdf");
    if (!ALLOWED_EXTENSIONS.contains(ext)) {
        throw new IllegalArgumentException("Invalid file extension: " + ext);
    }

    // 3. 校验文件大小
    long MAX_SIZE = 10 * 1024 * 1024; // 10MB
    if (file.getSize() > MAX_SIZE) {
        throw new IllegalArgumentException("File too large");
    }

    // 4. 校验文件内容（Magic Number）
    try (InputStream is = file.getInputStream()) {
        byte[] header = new byte[8];
        is.read(header);
        if (!isValidImageHeader(header)) {
            throw new IllegalArgumentException("Invalid file content");
        }
    }

    // 5. 重命名文件（不使用原始文件名）
    String safeFilename = UUID.randomUUID().toString() + "." + ext;

    // 6. 安全的保存路径
    Path uploadDir = Paths.get("/var/uploads/").normalize().toAbsolutePath();
    Path targetPath = uploadDir.resolve(safeFilename).normalize();

    // 7. 确保目标路径在允许的目录内
    if (!targetPath.startsWith(uploadDir)) {
        throw new SecurityException("Path traversal detected");
    }

    // 8. 保存文件
    file.transferTo(targetPath.toFile());

    return "uploaded: " + safeFilename;
}

private boolean isValidImageHeader(byte[] header) {
    // JPEG: FF D8 FF
    if (header[0] == (byte) 0xFF && header[1] == (byte) 0xD8 && header[2] == (byte) 0xFF) {
        return true;
    }
    // PNG: 89 50 4E 47
    if (header[0] == (byte) 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47) {
        return true;
    }
    // GIF: 47 49 46 38
    if (header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38) {
        return true;
    }
    return false;
}
```

## 防护措施清单

| 措施 | 说明 |
|------|------|
| 扩展名白名单 | 只允许安全的扩展名（jpg, png, pdf, doc 等） |
| MIME 类型校验 | 作为辅助校验，不作为唯一防线 |
| 文件内容校验 | 校验文件头（Magic Number） |
| 文件大小限制 | 防止大文件攻击 |
| 重命名文件 | 使用 UUID 或时间戳重命名 |
| 独立存储目录 | 上传目录禁止执行权限 |
| 路径穿越防护 | 规范化路径并校验 |
| 文件重解析 | 图片可重新渲染去除恶意代码 |
| 病毒扫描 | 上传后进行病毒扫描 |

## 参考资料

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
