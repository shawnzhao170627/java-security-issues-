---
id: SSTI
name: 服务端模板注入
severity: critical
owasp: "A05:2025"
cwe: ["CWE-1336", "CWE-94"]
category: injection
frameworks: [FreeMarker, Velocity, Thymeleaf, Pebble, Groovy Template]
last_updated: "2026-04-17"
doc_version: "1.0"
---

# 服务端模板注入（SSTI）

> 最后更新：2026-04-17

## 概述

服务端模板注入（Server-Side Template Injection，SSTI）是指用户输入被嵌入模板引擎并以代码形式执行，导致远程代码执行（RCE）。Java 生态中 FreeMarker、Velocity、Thymeleaf 等主流模板引擎均存在此风险。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Injection |
| CWE | CWE-1336 / CWE-94 |
| 严重程度 | 严重 |

## 攻击类型

### 1. FreeMarker 注入

```
${7*7}                          → 输出 49（探测）
${"freemarker.template.utility.Execute"?new()("id")}  → 执行系统命令
```

### 2. Velocity 注入

```
#set($e="")
$e.class.forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)
```

### 3. Thymeleaf 注入（Spring View Name 操控）

```
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

## Java 场景

### FreeMarker 注入

```java
// [VULNERABLE] 将用户输入直接作为模板内容渲染
@GetMapping("/render")
public String render(@RequestParam String template, HttpServletResponse response) throws Exception {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    // 危险：用户输入直接作为模板字符串
    Template t = new Template("name", new StringReader(template), cfg);
    StringWriter out = new StringWriter();
    t.process(new HashMap<>(), out);
    return out.toString();
}
// 攻击输入：${"freemarker.template.utility.Execute"?new()("whoami")}
```

```java
// [SECURE] 模板内容来自受信任的文件，用户输入仅作为数据传入
@GetMapping("/render")
public String render(@RequestParam String username, Model model) {
    // 安全：模板固定，用户输入仅作为变量值
    model.addAttribute("username", HtmlUtils.htmlEscape(username));
    return "welcome"; // 指向 templates/welcome.html，非用户可控
}
```

### Velocity 注入

```java
// [VULNERABLE] 用户控制模板内容
@PostMapping("/report")
public String generateReport(@RequestBody String templateContent) {
    VelocityEngine ve = new VelocityEngine();
    ve.init();
    Template t = ve.getTemplate(templateContent); // 危险
    StringWriter sw = new StringWriter();
    t.merge(new VelocityContext(), sw);
    return sw.toString();
}
```

```java
// [SECURE] 模板路径白名单 + 用户输入仅作为上下文变量
@PostMapping("/report")
public String generateReport(@RequestParam String reportType,
                              @RequestBody Map<String, Object> data) {
    // 白名单校验模板名称
    if (!ALLOWED_TEMPLATES.contains(reportType)) {
        throw new IllegalArgumentException("非法模板类型");
    }
    VelocityEngine ve = new VelocityEngine();
    ve.init();
    Template t = ve.getTemplate("templates/" + reportType + ".vm");
    VelocityContext ctx = new VelocityContext();
    // 用户数据仅作为变量，不影响模板结构
    data.forEach(ctx::put);
    StringWriter sw = new StringWriter();
    t.merge(ctx, sw);
    return sw.toString();
}
```

### Thymeleaf Spring MVC 注入

```java
// [VULNERABLE] 视图名称由用户输入控制
@GetMapping("/view")
public String view(@RequestParam String page) {
    return page; // 危险：攻击者可传入 __${...}__::
}
```

```java
// [SECURE] 视图名称白名单控制
private static final Set<String> ALLOWED_VIEWS = Set.of("home", "about", "contact");

@GetMapping("/view")
public String view(@RequestParam String page) {
    if (!ALLOWED_VIEWS.contains(page)) {
        return "error/404";
    }
    return page;
}
```

## 检测方法

1. **静态分析**：搜索 `new Template`、`ve.getTemplate`、用户输入直接作为 `return` 的视图名
2. **探测 Payload**：输入 `${7*7}` 或 `#{7*7}`，观察响应是否包含 `49`
3. **Semgrep**：使用 `java-ssti-freemarker` 规则扫描

## 防护措施

1. **模板内容固定**：模板文件存于服务端，用户输入只作为变量值传入
2. **视图名白名单**：Spring MVC 的视图名称不由用户控制
3. **沙箱模式**：FreeMarker 开启 `TemplateClassResolver.SAFER_RESOLVER`
4. **输入校验**：过滤 `${`、`#{`、`#set`、`<#` 等模板特殊字符

```java
// FreeMarker 沙箱配置
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
```

## 参考资料

- [OWASP SSTI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection)
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
