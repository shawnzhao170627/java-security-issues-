# 贡献指南

感谢您有兴趣为 Java Security Issues 项目做出贡献！

## 如何贡献

### 报告问题

如果您发现了问题或有改进建议，请：

1. 在 [Issues](https://github.com/your-org/java-security-issues/issues) 中搜索是否已有相关 Issue
2. 如果没有，创建新的 Issue，包含：
   - 清晰的标题
   - 问题的详细描述
   - 相关的分类（如漏洞类型、框架等）
   - 参考资料（如有）

### 贡献内容

#### 漏洞文档贡献

1. Fork 本仓库
2. 创建新的分支：`git checkout -b feature/new-vulnerability`
3. 在 `docs/vulnerabilities/` 对应目录下创建或编辑文档
4. 确保文档包含以下内容：
   - 漏洞概述
   - 风险等级（OWASP/CWE 映射）
   - 漏洞类型
   - Java 场景示例
   - 检测方法
   - 防护措施
   - 参考资料

#### 代码示例贡献

1. 在 `examples/vulnerable/` 中添加漏洞代码示例
2. 在 `examples/secure/` 中添加对应的安全代码示例
3. 确保代码可以编译（添加必要的 import 和依赖）

#### 检测规则贡献

1. 在 `docs/tools/semgrep-rules/` 中添加 Semgrep 规则
2. 在 `docs/tools/codeql-queries/` 中添加 CodeQL 查询
3. 添加规则的测试用例

### 文档格式规范

#### Markdown 格式

```markdown
# 漏洞名称

> 最后更新：YYYY-MM-DD

## 概述

漏洞的简要描述。

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | A0X:2025 - XXX |
| CWE | CWE-XXX |
| 严重程度 | 高危/严重 |

## 漏洞类型

...

## Java 场景

```java
// 代码示例
```

## 检测方法

...

## 防护措施

...

## 参考资料

- [标题](链接)
```

### 提交信息规范

使用约定式提交格式：

```
<type>(<scope>): <subject>

<body>

<footer>
```

类型：
- `feat`: 新功能/新内容
- `fix`: 修复错误
- `docs`: 文档更新
- `style`: 格式调整
- `refactor`: 内容重构
- `test`: 添加测试

示例：
```
feat(injection): 添加 SSTI 漏洞文档

添加服务端模板注入漏洞的详细说明，包含 FreeMarker、Velocity 等模板引擎的示例。

Closes #123
```

### 审核流程

1. 提交 Pull Request
2. 维护者会进行审核
3. 可能会提出修改建议
4. 审核通过后合并

### 行为准则

- 尊重所有贡献者
- 建设性的讨论和反馈
- 专注于对项目最有利的事情

## 需要帮助？

如果您有任何问题，可以：
- 在 [Discussions](https://github.com/your-org/java-security-issues/discussions) 中提问
- 创建 Issue 询问

再次感谢您的贡献！
