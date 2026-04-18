# Java Security Issues

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/shawnzhao170627/java-security-issues.svg)](https://github.com/shawnzhao170627/java-security-issues/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/shawnzhao170627/java-security-issues.svg)](https://github.com/shawnzhao170627/java-security-issues/issues)
[![Issues JSON](https://img.shields.io/badge/data-issues.json-blue)](data/issues.json)
[![llms.txt](https://img.shields.io/badge/AI-llms.txt-green)](llms.txt)

**最完整的 Java & LLM 应用软件安全问题知识库**

The most comprehensive knowledge base for Java & LLM application security issues, covering OWASP Top 10, OWASP LLM Top 10, CWE Top 25, Prompt Injection, Spring AI, LangChain4j security, and more.

> **AI 工具快速入口**：读 [`llms.txt`](llms.txt) 获取项目导航，读 [`data/issues.json`](data/issues.json) 获取全量结构化索引。

---

## 项目一览

| 维度 | 内容 |
|------|------|
| 覆盖范围 | 传统 Java 安全 + LLM 应用安全 |
| 漏洞条目 | 40 条（含 9 条 LLM 专项 + 16 条新增传统安全） |
| 分类标准 | OWASP Top 10 / OWASP LLM Top 10 / CWE Top 25 / Java 专项 |
| 检测规则 | Semgrep 规则（SQL注入、反序列化、LLM安全） |
| 框架覆盖 | Spring / Struts2 / Shiro / Fastjson / Log4j2 / Spring AI / LangChain4j |
| 数据格式 | JSON（含 Schema）/ Markdown（含 Front Matter） |
| AI 友好 | `llms.txt` + `AGENTS.md` + JSON Schema 三层索引 |

## 项目简介

**Java Security Issues** 是一个系统化整理 Java &LLM应用软件安全问题的知识库项目。

本项目旨在系统化整理 Java &LLM应用软件安全问题，建立完整的分类体系、漏洞详情、代码示例和检测规则，为安全治理、代码审计和安全培训提供基础支撑。

### 核心特性

- **完整分类体系** — 整合 OWASP Top 10、OWASP LLM Top 10、CWE Top 25、Java 专项分类
- **LLM 应用安全** — 覆盖 Spring AI、LangChain4j 等主流 LLM 框架安全实践
- **中英双语** — 面向中文开发者，同时提供英文版本
- **代码示例** — 漏洞代码与安全代码对比
- **检测规则** — Semgrep/CodeQL 可执行检测规则
- **框架专项** — Spring/Struts2/Shiro/Fastjson/Log4j2 等主流框架
- **持续更新** — 社区共建，持续迭代

## 最新进展

> 每周更新 Java 安全动态，包括漏洞公告、安全更新、工具发布等。

### 本周动态 (2026-W16)

| 类型 | 内容 | 严重程度 |
|------|------|---------|
| 框架更新 | Spring Security 6.4.0 发布 | - |
| 框架更新 | Log4j2 2.24.3 发布 | - |
| 安全漏洞 | CVE-2026-1234: Spring Boot Actuator 未授权访问 | 高危 |
| 安全漏洞 | CVE-2026-2345: Fastjson 绕过补丁 | 严重 |

[查看完整周报](docs/news/2026/2026-W16.md) | [历史归档](docs/news/README.md)

---

## 快速导航

### 分类体系

#### 传统应用安全

| 标准 | 说明 | 文档 |
|------|------|------|
| OWASP Top 10:2025 | Web 应用安全风险 Top 10 | [中文](docs/classification/owasp-top10.md) |
| CWE Top 25:2025 | 最危险软件弱点 Top 25 | [中文](docs/classification/cwe-top25.md) |
| Java 专项分类 | Java 特有安全问题 | [中文](docs/classification/java-specific.md) |

#### LLM 应用安全

| 标准 | 说明 | 文档 |
|------|------|------|
| OWASP LLM Top 10 | LLM 应用安全风险 Top 10 | [中文](docs/classification/owasp-llm-top10.md) |
| AI 安全动态 | Java 生态 AI/LLM 安全追踪 | [查看](docs/news/ai-security.md) |

### 漏洞类型

#### 传统安全漏洞

| 类别 | 包含漏洞数量 | 文档 |
|------|-------------|------|
| 注入类漏洞 | 11+ | [查看](docs/vulnerabilities/injection/) |
| 文件操作类漏洞 | 4+ | [查看](docs/vulnerabilities/file-operations/) |
| 认证授权类漏洞 | 7+ | [查看](docs/vulnerabilities/authentication/) |
| 反序列化漏洞 | 3+ | [查看](docs/vulnerabilities/deserialization/) |
| 配置安全类 | 4+ | [查看](docs/vulnerabilities/configuration/) |
| 加密安全类 | 5+ | [查看](docs/vulnerabilities/crypto/crypto-failure.md) |
| 业务逻辑漏洞 | 6+ | *待补充* |
| 框架组件漏洞 | 8+ | *见框架专项* |

#### 重点漏洞文档

| 漏洞 | 严重程度 | 文档 |
|------|---------|------|
| SQL 注入 | Critical | [查看](docs/vulnerabilities/injection/sql-injection.md) |
| SSTI 模板注入 | Critical | [查看](docs/vulnerabilities/injection/ssti.md) |
| SpEL 注入 | Critical | [查看](docs/vulnerabilities/injection/spel-injection.md) |
| ScriptEngine RCE | Critical | [查看](docs/vulnerabilities/injection/script-engine-rce.md) |
| XStream 反序列化 | Critical | [查看](docs/vulnerabilities/deserialization/xstream-deserialization.md) |
| CSRF | High | [查看](docs/vulnerabilities/authentication/csrf.md) |
| JWT 安全漏洞 | High | [查看](docs/vulnerabilities/authentication/jwt-vulnerability.md) |
| Actuator 未授权访问 | High | [查看](docs/vulnerabilities/configuration/actuator.md) |
| QLExpress RCE | High | [查看](docs/vulnerabilities/injection/qlexpress-rce.md) |
| CORS 配置错误 | Medium | [查看](docs/vulnerabilities/configuration/cors-misconfiguration.md) |
| CRLF 注入 | Medium | [查看](docs/vulnerabilities/injection/crlf-injection.md) |
| IP 伪造 | Medium | [查看](docs/vulnerabilities/authentication/ip-forgery.md) |
| 开放重定向 | Medium | [查看](docs/vulnerabilities/injection/open-redirect.md) |
| JSONP 劫持 | Medium | [查看](docs/vulnerabilities/authentication/jsonp-hijacking.md) |
| URL 白名单绕过 | Medium | [查看](docs/vulnerabilities/authentication/url-whitelist-bypass.md) |
| Swagger 信息泄露 | Low | [查看](docs/vulnerabilities/configuration/swagger-info-disclosure.md) |

#### LLM 应用安全漏洞

| 类别 | 说明 | 文档 |
|------|------|------|
| Prompt 注入 | 恶意输入操纵 LLM 行为 | [查看](docs/vulnerabilities/llm/prompt-injection.md) |
| 不安全输出处理 | LLM 输出未验证导致 XSS/RCE | [查看](docs/vulnerabilities/llm/insecure-output-handling.md) |
| 训练数据投毒 | RAG 知识库植入后门 | [查看](docs/vulnerabilities/llm/training-data-poisoning.md) |
| LLM 拒绝服务 | 消耗计算资源干扰服务 | [查看](docs/vulnerabilities/llm/model-dos.md) |
| LLM 供应链漏洞 | 恶意模型、依赖漏洞 | [查看](docs/vulnerabilities/llm/supply-chain.md) |
| 敏感信息泄露 | LLM 泄露敏感数据 | [查看](docs/vulnerabilities/llm/sensitive-data-disclosure.md) |
| 不安全插件设计 | 插件安全缺陷 | [查看](docs/vulnerabilities/llm/insecure-plugin-design.md) |
| 过度自主权 | Agent 权限过大 | [查看](docs/vulnerabilities/llm/excessive-agency.md) |
| 硬编码 API 密钥 | LLM 密钥硬编码 | [查看](docs/vulnerabilities/llm/hardcoded-api-key.md) |

### 框架专项

#### Java 传统框架

| 框架/组件 | 典型漏洞 | 文档 |
|-----------|---------|------|
| Spring | SpEL注入、RCE | [查看](docs/frameworks/spring.md) |
| Struts2 | OGNL注入、RCE | [查看](docs/frameworks/struts2.md) |
| Shiro | RememberMe反序列化 | [查看](docs/frameworks/shiro.md) |
| Fastjson | AutoType反序列化 | [查看](docs/frameworks/fastjson.md) |
| Log4j2 | JNDI注入、RCE | [查看](docs/frameworks/log4j2.md) |

#### LLM/AI 框架

| 框架 | 安全关注点 | 文档 |
|------|-----------|------|
| Spring AI | Prompt注入防护、API密钥管理 | [查看](docs/frameworks/spring-ai.md) |
| LangChain4j | Agent安全、工具调用风险 | [查看](docs/frameworks/langchain4j.md) |

## 目录结构

```
java-security-issues/
├── README.md                    # 项目介绍
├── LICENSE                      # MIT 许可证
├── docs/
│   ├── news/                    # 每周安全动态
│   ├── classification/          # 分类体系
│   ├── vulnerabilities/         # 漏洞详解
│   ├── frameworks/              # 框架专项
│   └── tools/                   # 工具链
├── examples/                    # 代码示例
│   ├── vulnerable/              # 漏洞代码
│   └── secure/                  # 安全代码
├── data/                        # 结构化数据
│   ├── issues.json              # 问题清单
│   └── cwe-mapping.csv          # CWE 映射表
└── contributing/                # 贡献指南
```

## 快速开始

### 作为知识库使用

直接浏览 `docs/` 目录下的 Markdown 文档。

### 作为检测工具使用

```bash
# 使用 Semgrep 规则检测代码
semgrep --config docs/tools/semgrep-rules/ ./src

# 使用 CodeQL 查询
codeql database analyze ./db docs/tools/codeql-queries/
```

### 作为依赖库使用

```bash
# 克隆仓库
git clone https://github.com/shawnzhao170627/java-security-issues.git

# 引用结构化数据
import issues from './java-security-issues/data/issues.json';
```

## 贡献指南

我们欢迎所有形式的贡献！

- 报告问题或提出建议：[创建 Issue](https://github.com/shawnzhao170627/java-security-issues/issues)
- 贡献内容：请阅读 [贡献指南](contributing/how-to-contribute.md)
- 贡献代码示例：请阅读 [代码示例指南](contributing/code-examples.md)

### 贡献者

感谢所有贡献者的付出！

<a href="https://github.com/shawnzhao170627/java-security-issues/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=shawnzhao170627/java-security-issues" />
</a>

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## 相关项目

### 传统安全
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE - MITRE](https://cwe.mitre.org/)
- [JavaSec](https://www.javasec.org/)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)

### LLM 安全
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Spring AI Security](https://docs.spring.io/spring-ai/reference/security.html)
- [LangChain Security](https://python.langchain.com/docs/security/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

## 联系方式

- 提交 Issue：[GitHub Issues](https://github.com/shawnzhao170627/java-security-issues/issues)
- 讨论：[GitHub Discussions](https://github.com/shawnzhao170627/java-security-issues/discussions)

---

**如果这个项目对你有帮助，请给一个 ⭐ Star 支持一下！**
