# AGENTS.md — AI 贡献者指南

本文件面向 AI 编码工具（Qoder、GitHub Copilot、Devin 等），说明如何正确为本项目贡献内容。

---

## 项目结构约定

```
java-security-issues/
├── llms.txt                          # AI 工具项目导航（优先读取）
├── AGENTS.md                         # AI 贡献规范（本文件）
├── data/
│   ├── issues.json                   # 全局结构化索引（所有变更必须同步）
│   └── issues.schema.json            # issues.json 的 JSON Schema 约束
├── docs/
│   ├── classification/               # 分类体系文档
│   ├── vulnerabilities/              # 漏洞详解，按 category 分子目录
│   │   ├── injection/
│   │   ├── file-operations/
│   │   ├── authentication/
│   │   ├── deserialization/
│   │   ├── crypto/
│   │   ├── configuration/
│   │   ├── business-logic/
│   │   ├── frameworks/
│   │   └── llm/                      # LLM 应用安全专项
│   ├── frameworks/                   # 框架专项文档
│   ├── tools/semgrep-rules/          # Semgrep 检测规则
│   └── news/                         # 安全动态
├── examples/
│   ├── vulnerable/                   # 漏洞代码示例（含 [VULNERABLE] 标注）
│   └── secure/                       # 安全代码示例（含 [SECURE] 标注）
└── contributing/                     # 人工贡献指南
```

---

## 新增漏洞的操作步骤

新增一个漏洞条目，**必须**同时完成以下 4 步，缺一不可：

### 第 1 步：在 `data/issues.json` 添加结构化条目

按 JSON Schema（`data/issues.schema.json`）约束添加，所有字段含义如下：

```json
{
  "id": "VULN-ID",
  "name": "漏洞中文名",
  "name_en": "Vulnerability English Name",
  "category": "injection",
  "owasp": "A05:2025",
  "owasp_llm": "LLM01",
  "cwe": ["CWE-89"],
  "severity": "critical",
  "description": "一句话描述漏洞",
  "description_en": "One-sentence description in English",
  "java_affected": ["受影响的 Java 组件或框架"],
  "doc_path": "docs/vulnerabilities/{category}/{id-lowercase}.md",
  "examples": {
    "vulnerable": "examples/vulnerable/{Name}Vulnerable.java",
    "secure": "examples/secure/{Name}Secure.java"
  },
  "semgrep_rule": "docs/tools/semgrep-rules/{category}.yml",
  "detection_methods": ["静态分析", "动态测试"],
  "mitigation": ["修复措施1", "修复措施2"],
  "tags": ["标签1", "标签2"],
  "last_updated": "YYYY-MM-DD",
  "references": [
    "https://权威来源链接"
  ]
}
```

**字段约束**（违反会导致 Schema 验证失败）：
- `severity` 只能是：`critical` / `high` / `medium` / `low`
- `category` 只能是：`injection` / `file-operations` / `authentication` / `deserialization` / `crypto` / `configuration` / `business-logic` / `frameworks` / `llm`
- `id` 格式：大写字母 + 连字符，如 `SQL-INJECTION`、`PROMPT-INJECTION`
- `doc_path` 必须与实际创建的文件路径一致

---

### 第 2 步：创建漏洞详细文档

文件路径：`docs/vulnerabilities/{category}/{id-lowercase}.md`

**文档必须以 YAML Front Matter 开头**（AI 工具解析元数据用）：

```markdown
---
id: VULN-ID
name: 漏洞名称
severity: critical
owasp: A05:2025
cwe: [CWE-89]
category: injection
frameworks: [JDBC, MyBatis]
last_updated: YYYY-MM-DD
doc_version: "1.0"
---

# 漏洞名称

> 最后更新：YYYY-MM-DD

## 概述

## 风险等级

| 维度 | 评级 |
|------|------|
| OWASP Top 10 | AXX:2025 - 名称 |
| CWE | CWE-XXX |
| 严重程度 | 严重/高危/中危/低危 |

## 攻击类型

## Java 场景

## 检测方法

## 防护措施

## 参考资料
```

**章节顺序不可变更**，AI 工具依赖固定偏移量定位内容。

---

### 第 3 步：添加代码示例

**漏洞代码**（`examples/vulnerable/{Name}Vulnerable.java`）：

```java
// [VULNERABLE] 文件说明：演示 XXX 漏洞，仅用于教学目的
// 漏洞类型：VULN-ID
// 风险等级：critical
// 对应文档：docs/vulnerabilities/{category}/{id}.md

public class {Name}Vulnerable {

    // [VULNERABLE] 此方法存在 XXX 漏洞，原因：...
    public void vulnerableMethod(String input) {
        // 漏洞代码
    }
}
```

**安全代码**（`examples/secure/{Name}Secure.java`）：

```java
// [SECURE] 文件说明：演示 XXX 漏洞的安全修复方案
// 修复方式：参数化查询 / 输入验证 / ...
// 对应文档：docs/vulnerabilities/{category}/{id}.md

public class {Name}Secure {

    // [SECURE] 修复了 [VULNERABLE] 版本中的 XXX 漏洞，修复方式：...
    public void secureMethod(String input) {
        // 安全代码
    }
}
```

---

### 第 4 步：在 Semgrep 规则文件中添加检测规则

在对应的 `docs/tools/semgrep-rules/{category}.yml` 中追加规则：

```yaml
- id: java-{category}-{vuln-id-lowercase}
  pattern: |
    # 匹配漏洞代码模式
  message: |
    检测到 XXX 漏洞。建议：...
  severity: ERROR
  languages: [java]
  metadata:
    category: security
    subcategory: {category}
    cwe: CWE-XXX
    references:
      - https://权威来源
```

---

## 更新现有文档的规则

- **允许**：补充攻击类型、添加新的 Java 示例、更新防护措施、修正错误
- **禁止**：修改 `id` 字段、删除已有章节、降低风险等级（需提 Issue 讨论）
- **禁止**：删除任何文件（如需废弃，在 Front Matter 中添加 `deprecated: true`）

更新文档后必须同步更新 `data/issues.json` 中对应条目的 `last_updated` 字段。

---

## 安全红线（必须遵守）

1. **禁止**提交可实际利用的攻击 payload（如真实的 SQL 注入绕过串、完整 exploit 代码）
2. **禁止**在代码示例中包含真实的 API 密钥、密码、内网地址
3. **禁止**添加描述如何攻击特定真实系统的内容
4. 代码示例只用于演示漏洞原理，不能作为攻击工具

---

## PR 自检清单

AI 工具提交 PR 前，必须确认以下所有项：

```
数据层
[ ] data/issues.json 已新增或更新对应条目
[ ] 新增条目通过 issues.schema.json 的 Schema 校验
[ ] doc_path 字段与实际文件路径一致

文档层
[ ] 文档包含完整的 YAML Front Matter
[ ] Front Matter 中 id/severity/category 与 issues.json 一致
[ ] 章节顺序符合规范（概述/风险等级/攻击类型/Java场景/检测方法/防护措施/参考资料）
[ ] 至少包含一个 Java 代码示例

代码层
[ ] 漏洞示例文件含 [VULNERABLE] 标注
[ ] 安全示例文件含 [SECURE] 标注
[ ] 代码示例不含真实可利用的 payload

规则层
[ ] Semgrep 规则文件已追加对应规则
[ ] 规则 id 格式为 java-{category}-{vuln-id-lowercase}

安全
[ ] 无真实 API 密钥、密码等敏感信息
[ ] 无可实际利用的攻击代码
```

---

## Commit 信息规范

```
<type>(<scope>): <subject>

类型（type）：
  feat     新增漏洞/内容
  fix      修正错误信息
  update   更新现有文档
  rule     新增/修改检测规则
  data     更新 issues.json 数据

范围（scope）：漏洞 id 或目录名，如 sql-injection、llm、frameworks

示例：
  feat(prompt-injection): 新增 Spring AI Prompt 注入漏洞文档
  rule(llm): 新增硬编码 API 密钥检测规则
  update(sql-injection): 补充 HQL 注入示例
  data: 更新 SSRF 条目的 doc_path 字段
```

---

## 快速参考

| 需求 | 读取路径 |
|------|---------|
| 了解所有漏洞列表 | `data/issues.json` |
| 查找某个漏洞详情 | `issues.json[].doc_path` |
| 获取检测规则 | `docs/tools/semgrep-rules/` |
| 查看代码对比示例 | `examples/vulnerable/` + `examples/secure/` |
| 了解分类标准 | `docs/classification/` |
