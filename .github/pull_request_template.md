## 变更类型

- [ ] 新增漏洞文档
- [ ] 更新现有文档
- [ ] 新增检测规则
- [ ] 新增代码示例
- [ ] 数据修正（issues.json）
- [ ] 安全动态周报

## 关联 Issue

Closes #

## 变更文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `data/issues.json` | 新增/更新/无 | |
| `docs/vulnerabilities/` | 新增/更新/无 | 路径： |
| `examples/` | 新增/无 | |
| `docs/tools/semgrep-rules/` | 新增/更新/无 | |

## 变更摘要

<!-- 简要描述本次 PR 的内容和目的 -->

---

## AI 工具自检清单

> 如果你是 AI 工具提交的 PR，请确认以下所有项。人工贡献者也建议参考检查。

### 数据层
- [ ] `data/issues.json` 已新增或更新对应条目
- [ ] 新增条目符合 `data/issues.schema.json` 约束（`id` 格式、`severity` 枚举值、`category` 枚举值）
- [ ] `doc_path` 字段与实际创建的文件路径一致

### 文档层
- [ ] 文档包含完整的 YAML Front Matter（id / name / severity / owasp / cwe / category / last_updated）
- [ ] Front Matter 中的字段值与 `issues.json` 对应条目一致
- [ ] 文档章节顺序正确：概述 → 风险等级 → 攻击类型 → Java 场景 → 检测方法 → 防护措施 → 参考资料
- [ ] 至少包含一个带注释的 Java 代码示例

### 代码层
- [ ] 漏洞示例文件包含 `[VULNERABLE]` 标注
- [ ] 安全示例文件包含 `[SECURE]` 标注
- [ ] 代码示例不含真实可利用的攻击 payload

### 规则层
- [ ] 对应 Semgrep 规则已添加或更新
- [ ] 规则 `id` 格式为 `java-{category}-{vuln-id-lowercase}`

### 安全红线
- [ ] 无硬编码的真实 API 密钥、密码、内网地址
- [ ] 无可实际用于攻击的完整 exploit 代码
- [ ] 无针对特定真实系统的攻击描述
