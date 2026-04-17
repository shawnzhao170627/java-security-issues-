# 发布到 GitHub 操作指南

> 本指南涵盖：初始发布流程 + GitHub 仓库 AI 友好配置 + 后续维护流程

---

## 目录

1. [前置准备](#1-前置准备)
2. [初始化本地 Git 仓库](#2-初始化本地-git-仓库)
3. [在 GitHub 创建仓库](#3-在-github-创建仓库)
4. [推送代码到 GitHub](#4-推送代码到-github)
5. [GitHub 仓库 AI 友好配置](#5-github-仓库-ai-友好配置)
6. [验证 AI 可读性](#6-验证-ai-可读性)
7. [日常维护流程](#7-日常维护流程)
8. [附录：项目 AI 友好设计说明](#附录项目-ai-友好设计说明)

---

## 1. 前置准备

### 1.1 确认本地环境

```bash
# 确认 Git 已安装
git --version

# 确认已登录 GitHub CLI（可选，推荐）
gh auth status
```

### 1.2 确认项目文件完整

发布前检查以下关键文件均已存在：

```
java-security-issues/
├── README.md                         ✅ 含"项目一览"表和 AI 快速入口
├── llms.txt                          ✅ AI 工具项目导航文件
├── AGENTS.md                         ✅ AI 贡献者规范
├── data/
│   ├── issues.json                   ✅ 全量结构化索引（24 条）
│   └── issues.schema.json            ✅ JSON Schema 约束
├── .github/
│   ├── pull_request_template.md      ✅ PR 模板（含 AI 自检清单）
│   └── ISSUE_TEMPLATE/
│       ├── new-vulnerability.yml     ✅ 新增漏洞 Issue 模板
│       ├── doc-improvement.yml       ✅ 文档改进 Issue 模板
│       └── security-news.yml         ✅ 安全动态 Issue 模板
├── docs/
│   ├── classification/
│   │   ├── owasp-top10.md            ✅
│   │   ├── owasp-llm-top10.md        ✅ LLM Top 10 专项
│   │   ├── cwe-top25.md              ✅
│   │   └── java-specific.md          ✅
│   ├── vulnerabilities/              ✅ 各漏洞文档含 YAML Front Matter
│   ├── frameworks/
│   └── tools/semgrep-rules/          ✅ 含 LLM 安全规则
└── examples/
    ├── vulnerable/                   ✅ 含 [VULNERABLE] 标注
    └── secure/                       ✅ 含 [SECURE] 标注
```

---

## 2. 初始化本地 Git 仓库

```bash
# 进入项目目录
cd /path/to/java-security-issues

# 初始化 Git 仓库
git init

# 配置用户信息（如已全局配置可跳过）
git config user.name "你的 GitHub 用户名"
git config user.email "你的注册邮箱"

# 查看待提交文件
git status
```

### 2.1 检查 .gitignore

确认 `.gitignore` 中包含常见排除项：

```gitignore
# IDE
.idea/
.vscode/
*.iml

# OS
.DS_Store
Thumbs.db

# 编译产物
target/
*.class

# 敏感信息（绝对不能提交）
.env
*.key
secrets/
```

### 2.2 创建首次提交

```bash
# 添加所有文件
git add .

# 确认暂存内容（检查无敏感文件）
git status

# 创建首次提交
git commit -m "init: Java & LLM 应用安全知识库初始版本

- 覆盖传统 Java 安全（OWASP Top 10、CWE Top 25、Java 专项）
- 覆盖 LLM 应用安全（OWASP LLM Top 10）
- 24 条结构化漏洞数据（data/issues.json）
- Semgrep 检测规则（SQL注入、反序列化、LLM安全）
- AI 友好设计：llms.txt + AGENTS.md + JSON Schema"
```

---

## 3. 在 GitHub 创建仓库

### 方式 A：GitHub CLI（推荐）

```bash
# 创建公开仓库并推送
gh repo create java-security-issues \
  --public \
  --description "最完整的 Java & LLM 应用软件安全问题知识库 | Java & LLM Application Security Knowledge Base" \
  --push \
  --source .
```

### 方式 B：网页操作

1. 登录 GitHub，点击右上角 **+** → **New repository**
2. 填写信息：
   - **Repository name**：`java-security-issues`
   - **Description**：`最完整的 Java & LLM 应用软件安全问题知识库 | Java & LLM Application Security Knowledge Base`
   - 选择 **Public**
   - **不要**勾选任何初始化选项（本地已有完整内容）
3. 点击 **Create repository**，记录仓库 URL

---

## 4. 推送代码到 GitHub

### 4.1 关联远程仓库并推送

```bash
# 方式 A：HTTPS（需要 Personal Access Token）
git remote add origin https://github.com/你的用户名/java-security-issues.git

# 方式 B：SSH（推荐，免密码）
git remote add origin git@github.com:你的用户名/java-security-issues.git

# 推送到 main 分支
git push -u origin main
```

> **如果遇到 `master` vs `main` 问题**：
> ```bash
> # 将默认分支重命名为 main
> git branch -M main
> git push -u origin main
> ```

### 4.2 SSH 密钥配置（首次使用）

```bash
# 生成 SSH 密钥
ssh-keygen -t ed25519 -C "你的邮箱"

# 查看公钥内容
cat ~/.ssh/id_ed25519.pub
```

复制公钥内容，在 GitHub **Settings → SSH and GPG keys → New SSH key** 中粘贴添加。

```bash
# 验证 SSH 连接
ssh -T git@github.com
# 输出 "Hi username! You've successfully authenticated." 表示成功
```

### 4.3 替换 README 中的占位符

```bash
# 将 your-org 替换为真实 GitHub 用户名（macOS）
sed -i '' 's/your-org/你的用户名/g' README.md

# Linux
sed -i 's/your-org/你的用户名/g' README.md

# 提交更新
git add README.md
git commit -m "fix: 更新 README 中的仓库地址为实际用户名"
git push
```

---

## 5. GitHub 仓库 AI 友好配置

**这是本项目区别于普通知识库的核心配置，直接影响 AI 工具的发现率和理解质量。**

### 5.1 设置仓库基本信息（网页操作）

进入仓库页面，点击右侧 **About** 旁的齿轮图标：

| 字段 | 填写内容 |
|------|---------|
| Description | `最完整的 Java & LLM 应用软件安全问题知识库` |
| Website | （开启 GitHub Pages 后填入，见 5.3） |
| Topics | 见下方 |

**Topics 推荐配置**（对 GitHub Copilot 和搜索引擎均有效）：

```
java
security
owasp
owasp-top-10
llm-security
prompt-injection
cwe
semgrep
spring-security
vulnerability
knowledge-base
java-security
llm
spring-ai
langchain4j
```

> Topics 是 GitHub 搜索和 Copilot 检索时权重最高的字段，务必设置完整。

### 5.2 开启 GitHub Pages（让 llms.txt 可被外部访问）

进入仓库 **Settings → Pages**：

- **Source**：选择 `Deploy from a branch`
- **Branch**：选择 `main`，目录选 `/ (root)`
- 保存后等待约 1 分钟，获得访问地址：
  `https://你的用户名.github.io/java-security-issues/`

开启后，`llms.txt` 的公开访问地址为：
```
https://你的用户名.github.io/java-security-issues/llms.txt
```

AI 工具（支持 llms.txt 标准的工具）可通过此地址直接读取项目导航。

### 5.3 更新 README 徽章中的实际链接

GitHub Pages 开启后，更新 README 顶部的 llms.txt 徽章为可点击的真实链接：

```bash
# 编辑 README.md，将 llms.txt 徽章的链接更新为 GitHub Pages 地址
# 将：
# [![llms.txt](https://img.shields.io/badge/AI-llms.txt-green)](llms.txt)
# 改为：
# [![llms.txt](https://img.shields.io/badge/AI-llms.txt-green)](https://你的用户名.github.io/java-security-issues/llms.txt)
```

### 5.4 配置仓库安全设置

进入 **Settings → General**，建议开启：

- **Discussions**：允许社区讨论，AI 工具可读取讨论内容
- **Issues**：确保已开启，Issue 模板才能生效

进入 **Settings → Branches**，建议配置：

- 保护 `main` 分支：要求 PR 审核后才能合并（防止 AI 工具直接推送到主分支）

---

## 6. 验证 AI 可读性

发布完成后，通过以下方式验证 AI 友好性：

### 6.1 验证 llms.txt 可访问

```bash
# 验证 GitHub Pages 上的 llms.txt 是否可访问
curl https://你的用户名.github.io/java-security-issues/llms.txt
```

### 6.2 验证 issues.json 结构完整

```bash
# 克隆仓库后验证 JSON 格式
git clone https://github.com/你的用户名/java-security-issues.git
cd java-security-issues

# 验证 JSON 格式合法
python3 -c "import json; data=json.load(open('data/issues.json')); print(f'共 {len(data)} 条记录')"

# 验证所有条目都有 doc_path 字段
python3 -c "
import json
data = json.load(open('data/issues.json'))
missing = [d['id'] for d in data if 'doc_path' not in d]
print('缺少 doc_path 的条目:', missing if missing else '无')
"
```

### 6.3 验证漏洞文档包含 Front Matter

```bash
# 检查所有漏洞文档是否有 Front Matter（以 --- 开头）
for f in docs/vulnerabilities/**/*.md; do
  if ! head -1 "$f" | grep -q "^---"; then
    echo "缺少 Front Matter: $f"
  fi
done
```

### 6.4 用 AI 工具做一次测试读取

给你的 AI 工具（Qoder、Copilot 等）以下提示，验证它能快速理解项目：

```
请读取这个 GitHub 仓库的 llms.txt 和 data/issues.json，
告诉我：
1. 项目覆盖了哪些安全分类？
2. 其中 LLM 安全相关的漏洞有哪些？
3. 如果我想查看 Prompt 注入的详细文档，应该读哪个文件？
```

如果 AI 能准确回答以上三问，说明 AI 可读性验证通过。

---

## 7. 日常维护流程

### 7.1 每周更新安全动态

```bash
# 创建本周动态文件（参考模板）
cp docs/news/TEMPLATE.md docs/news/2026/2026-W17.md

# 编辑内容后提交
git add docs/news/2026/2026-W17.md
git commit -m "news(2026-W17): 本周 Java & LLM 安全动态"
git push
```

### 7.2 新增漏洞文档

每次新增漏洞，**必须同时更新 4 个位置**：

```bash
# 1. 更新 data/issues.json（新增条目，含 doc_path）
# 2. 新建文档 docs/vulnerabilities/{category}/{id}.md（含 Front Matter）
# 3. 新建示例 examples/vulnerable/{Name}Vulnerable.java（含 [VULNERABLE] 标注）
# 4. 新建示例 examples/secure/{Name}Secure.java（含 [SECURE] 标注）

# 完成后统一提交
git add .
git commit -m "feat(xxe): 新增 XML 外部实体注入漏洞文档"
git push
```

> 完整规范参见 [AGENTS.md](AGENTS.md)

### 7.3 接受社区 PR

AI 工具或社区成员提交 PR 时，检查 `.github/pull_request_template.md` 中的自检清单是否全部勾选，重点确认：

- `data/issues.json` 已同步更新
- 文档包含 YAML Front Matter
- 无真实可利用的攻击 payload

### 7.4 标准 commit 格式

```
feat(scope)   新增漏洞/内容
update(scope) 更新现有文档
fix(scope)    修正错误信息
rule(scope)   新增/修改检测规则
data          更新 issues.json 数据
news(week)    安全动态周报

示例：
feat(prompt-injection): 补充 LangChain4j Agent 攻击场景
rule(llm): 新增 RAG 数据投毒 Semgrep 检测规则
news(2026-W17): Spring Security 6.4.1 安全更新
```

---

## 附录：项目 AI 友好设计说明

本项目在设计上针对 AI 工具的读取和贡献做了系统性优化，形成三层索引架构：

```
AI 工具访问路径：

┌─────────────────────────────────────────┐
│  第一层：发现（Discoverability）          │
│                                         │
│  llms.txt          ← AI 导航标准文件     │
│  GitHub Topics     ← 搜索信号           │
│  README 前 15 行   ← 项目一览表         │
└────────────────┬────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│  第二层：理解（Readability）              │
│                                         │
│  data/issues.json  ← 全量结构化索引     │
│  issues.schema.json← 数据格式约束       │
│  YAML Front Matter ← 文档元数据         │
└────────────────┬────────────────────────┘
                 ↓
┌─────────────────────────────────────────┐
│  第三层：贡献（Contribution）            │
│                                         │
│  AGENTS.md         ← AI 贡献规范        │
│  Issue 模板        ← 结构化输入         │
│  PR 模板           ← AI 自检清单        │
└─────────────────────────────────────────┘
```

### 关键文件说明

| 文件 | 作用 | AI 读取场景 |
|------|------|------------|
| `llms.txt` | 项目导航入口，类似 `robots.txt` | AI 首次访问，获取全局结构 |
| `data/issues.json` | 全量结构化索引，每条含 `doc_path` | AI 查询漏洞列表，定位文档 |
| `data/issues.schema.json` | JSON Schema 约束 | AI 生成新条目时校验格式 |
| `AGENTS.md` | AI 贡献者规范 | AI 提交 PR 前读取 |
| YAML Front Matter | 文档顶部的结构化元数据 | AI 快速提取 severity/cwe/owasp |
| `.github/` 模板 | 结构化 Issue/PR 输入 | AI 提交变更请求 |

### GitHub Topics 配置说明

Topics 对 AI 工具的影响：
- **GitHub Copilot**：在搜索相关仓库时以 Topics 作为主要过滤条件
- **网络检索型 AI**（Perplexity、ChatGPT Search）：Topics 作为页面关键词被索引
- **开发者搜索**：Topics 是 GitHub 搜索的核心筛选维度

推荐必设的最小 Topics 集合：`java` `security` `owasp` `llm-security` `knowledge-base`
