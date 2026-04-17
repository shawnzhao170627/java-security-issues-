# 周报维护指南

## 更新频率

- 每周一发布上周安全动态
- 重大安全事件可随时发布紧急更新

## 更新流程

### 1. 收集信息

从以下来源收集 Java 安全信息：

| 来源 | 链接 | 关注内容 |
|------|------|---------|
| NVD | https://nvd.nist.gov/ | 新增 CVE |
| Spring Security | https://spring.io/security | Spring 安全公告 |
| Apache Security | https://www.apache.org/security/ | Apache 项目安全公告 |
| Oracle CPU | https://www.oracle.com/security-alerts/ | Oracle 补丁更新 |
| GitHub Security | https://github.com/advisories | 依赖安全公告 |

### 2. 创建周报

1. 复制 `TEMPLATE.md` 模板
2. 命名为 `2026/2026-WXX.md`（XX 为周数）
3. 填写本周内容
4. 更新 `README.md` 中的索引

### 3. 内容规范

#### 框架更新

记录主要内容：
- 版本号
- 发布日期
- 安全相关更新点
- 升级建议

#### 安全漏洞

必须包含：
- CVE 编号
- 组件名称
- 严重程度
- 影响版本
- 修复方案
- 参考链接

#### 工具更新

记录安全工具更新：
- Semgrep
- CodeQL
- OWASP Dependency-Check
- Snyk

### 4. 发布检查

- [ ] 所有链接可访问
- [ ] CVE 编号正确
- [ ] 版本号准确
- [ ] 周数正确
- [ ] README 索引已更新

## 周数计算

```bash
# 获取当前周数
date +%V
```

## 信息来源优先级

1. **官方公告**：Spring、Apache、Oracle 官方安全公告
2. **NVD/CVE**：权威漏洞数据库
3. **安全社区**：安全客、Seebug 等
4. **社交媒体**：Twitter、安全研究博客

## 注意事项

- 只收录与 Java 相关的安全信息
- 优先关注高危及以上漏洞
- 提供可操作的修复建议
- 保持内容客观准确
- 不发布未公开的 0day 信息
