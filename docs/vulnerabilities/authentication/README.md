# 认证授权类漏洞索引

> 最后更新：2026-04-17

## 概述

认证授权类漏洞涉及身份验证和访问控制机制的缺陷，是最常见的安全问题之一。

## 漏洞类型

| 漏洞类型 | CWE | 严重程度 | 文档 |
|---------|-----|---------|------|
| 身份认证绕过 | CWE-287 | 严重 | [查看](authentication-bypass.md) |
| 未授权访问 | CWE-862 | 高危 | [查看](unauthorized-access.md) |
| 纵向越权 | CWE-269 | 高危 | [查看](vertical-privilege.md) |
| 横向越权 | CWE-639 | 高危 | [查看](horizontal-privilege.md) |
| Session 劫持 | CWE-384 | 高危 | [查看](session-hijacking.md) |
| 密码安全 | CWE-522 | 高危 | [查看](password-security.md) |

## OWASP 映射

| OWASP | 涵盖漏洞 |
|-------|---------|
| A01:2025 - Broken Access Control | 未授权访问、越权访问、IDOR |
| A07:2025 - Authentication Failures | 认证绕过、Session 劫持、弱密码 |

## Java 框架相关

| 框架 | 常见问题 |
|------|---------|
| Spring Security | 配置错误、权限注解遗漏 |
| Apache Shiro | 认证绕过、RememberMe 反序列化 |
| 自定义实现 | 缺乏安全机制、逻辑缺陷 |
