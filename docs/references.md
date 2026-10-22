# 参考项目与标准化选择

参考时间：2026-10-22。借鉴工程做法，没有复制这些项目的实现代码，不表示得到它们背书。

| 参考 | 可借鉴做法 | 本项目选择 |
|---|---|---|
| [PyPA pip-audit](https://github.com/pypa/pip-audit) | 安装、用法、退出码和安全模型单独说明 | 首页面向使用者，证据限制与门禁有明确文档 |
| [Yelp detect-secrets 贡献指南](https://github.com/Yelp/detect-secrets/blob/master/CONTRIBUTING.md) | 设计、开发环境与完整测试相互链接 | 贡献者可按设计、测试和制品验证步骤操作 |
| [Ruff 贡献指南](https://github.com/astral-sh/ruff/blob/main/CONTRIBUTING.md) | 提交前运行格式/检查，由 CI 重复验证 | Ruff 统一格式和基础 lint，不增加运行依赖 |
| [Python 官方打包指南](https://packaging.python.org/en/latest/tutorials/packaging-projects/) | pyproject 元数据、wheel 与源码分发 | distribution 名 riskcheck-offline，模块/命令为 riskcheck，规则作为数据包分发 |
| [GitHub Actions 安全指南](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) | 最小令牌权限与固定 Action 引用 | 普通 CI 只读，发布 job 单独申请写权限，Action 固定提交号 |

没有引入在线数据库、自动修复或后台服务，因为它们会改变离线检测边界。项目代码与原创文档采用 MIT；上游公告、文档和代码保持各自许可，引用用于说明事实和工程取舍。
