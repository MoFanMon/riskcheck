# Changelog

版本使用语义化的三段版本号；0.x 阶段的变更在每次发布中说明。规则 revision 和核实日期独立于工具版本。

## [0.1.0] - 2026-10-22

### Added

- 23 条专项公告/事件规则，覆盖版本、配置线索与 LiteLLM 历史暴露。
- 文本、JSON、离线 HTML；风险和证据缺口的独立 CI 退出码。
- 标准 pyproject/wheel/源码分发，自带规则的便携 pyz 和 SHA256SUMS。
- 中文首页、英文简介、用法、原理、部署、规则维护与贡献文档。
- MIT 许可证、Issue/PR 模板、安全策略、格式规范、测试与发布工作流。
- 便携下载制品、摘要和隔离运行的分发测试。

### Changed

- 内置规则从根目录 rules.json 移至 riskcheck_data/rules.json，默认 CLI 自动加载。
- JSON 新增 tool_version 字段，保留 schema_version=1 与原退出码语义。
- 新增 --version，可在不指定目标目录时查看版本。

尚未发布到 PyPI，也未发布预构建容器镜像。首次 Release 之前的原型无正式版本标签。

[0.1.0]: https://github.com/MoFanMon/riskcheck/releases/tag/v0.1.0
