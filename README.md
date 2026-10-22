# RiskCheck

[![CI](https://github.com/MoFanMon/riskcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/MoFanMon/riskcheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**面向运维和 CI 的离线事件风险检测工具。** 读取项目文件与资产版本清单，输出风险依据、证据缺口和修复建议。仅用 Python 标准库，不联网、不安装目标依赖、不执行目标代码。

[English](README.en.md) · [下载安装](docs/deployment.md) · [完整用法](docs/usage.md) · [原理说明](docs/design.md) · [版本下载](https://github.com/MoFanMon/riskcheck/releases/latest)

当前版本 **0.1.0**，包含 **2026-10-22 核实的 23 条事件规则**，涉及 Node.js、PHP、nginx、Tomcat、Go、Rust 证书依赖及 LiteLLM 投毒事件。规则是有日期的专项快照，默认超过 30 天即要求复核；它不是实时全量 CVE 扫描服务。

## 它解决什么问题

- 同一轮安全事件涉及多种组件，需要统一检查版本、配置线索和处理建议。
- CI 不应把“版本未知”“文件读不到”“规则过期”当成安全通过。
- 受影响版本、可能触发的配置、执行过恶意制品，是不同等级的证据。
- 厂商回补可能不改变上游版本号；历史 LiteLLM 暴露也不能被当前升级覆盖。

支持项目目录、静态导出的文件系统和显式资产清单。运行中服务的版本由部署系统或操作者提供，不能用锁文件冒充运行态证据。

## 下载安装

推荐从 [Releases](https://github.com/MoFanMon/riskcheck/releases/latest) 下载便携版及 `SHA256SUMS`，在干净系统上校验后执行：

```sh
python3 -I -S riskcheck-0.1.0.pyz --version
python3 -I -S riskcheck-0.1.0.pyz --root /srv/myapp --format json
```

便携版自带规则，不需要 pip 或第三方包。需要 Python 3.9+；部署优先选择仍由供应商提供安全维护的 Python。

从源码运行也不需要安装：

```sh
git clone https://github.com/MoFanMon/riskcheck.git
cd riskcheck
python3 -I -S riskcheck.py --version
python3 -I -S riskcheck.py --root . --inventory-only --inventory examples/inventory-fixed.json
```

最后一条只检查合成示例资产，预期退出 0。用自己的目录和清单替换它。Release 还提供 wheel、源码 ZIP 和源码 tar.gz；[部署文档](docs/deployment.md) 包含离线安装、Windows、Docker 和 CI 步骤。尚未发布到 PyPI，不要通过同名陌生包安装。

## 实际检测示例

创建 `assets.json`，只放组件信息，不放账号、密钥或业务数据：

```json
{
  "schema_version": 1,
  "required_components": ["node"],
  "assets": [
    {"id": "api", "component": "node", "version": "24.22.0", "kind": "runtime"}
  ]
}
```

```sh
python3 -I -S riskcheck.py --root /srv/myapp --inventory assets.json --require node
python3 -I -S riskcheck.py --root /srv/myapp --inventory assets.json --format json --output risk-report.json
python3 -I -S riskcheck.py --root /srv/myapp --inventory assets.json --format html --output risk-report.html
```

输出文件不能已存在。HTML 可直接离线打开。只检查部署清单时加 `--inventory-only`。

| 退出码 | 含义 | CI 行为 |
|---|---|---|
| `0` | 给定证据在本次规则和阈值范围内通过 | 允许继续，不代表系统安全 |
| `1` | 命中风险阈值，默认 high | 阻断并处理风险 |
| `2` | 未知版本、缺口、规则过期或输入错误 | 阻断并补证据 |

medium/low 也会写入报告；用 `--fail-on medium` 或 `low` 调整门禁。真实 CI 不固定 `--as-of`，避免冻结时效判断。

## 文档

| 文档 | 内容 |
|---|---|
| [部署与下载](docs/deployment.md) | 便携版、校验、wheel、容器、CI、升级与卸载 |
| [完整用法](docs/usage.md) | 支持文件、资产清单、参数和状态 |
| [设计说明](docs/design.md) | 检测流程、信任边界和证据层次 |
| [规则维护](docs/rules.md) | 官方来源、版本边界、回补与时效 |
| [开发与发布](docs/development.md) | 测试、格式检查、打包、发布 |
| [参考项目与取舍](docs/references.md) | 标准化参考及采用原因 |
| [更新日志](CHANGELOG.md) | 按版本记录变化 |

## 边界

不发送漏洞载荷，不确认可利用性或系统已被入侵，不测试系统 CA 文件的实际 TLS 拦截效果。配置共现仅是线索；`vendor_attested` 是用户提交的厂商修复声明。完整限制随报告输出，见[设计说明](docs/design.md)。

## 开发与开源

```sh
python3 -I -S -m unittest discover -s tests -v
```

贡献前阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，工具自身漏洞按 [SECURITY.md](SECURITY.md) 处理。项目采用 [MIT License](LICENSE)；第三方公告与项目仍遵循各自许可。
