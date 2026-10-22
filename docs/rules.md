# 规则维护

数据位于 `riskcheck_data/rules.json`，当前 revision 为 `2026-10-22.1`，核实日期为 2026-10-22。工具升级打包功能不会自动刷新规则日期。

| 组件 | 数量 | 来源 |
|---|---:|---|
| Node.js | 10 | [官方安全公告](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) |
| PHP | 2 | [官方公告](https://www.php.net/archive/2026.php) |
| nginx | 5 | [官方安全列表](https://nginx.org/en/security_advisories.html) |
| Tomcat | 1 | [Apache 公告](https://tomcat.apache.org/security-11.html) |
| Go | 1 | [官方漏洞库](https://pkg.go.dev/vuln/GO-2026-6809) |
| Rust | 3 | [RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) |
| LiteLLM | 1 | [维护方事件通告](https://docs.litellm.ai/blog/security-incident-oct-21-2026) |

规则是简要事实归纳和本项目策略，不复制公告全文。字段包括 ID、组件、严重度、优先级、条件、建议与来源；版本策略按分支或区间判断。

维护步骤：

1. 从维护方或原始研究核实 ID、分支、修复边界与披露状态，记录来源。
2. 先补修复前一版、修复版、其他分支、预发布与厂商版本测试。
3. 修改 policies、rules 和 sources。没有官方评分时保留 unscored，不把本项目优先级冒充 CVSS。
4. 恶意制品用完整摘要，注明类型和来源，不能用摘要前缀确认。
5. 跑全部测试与制品验证，更新 revision、核实日期和 CHANGELOG，提交证据变化。

公告未提供精确引入版本时，按已核实发行线的修复边界判断，需结合来源复核。Go/Rust 的 high 是门禁策略；nginx 五条保留官方 medium。

厂商回补按 rule_id 附 HTTPS 公告，操作者先核对包修订号和部署记录。它不是通用忽略项，对 LiteLLM 投毒历史无豁免效果。普通启动文件名仅是线索；未发现也不能排除历史暴露。

规则默认超过 30 天或核实时间明显在未来即返回 2。真实 CI 不固定 `--as-of`；改变时效策略需要复核，而非仅改时间戳或阈值。
