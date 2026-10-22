# 完整用法与输入证据

从仓库根目录执行下列源码命令。Python 3.9+，仅用标准库，无需安装依赖。读取指定目录与显式资产清单，输出文本、JSON 或独立 HTML 报告。第一版规则核实日期为 **2026-10-22**，共 **23 条规则**，来源保存在 `riskcheck_data/rules.json`。下载便携版或 wheel 的方法见[部署说明](deployment.md)。

这是针对本次事件的版本与证据检查器。没有获得目标系统的真实数据前，示例报告不代表你的机器已被检测。

## 快速开始

在解压后的 `riskcheck` 目录中运行，解释器应来自干净、可信的系统。`-I -S` 用于隔离 Python 搜索路径并禁用 site 初始化，避免加载目标环境的 `.pth` / `sitecustomize.py`。

```sh
# 演示受影响资产与 LiteLLM 历史暴露：预期退出 1
python3 -I -S riskcheck.py --root . --inventory-only --inventory examples/inventory.json

# 演示已修复版本：预期退出 0，仅在本次版本规则范围内通过
python3 -I -S riskcheck.py --root . --inventory-only --inventory examples/inventory-fixed.json

# 实际扫描项目目录，并纳入资产清单；修改为你的真实路径
python3 -I -S riskcheck.py --root /srv/myapp --inventory /srv/assets.json --require node

# JSON 报告，供 CI 读取；输出文件必须尚不存在
python3 -I -S riskcheck.py --root /srv/myapp --inventory /srv/assets.json --format json --output risk-report.json

# HTML 报告，无外部字体、脚本或网络资源
python3 -I -S riskcheck.py --root /srv/myapp --inventory /srv/assets.json --format html --output risk-report.html
```

报告路径的父目录必须已存在。工具拒绝覆盖现有报告。扫描目标不被修改；只有指定的报告文件会被创建。运行受影响示例返回非零是预期门禁行为，不是脚本故障。

## 检测范围

| 对象 | 检查方式 | 主要限制 |
|---|---|---|
| Node.js | 清单、`.nvmrc`、`.node-version`、`package.json` 的 `engines.node`、标准基础镜像标签 | 声明版本不等于运行中版本；范围、别名、浮动标签返回待核实 |
| PHP / nginx / Tomcat | 清单、标准基础镜像标签 | 不执行目标二进制；厂商回补需要逐条声明 |
| Go | 清单中的构建版本、`golang` 镜像；识别 `go.mod` 的最低要求 | `go.mod`、`toolchain` 声明不能证明产物用哪个编译器构建 |
| Rust 证书依赖 | `Cargo.lock` 中的 `rustls-webpki`、`webpki-roots`、`webpki-root-certs` | 不推断依赖图；0.26.11 包装层的父依赖需人工核实 |
| LiteLLM | 清单、`requirements*.txt`、`poetry.lock`、`uv.lock`、官方镜像名、安装元数据 | 版本命中不证明执行过恶意制品；官方源码 tag 与发布 wheel 不等价 |
| nginx 配置 | `nginx.conf` 及路径含 nginx 的 `.conf` 文件 | 只报告静态线索，不确认 location、继承、模块和真实生效状态 |
| Tomcat 配置 | `server.xml` 中的 JNDIRealm 及疑似 SASL 设置 | 外部覆盖、变量和实际认证机制需复核 |
| LiteLLM 文件线索 | 指定目录内的 `cook.pth`、`cook.py`、`sitecustomize.py`、两个公开事件标记文件名 | 普通启动文件也有合法用途；不读取文件内容作恶意判定；缺失不能排除入侵 |

TOML 锁文件仅读取标准 `[[package]]` 下单行双引号 `name`、`version` 字段，不是完整 TOML 解释器。无法理解的相关字段、损坏文件、超限、无权读取、符号链接与 nginx include 等均报告缺口，不静默放行。requirements 中环境标记、范围、URL 和引用文件不会被猜测为已解析版本；外部引用需要提供最终锁文件或纳入扫描范围。

第一版不解析 `package-lock.json`、pnpm/yarn 锁文件来判断 Node 运行时，因为 npm 依赖锁不能证明部署使用的 Node 版本；也不自动展开 Docker Compose、Helm、远程主机、运行中容器。自定义镜像、私有仓库镜像、产物版本请放入资产清单。

## 资产清单

复制并修改 `examples/inventory.json`。不要直接把演示资产带进真实 CI。每个部署、产物、历史暴露记录应使用独立 `id`；不同记录不会相互覆盖。

```json
{
  "schema_version": 1,
  "required_components": ["node"],
  "assets": [
    {
      "id": "production-api",
      "component": "node",
      "version": "24.22.0",
      "kind": "runtime",
      "context": {"brotli_untrusted": true}
    }
  ]
}
```

- `component`：`node`、`php`、`nginx`、`tomcat`、`go`、`litellm`、三个 Rust 包名。
- `kind`：`runtime`（清单声明的运行/构建版本）、`installed`、`locked`、`declared`、`historical`；工具还会生成 Go `minimum` 记录。
- `context`：布尔值，键可从规则的 `condition` 字段查看。它只是你提供的触发场景声明，**false 不会消除受影响版本命中**。
- `required_components` 或重复的 `--require node --require php`：指定本轮必须获得版本证据的组件。未声明的其他组件不被当作已扫描。
- `digest`：可提供镜像完整摘要。首版仅内置通告中一条完整公共摘要；其他恶意镜像摘要未录全，不能用未命中排除暴露。
- `vendor_fixes`：按 `rule_id` 附 HTTPS 厂商安全公告，详见 `inventory-vendor.json`。结果为 `vendor_attested`，不是工具独立确认。必须在审核确认具体包修复后填写，不能当作通用忽略开关；对 LiteLLM 投毒无豁免效果。

`--inventory-only` 只检查清单，不遍历 `--root`。适合由已有 CMDB、构建流水线或人工确认提供精确部署版本的场景。默认目录扫描会把不精确的 `engines`、`go.mod` 等保留为待核实，防止将声明冒充真实产物。

## 结论和 CI 退出码

| 状态 | 含义 |
|---|---|
| `affected` | 版本符合本条规则，需要更新或核实触发条件；不表示已成功利用 |
| `artifact_match` | 完整摘要命中已知恶意制品；不自动证明制品执行过 |
| `exposure` | 用户清单记录受影响版本曾安装/运行；不能被当前升级记录覆盖 |
| `unknown` | 版本范围、厂商后缀、未知分支、最低语言要求等证据不足 |
| `vendor_attested` | 用户提交了逐条厂商回补声明，允许门禁接受该声明，但报告保留来源与声明性质 |
| `not_affected` | 仅本条版本规则未命中，不代表整个资产安全 |

| 退出码 | 含义 | CI 处理 |
|---|---|---|
| 0 | `pass_scoped`：已提供证据未触发当前阈值，无阻塞缺口 | 在明确范围内通过 |
| 1 | `fail`：命中 `--fail-on` 阈值及以上的风险 | 阻断 |
| 2 | `incomplete`：缺失证据、扫描不完整、未知版本、过期规则或输入/输出错误 | 阻断并补证据，不当作通过 |

同时存在风险和缺口时，退出 2，报告仍保留全部风险发现。默认阈值 `high`；medium/low 仍写入报告，若要一并阻断使用 `--fail-on medium` 或 `low`。

优先级与公告严重度独立保存。Go/Rust 公告未打分项保留 `advisory_severity=unscored`，本工具策略优先级为 high；LiteLLM 是 incident，策略优先级为 critical。Tomcat 的 Important 映射至 high 策略优先级。没有将所有风险数字相加制造总风险分数。

已提供 GitLab job 示例 `examples/gitlab-ci.yml`。其他 CI 也直接使用退出码；配置在任务失败时仍上传报告。示例依赖可信 runner 预装 Python，不在任务中安装目标依赖。若使用独立资产清单模式，在 job 中加 `--inventory-only`。

## 规则维护与运行边界

- 规则库默认超过 30 天就视为证据过期，退出 2。先复核官方公告、范围及新版本，再更新 `verified_at`、`revision` 和边界测试。只改时间戳不能算维护。
- `--as-of 2026-10-22` 用于复现示例或固定基准测试；真实 CI 通常不要设置，否则会冻结时效检查。
- `--rules` 可指向审核后的本地 JSON，工具不联网自动下载或更新规则。
- 本次报告覆盖 Node 的 10 条、PHP 2 条、nginx 5 条、Tomcat 1 条、Go 1 条、Rust 3 条及 LiteLLM 事件 1 条。Node 自带证书更新随相应运行时版本体现；**不检查系统、自定义 CA 文件内容或实际 TLS 阻断效果**。
- 不导入目标模块，不执行 PHP/Node/Python 项目，不调用 pip、npm、Docker 或目标二进制，不读 `.env` 和凭据配置，不输出配置原文。HTML 转义输入、禁用脚本、无外部资源。命令行报告移除终端控制字符。
- 默认单文件 8 MiB、文件与目录各最多遍历 30,000 个、目录深度 32。不跟随符号链接。默认跳过 `.git`、`node_modules`、Rust `target` 等目录，具体清单随报告输出；`.venv` 不默认排除，因此可以静态查看其中 LiteLLM 安装元数据。
- 它不是抗主动篡改的取证平台；如果宿主系统或解释器本身不可信，应从干净系统对只读导出副本检查。未发现线索不证明没有入侵。

## 测试

```sh
python3 -I -S -m unittest discover -s tests -v
```

测试使用临时目录和合成资产，覆盖修复边界、预发布/厂商版本、历史暴露、配置线索、XML 实体、HTML 转义、符号链接、坏文件和 CI 门禁，不连接外网。
