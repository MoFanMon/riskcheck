# 下载、部署与升级

这是一次运行后退出的 CLI，不需要数据库、监听端口或系统服务。读取指定目录与资产清单，将报告保存为新文件。

## 下载形式

| 文件 | 场景 |
|---|---|
| `riskcheck-0.1.0.pyz` | 推荐；自带规则，无需安装；需要 Python 3.9+ |
| `riskcheck_offline-0.1.0-py3-none-any.whl` | 在干净工具虚拟环境中离线安装 |
| `riskcheck-0.1.0-source.zip` | 查看代码、源码运行和修改 |
| `riskcheck_offline-0.1.0.tar.gz` | 标准 Python 源码构建，构建时需要 setuptools |

[最新 Release](https://github.com/MoFanMon/riskcheck/releases/latest) · [v0.1.0](https://github.com/MoFanMon/riskcheck/releases/tag/v0.1.0)。GitHub 自动生成的 Source code 包不是 wheel 或 pyz。尚未发布 PyPI 包或 GHCR 镜像。

## Linux / macOS：便携版

在干净目录下载：

```sh
curl -fLO https://github.com/MoFanMon/riskcheck/releases/download/v0.1.0/riskcheck-0.1.0.pyz
curl -fLO https://github.com/MoFanMon/riskcheck/releases/download/v0.1.0/SHA256SUMS
```

Linux 用 `sha256sum riskcheck-0.1.0.pyz`；macOS 用 `shasum -a 256 riskcheck-0.1.0.pyz`。将完整输出与清单中的对应摘要比较。若下载了全部附件，可用 `sha256sum -c SHA256SUMS` 或 `shasum -a 256 -c SHA256SUMS` 批量检查。摘要检测损坏和不一致，不能替代对发布来源的信任。

```sh
python3 -I -S riskcheck-0.1.0.pyz --version
python3 -I -S riskcheck-0.1.0.pyz --root /srv/project --inventory /srv/assets.json --format html --output report.html
```

不需要 root；输出目录需可写，文件必须尚不存在。`-I -S` 隔离搜索路径并禁用 site 初始化，避免加载目标环境的 `.pth` 和 `sitecustomize.py`。解释器本身必须可信，生产部署优先选择仍受供应商安全维护的 Python。

## Windows：PowerShell

从 Release 下载相同文件并比较摘要：

```powershell
Get-FileHash .\riskcheck-0.1.0.pyz -Algorithm SHA256
py -3 -I -S .\riskcheck-0.1.0.pyz --version
py -3 -I -S .\riskcheck-0.1.0.pyz --root C:\apps\project --inventory C:\audit\assets.json --format json --output .\report.json
$LASTEXITCODE
```

## wheel：离线安装

下载并校验 wheel 后，在可信、干净的解释器中创建独立工具环境。不要在疑似 LiteLLM 污染环境里启动 pip。

```sh
python3 -I -m venv .venv-riskcheck
.venv-riskcheck/bin/python -I -m pip install --no-index --no-deps ./riskcheck_offline-0.1.0-py3-none-any.whl
.venv-riskcheck/bin/python -I -m riskcheck --version
.venv-riskcheck/bin/riskcheck --root /srv/project --inventory assets.json
```

Windows 对应路径为 `.venv-riskcheck\Scripts\python.exe` 和 `riskcheck.exe`。安装后的模块需要 site-packages，因此这条方式不使用 `-S`；检查可疑环境时优先在干净系统使用隔离便携版。

卸载：在该干净环境运行 `python -m pip uninstall riskcheck-offline`，或删除独立工具虚拟环境。便携版删除文件即可。

## Docker：只读目标、禁网运行

仓库提供 Dockerfile。构建需取得官方 Python 基础镜像；运行检测时可禁网。仓库 CI 验证容器的构建和只读、禁网运行。

```sh
docker build -t riskcheck:0.1.0 .
mkdir -p reports
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/project:/target:ro" \
  -v "$PWD/assets.json:/inventory/assets.json:ro" \
  -v "$PWD/reports:/reports:rw" \
  riskcheck:0.1.0 --root /target --inventory /inventory/assets.json \
  --format json --output /reports/report.json
```

先准备项目目录、清单和可写报告目录。默认基础镜像为官方 `python:3.12-slim`；生产构建应记录或固定经审核摘要，安全更新后重建。不要挂载宿主根目录、Docker socket 或凭据目录。

## CI、更新与排错

```sh
python3 -I -S riskcheck.py --root . --inventory ci/assets.json --require node --format json --output risk-report.json
```

标准输出、标准错误和报告文件均使用 UTF-8。退出 1 和 2 都应阻断，任务失败时仍保存报告。参考 [GitHub Actions](../examples/github-actions.yml) 与 [GitLab](../examples/gitlab-ci.yml)。扫描离线不代表 CI 的 checkout 和报告上传离线；隔离网络应预分发工具和清单。生产报告包含资产标识、路径，应作为内部资料保存，不提交到本公开仓库。

- 更新工具：下载、校验新 Release，再替换文件；工具版本和规则 revision 分开管理。
- 退出 2：检查 gaps、unknown、日期、权限和实际组件版本；不要仅调大时效取得通过。
- 输出已存在：换文件名或由流水线管理旧报告，工具不覆盖。
- 固定 `--as-of` 只用于复现样例，真实 CI 不固定日期。
- 当前版本已修复仍告警：核对旧副本或历史记录，不直接删除证据。
