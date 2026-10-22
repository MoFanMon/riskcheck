# 开发、测试与发布

## 开发环境

在可信解释器上从仓库根目录执行：

```sh
python3 -I -m venv .venv
.venv/bin/python -I -m pip install -r requirements-dev.txt
.venv/bin/python -I -S -m unittest discover -s tests -v
.venv/bin/python -I -m ruff check .
.venv/bin/python -I -m ruff format --check .
```

Windows 用 `.venv\Scripts\python.exe`。扫描器运行不依赖这些开发工具；它们只用于构建和检查。根目录模块由 pyproject 显式声明，版本读取 riskcheck.py 的字面量 `__version__`。

## 构建下载包

```sh
.venv/bin/python -I -m build --no-isolation
.venv/bin/python -I -S tools/build_release.py --output dist
```

构建结果：wheel、标准源码 tar.gz、源码 ZIP、便携 pyz 与 SHA256SUMS。ZIP 固定条目时间并按名称排序；压缩器或 Python 版本不同仍可能改变最终字节，不宣称所有平台之间完全可复现。

源码 ZIP 使用公开文件允许列表，排除 .git、.env 和运行报告。规则不从网络获取。检查 wheel 的包内数据和下载文件摘要，再在空目录执行便携版及安装后的 wheel；不能只测试源码 checkout。

## CI

仓库 CI 在 Linux 的 Python 3.9/3.12/3.14、Windows 和 macOS 的 3.12 运行测试；Linux 另做 lint、构建、wheel 安装和 Docker 构建/运行检查。普通 job 只申请 contents:read，第三方 Action 固定完整提交号。

测试只使用合成数据，固定 `--as-of` 复现快照。真实使用者不应照搬固定日期作为长期门禁配置。

## 发布

1. 更新 __version__、CHANGELOG、下载链接和发行说明；如修改规则，再独立更新 revision 和核实日期。
2. 跑全部测试、lint、格式检查、构建与安装验证；核对公开材料不含资产、凭据或私人路径。
3. 合并到 main，确认 CI；创建与工具版本一致的 vX.Y.Z 标签。
4. 在 GitHub Releases 添加发行说明、wheel、tar.gz、源码 ZIP、pyz 和 SHA256SUMS。
5. 可在 Actions 手动运行 Release 工作流，用现有标签重建并上传下载包；写权限仅授予发布 job。不自动向 PyPI、GHCR 或其他平台发布。
6. 从未登录环境检查公开源码和 Release 下载链接，校验附件摘要。

`.github/workflows/release.yml` 接受严格的 v数字.数字.数字 标签，检出标签后构建、测试并向对应 Release 上传。操作者必须审核并有权发布该标签代码。
