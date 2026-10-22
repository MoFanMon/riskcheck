# RiskCheck

[中文说明](README.md) · [Releases](https://github.com/MoFanMon/riskcheck/releases/latest)

An offline advisory checker for operations and CI. RiskCheck reads project files and explicit asset inventories without network access, executing target code, or installing target dependencies. It requires Python 3.9+ and only its standard library.

Version 0.1.0 includes 23 targeted rules verified on 2026-10-22 for Node.js, PHP, nginx, Tomcat, Go, Rust certificate packages, and the LiteLLM incident. This is a dated snapshot, not a live vulnerability database. Rules expire after 30 days by default.

## Download and run

Download `riskcheck-0.1.0.pyz` and `SHA256SUMS` from [Releases](https://github.com/MoFanMon/riskcheck/releases/latest), verify the digest on a trusted machine, then run:

```sh
python3 -I -S riskcheck-0.1.0.pyz --version
python3 -I -S riskcheck-0.1.0.pyz --root /srv/project --inventory assets.json --format json
```

The portable archive embeds its rules. Wheel, source ZIP, and source tarball downloads are also provided. This project has not been published to PyPI. See [deployment instructions](docs/deployment.md).

| Exit | Meaning |
|---|---|
| 0 | Scoped pass for supplied evidence and configured threshold |
| 1 | Findings meet the risk threshold, high by default |
| 2 | Incomplete evidence, unknown versions, expired rules, or input errors |

Text, JSON, and offline HTML reports distinguish version matches, static hints, user-attested vendor fixes, artifact matches, and historical exposure. A current upgrade does not erase a historical incident record. A scoped pass is not proof of safety or absence of compromise.

From source, run `python3 -I -S riskcheck.py --help`. Tests: `python3 -I -S -m unittest discover -s tests -v`. See the [design notes](docs/design.md), [contributing guide](CONTRIBUTING.md), [security policy](SECURITY.md), and [MIT license](LICENSE).
