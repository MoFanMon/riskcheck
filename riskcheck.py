#!/usr/bin/env python3
"""Offline October-2026 advisory checks. Python 3.9+, standard library only.

No network, target imports, package managers, subprocesses, or exploit payloads.
Run with a trusted interpreter: python3 -I -S riskcheck.py --root TARGET.
"""

import argparse
import collections
import datetime as dt
import html
import json
import os
import re
import shlex
import stat
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

__version__ = "0.1.0"
DEFAULT_RULES = None
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
KINDS = {"runtime", "installed", "locked", "declared", "historical", "minimum"}
COMPONENTS = {
    "node",
    "php",
    "nginx",
    "tomcat",
    "go",
    "litellm",
    "rustls-webpki",
    "webpki-roots",
    "webpki-root-certs",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    "target",
    ".tox",
    ".ruff_cache",
}
NOT_ASSESSED = [
    "漏洞实际可利用性、网络可达性及是否已被入侵",
    "运行中进程、容器和远程主机的自动资产发现",
    "系统或自定义 CA 包的内容、实际 TLS 握手与浏览器阻断状态",
    "这些事件之外的 CVE、完整恶意代码取证和未提供的历史记录",
]
STATUS_TEXT = {
    "affected": "受影响版本命中",
    "not_affected": "该条版本规则未命中",
    "unknown": "证据不足，待核实",
    "vendor_attested": "用户提交厂商回补声明",
    "artifact_match": "已知恶意制品摘要命中",
    "exposure": "历史安装/执行暴露记录",
}


def https_url(value):
    if not isinstance(value, str):
        return False
    p = urlsplit(value)
    return p.scheme == "https" and bool(p.hostname) and not p.username and not p.password


def load_rules(path=DEFAULT_RULES):
    if path is None:
        adjacent = Path(__file__).resolve().parent / "riskcheck_data" / "rules.json"
        if adjacent.is_file():
            text = adjacent.read_text(encoding="utf-8")
        else:
            # Zipapps have no filesystem directory for their embedded data.
            from importlib.resources import files

            text = files("riskcheck_data").joinpath("rules.json").read_text(encoding="utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("不支持的规则库 schema_version")
    if not isinstance(data.get("rules"), list) or not data["rules"]:
        raise ValueError("规则库不能为空")
    dt.date.fromisoformat(data["verified_at"])
    ids = set()
    for rule in data["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("规则条目需要对象")
        if rule["id"] in ids or rule["component"] not in COMPONENTS:
            raise ValueError("规则 ID 重复或组件不受支持")
        ids.add(rule["id"])
        if not https_url(data["sources"][rule["component"]]):
            raise ValueError("规则来源必须为有效 HTTPS 链接")
        if rule.get("priority", rule["severity"]) not in RANK:
            raise ValueError("规则缺少有效策略优先级")
        if rule["component"] not in data["policies"]:
            raise ValueError("规则缺少版本策略")
    return data


def version(value):
    """Parse exact upstream versions only; distribution revisions stay unknown."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(
        r"(?:v|go)?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value.strip()
    )
    if not m:
        return None
    return tuple(int(x) for x in m.group(1, 2, 3)), m.group(4)


def version_status(asset, rule, database):
    component = rule["component"]
    policy = database["policies"][component]
    parsed = version(asset.get("version"))
    if policy["strategy"] == "supply_chain":
        if asset.get("digest") in policy["bad_digests"]:
            return "artifact_match", "完整摘要与官方列出的恶意镜像匹配；执行情况需另核实。"
        if parsed and parsed == ((1, 107, 0), None):
            state = (
                "exposure"
                if asset.get("kind") in {"historical", "installed"}
                and asset.get("context", {}).get("executed") is True
                else "affected"
            )
            return state, "命中事件版本；版本声明本身不能证明恶意制品已安装或执行。"
        if parsed and parsed[1] is None:
            return "not_affected", "仅未命中本次 1.107.0 投毒规则；不能排除历史暴露或其他漏洞。"
        return "unknown", "浮动标签、版本范围或未知制品需要补充实际版本、完整摘要和历史记录。"
    if asset.get("kind") == "minimum":
        return (
            "unknown",
            "go.mod 的 go 指令是最低语言版本，不是实际编译器版本。请提供产物构建版本。",
        )
    if parsed is None:
        return "unknown", "需要精确上游版本；版本范围、浮动标签和别名不能放行。"
    nums, pre = parsed
    strategy = policy["strategy"]
    if strategy == "webpki":
        if nums > (0, 104, 0):
            return "unknown", "超出已核实分支，需更新规则。"
        if pre:
            m = re.fullmatch(r"alpha\.(\d+)", pre)
            if nums == (0, 104, 0) and m:
                return (
                    "not_affected" if int(m[1]) >= 8 else "affected"
                ), "按 RustSec 0.104.0-alpha.8 边界比较。"
            return "unknown", "未核实的预发布或厂商版本。"
        return (
            "not_affected" if nums >= (0, 103, 16) else "affected"
        ), "按 RustSec 稳定分支 0.103.16 边界比较。"
    if pre:
        return "unknown", "预发布和厂商包后缀不能直接按上游正式版判定；请补充相应安全公告。"
    if strategy == "roots":
        if nums == (0, 26, 11):
            return "unknown", "兼容包装层：必须核实实际依赖边解析到 1.0.10+；本工具不推断依赖图。"
        if nums[0] > 1:
            return "unknown", "超出已核实主分支，需更新规则。"
        return (
            "not_affected" if nums >= (1, 0, 10) else "affected"
        ), "按实际根证书包 1.0.10 边界比较。"
    if strategy == "branches":
        branch = ".".join(str(n) for n in nums[: policy["branch_parts"]])
        if branch not in policy["branches"]:
            return "unknown", "分支已停止支持或不在本规则核实范围；不据此判定安全。"
        if "branches" in rule and branch not in rule["branches"]:
            return "not_affected", "官方公告未将此受支持分支列为该漏洞受影响分支。"
        fixed = policy["branches"][branch]
        return (
            "not_affected" if nums >= version(fixed)[0] else "affected"
        ), "受支持分支的修复边界为 " + fixed + "。"
    if strategy == "ranges":
        if nums > version(policy["ceiling"])[0]:
            return "unknown", "超出已核实版本分支，需更新规则。"
        for branch, fixed in policy.get("fixes", {}).items():
            if ".".join(str(n) for n in nums[:2]) == branch and nums >= version(fixed)[0]:
                return "not_affected", "该分支已达到修复版本 " + fixed + "。"
        matched = any(version(low)[0] <= nums < version(high)[0] for low, high in rule["ranges"])
        return (
            "affected" if matched else "not_affected"
        ), "按官方受影响区间比较；配置和可利用性另行核实。"
    raise ValueError("不支持的版本策略")


def assess_asset(asset, database=None):
    database = database or load_rules()
    results = []
    for rule in database["rules"]:
        if rule["component"] != asset["component"]:
            continue
        status, detail = version_status(asset, rule, database)
        confidence = "version_match" if status == "affected" else "version_check"
        if status == "artifact_match":
            confidence = "digest_match"
        elif status == "exposure":
            confidence = "user_attested"
        for attestation in asset.get("vendor_fixes", []):
            # Supply-chain exposure cannot be waived by an upgrade/backport assertion.
            if (
                rule["component"] != "litellm"
                and attestation.get("rule_id") == rule["id"]
                and https_url(attestation.get("reference"))
            ):
                status, confidence = "vendor_attested", "user_attested"
                detail = "用户提交逐条厂商回补声明；工具未联网验证或独立验证包内容。"
        context = asset.get("context", {}).get(rule["condition"])
        reachability = (
            "user_reports_present"
            if context is True
            else "user_reports_absent"
            if context is False
            else "not_assessed"
        )
        results.append(
            {
                "rule_id": rule["id"],
                "asset_id": asset.get("id", "asset"),
                "component": asset["component"],
                "version": asset.get("version", "unknown"),
                "kind": asset.get("kind", "runtime"),
                "status": status,
                "confidence": confidence,
                "advisory_severity": rule["severity"],
                "priority": rule.get("priority", rule["severity"]),
                "title": rule["title"],
                "detail": detail,
                "reachability": reachability,
                "precondition": rule["precondition"],
                "action": rule["action"],
                "source": database["sources"][rule["component"]],
                "evidence": asset.get("evidence", {"file": "inventory", "line": None}),
                "vendor_references": [
                    a["reference"]
                    for a in asset.get("vendor_fixes", [])
                    if a.get("rule_id") == rule["id"] and https_url(a.get("reference"))
                ],
            }
        )
    return results


def safe_read(path, root, max_bytes):
    """Refuse symlinks and special files; bound reads even if a file grows."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("符号链接文件不读取")
    resolved_root = root.resolve()
    if resolved_root not in path.resolve().parents and path.resolve() != resolved_root:
        raise ValueError("文件路径超出扫描根目录")
    fd = os.open(
        str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("不是普通文件")
        if st.st_size > max_bytes:
            raise ValueError("文件超过读取上限")
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("文件超过读取上限")
    return raw.decode("utf-8-sig", errors="strict")


def read_inventory(path, max_bytes):
    doc = json.loads(safe_read(path, Path(path).absolute().parent, max_bytes))
    if (
        not isinstance(doc, dict)
        or doc.get("schema_version") != 1
        or not isinstance(doc.get("assets"), list)
    ):
        raise ValueError("资产清单需要 schema_version:1 和 assets 数组")
    assets, ids = [], set()
    for raw in doc["assets"]:
        if not isinstance(raw, dict) or raw.get("component") not in COMPONENTS:
            raise ValueError("资产必须包含受支持的 component")
        asset = dict(raw)
        if not isinstance(asset.get("id"), str) or not asset["id"] or asset["id"] in ids:
            raise ValueError("资产 id 必须为非空且唯一的字符串")
        ids.add(asset["id"])
        asset.setdefault("version", "unknown")
        asset.setdefault("kind", "runtime")
        asset.setdefault("context", {})
        if (
            not isinstance(asset["version"], str)
            or asset["kind"] not in KINDS
            or not isinstance(asset["context"], dict)
        ):
            raise ValueError("资产 version/kind/context 类型或取值错误")
        if any(type(v) is not bool for v in asset["context"].values()):
            raise ValueError("context 值必须为布尔值")
        fixes = asset.get("vendor_fixes", [])
        if not isinstance(fixes, list) or any(
            not isinstance(a, dict)
            or not isinstance(a.get("rule_id"), str)
            or not https_url(a.get("reference"))
            for a in fixes
        ):
            raise ValueError("vendor_fixes 需要逐条 rule_id 和 HTTPS 安全公告")
        asset["evidence"] = {"file": "inventory:" + Path(path).name, "line": None}
        # Do not echo arbitrary user fields or context values into public reports.
        assets.append(
            {k: asset[k] for k in ("id", "component", "version", "kind", "context", "evidence")}
            | {k: asset[k] for k in ("vendor_fixes", "digest") if k in asset}
        )
    required = doc.get("required_components", [])
    if not isinstance(required, list) or any(x not in COMPONENTS for x in required):
        raise ValueError("required_components 包含未知组件")
    return assets, required


def is_candidate(path):
    name = path.name
    return (
        name
        in {
            ".nvmrc",
            ".node-version",
            "package.json",
            "go.mod",
            "Cargo.lock",
            "poetry.lock",
            "uv.lock",
            "server.xml",
            "cook.pth",
            "cook.py",
            "sitecustomize.py",
            ".pc_once_72129118c59f5636c0bb",
            "remote_code_loader.lock",
        }
        or name.startswith("Dockerfile")
        or (name.startswith("requirements") and name.endswith(".txt"))
        or name == "nginx.conf"
        or (name.endswith(".conf") and any("nginx" in p.lower() for p in path.parts))
        or (
            name == "METADATA"
            and path.parent.name.endswith(".dist-info")
            and path.parent.name.lower().startswith("litellm-")
        )
    )


def collect_file(path, text, rel, assets, signals, gaps):
    def add(component, value, kind, line, **extras):
        assets.append(
            dict(
                id=rel + ":" + str(line) + ":" + component,
                component=component,
                version=value,
                kind=kind,
                context={},
                evidence={"file": rel, "line": line},
                **extras,
            )
        )

    def signal(component, feature, line, detail):
        signals.append(
            {
                "component": component,
                "feature": feature,
                "confidence": "static_hint",
                "evidence": {"file": rel, "line": line},
                "detail": detail,
            }
        )

    name = path.name
    if name in {".nvmrc", ".node-version"}:
        add("node", text.strip(), "declared", 1)
    elif name == "package.json":
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise ValueError("package.json 顶层需要对象")
        engines = doc.get("engines", {})
        if not isinstance(engines, dict):
            raise ValueError("engines 需要对象")
        if "node" in engines:
            add("node", str(engines["node"]), "declared", 1)
        dependencies = {}
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            value = doc.get(field, {})
            if not isinstance(value, dict):
                raise ValueError(field + " 需要对象")
            dependencies.update(value)
        if "body-parser" in dependencies or "express" in dependencies:
            signal(
                "node",
                "request_body_middleware",
                1,
                "声明了请求处理中间件；需核实版本、inflate 配置与 Brotli 路径。",
            )
    elif name == "go.mod":
        m = re.search(r"(?m)^\s*go\s+(\S+)", text)
        if m:
            add("go", m.group(1), "minimum", text[: m.start()].count("\n") + 1)
        else:
            gaps.append({"file": rel, "reason": "缺少 go 指令；实际编译器版本仍需资产清单。"})
    elif name in {"Cargo.lock", "poetry.lock", "uv.lock"}:
        # Deliberately parse only canonical package name/version fields, never TOML expressions.
        if "[[package]]" not in text:
            raise ValueError("未识别标准 [[package]] 锁文件；不作空结果放行")
        for m in re.finditer(r"(?ms)^\[\[package\]\]\s*\n(.*?)(?=^\[\[package\]\]|\Z)", text):
            block = m.group(1)
            n = re.search(r'(?m)^name\s*=\s*("[^"\n]*")\s*(?:#.*)?$', block)
            v = re.search(r'(?m)^version\s*=\s*("[^"\n]*")\s*(?:#.*)?$', block)
            if not n:
                gaps.append({"file": rel, "reason": "锁文件条目缺少支持的单行 name 字段。"})
                continue
            component = json.loads(n.group(1))
            if component in COMPONENTS:
                add(
                    component,
                    json.loads(v.group(1)) if v else "unknown",
                    "locked",
                    text[: m.start()].count("\n") + 1,
                )
    elif name.startswith("requirements") and name.endswith(".txt"):
        for number, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--requirement", "-c", "--constraint", "-e", "--editable")):
                gaps.append(
                    {
                        "file": rel,
                        "line": number,
                        "reason": "外部引用/可编辑依赖未展开；请提供解析后的锁文件或扫描引用目录。",
                    }
                )
                continue
            m = re.match(r"(?i)^litellm(?![A-Za-z0-9._-])(?:\[[^\]]*\])?(.*)$", line)
            if m:
                exact = re.fullmatch(
                    r"==([0-9]+\.[0-9]+\.[0-9]+)(?:\s+--hash=\S+)*\s*(?:#.*)?", m.group(1).strip()
                )
                add(
                    "litellm",
                    exact.group(1) if exact else "unresolved",
                    "locked" if exact else "declared",
                    number,
                )
    elif name == "METADATA":
        n = re.search(r"(?im)^Name:\s*(\S+)\s*$", text)
        v = re.search(r"(?im)^Version:\s*(\S+)\s*$", text)
        if not n or not v:
            raise ValueError("安装元数据缺少 Name/Version")
        if n.group(1).lower() == "litellm":
            add("litellm", v.group(1), "installed", 1)
    elif name.startswith("Dockerfile"):
        for number, line in enumerate(text.splitlines(), 1):
            if not re.match(r"(?i)^\s*FROM\s", line):
                continue
            tokens = shlex.split(line, comments=True)
            if not tokens or tokens[0].upper() != "FROM":
                continue
            tokens = [t for t in tokens[1:] if not t.startswith("--")]
            if not tokens:
                raise ValueError("FROM 缺少镜像名")
            image = tokens[0]
            if "$" in image:
                gaps.append(
                    {
                        "file": rel,
                        "line": number,
                        "reason": "FROM 包含变量；需要补充构建时解析后的镜像版本/摘要。",
                    }
                )
                continue
            base, _, digest = image.partition("@")
            image_name, sep, tag = base.rpartition(":")
            if not sep or "/" in tag:
                image_name, tag = base, "latest"
            normalized = re.sub(r"^(?:docker\.io/)?library/", "", image_name)
            normalized = re.sub(r"^docker\.io/", "", normalized)
            component = normalized if normalized in {"node", "php", "nginx", "tomcat"} else None
            if normalized == "golang":
                component = "go"
            if normalized in {
                "litellm/litellm",
                "berriai/litellm",
                "ghcr.io/berriai/litellm",
                "ghcr.io/berriai/litellm-database",
                "ghcr.io/berriai/litellm-non_root",
            }:
                component = "litellm"
            if component:
                m = re.match(
                    r"^v?(\d+\.\d+\.\d+)(?=$|-(?:alpine|bookworm|bullseye|slim|fpm|cli|apache|trixie|jdk|jre|temurin))",
                    tag,
                )
                add(component, m.group(1) if m else tag, "declared", number, digest=digest or "")
    elif name == "server.xml":
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
            raise ValueError("拒绝 XML DTD/实体声明")
        doc = ET.fromstring(text)
        for realm in doc.iter():
            if realm.tag.rsplit("}", 1)[-1] == "Realm" and realm.get("className", "").endswith(
                "JNDIRealm"
            ):
                signal(
                    "tomcat", "tomcat_jndi_realm", 1, "发现 JNDIRealm；未展开外部配置或运行态覆盖。"
                )
                auth = realm.get("authentication", "").upper()
                if auth and auth not in {"SIMPLE", "NONE", "GSSAPI"}:
                    signal(
                        "tomcat",
                        "tomcat_non_gssapi_sasl",
                        1,
                        "发现疑似非 GSSAPI SASL 配置；需人工核对有效机制。",
                    )
    elif name in {"sitecustomize.py", "cook.py", "cook.pth"}:
        signal(
            "litellm",
            "python_startup_file",
            1,
            "需人工检查的文件名线索；合法软件也可能使用该名称，不能单独认定入侵。",
        )
    elif name in {".pc_once_72129118c59f5636c0bb", "remote_code_loader.lock"}:
        signal(
            "litellm",
            "litellm_execution_marker",
            1,
            "发现公开事件的执行标记文件名；需结合来源和取证核实，缺失也不能排除历史暴露。",
        )
    else:
        features = {}
        for number, line in enumerate(text.splitlines(), 1):
            # shlex respects quoted '#' so comments cannot manufacture configuration evidence.
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";{}")
            lexer.whitespace_split = True
            tokens = list(lexer)
            for index, token in enumerate(tokens):
                if index == 0 or tokens[index - 1] in {";", "{"}:
                    args = tokens[index + 1 :]
                    if token in {"alias", "rewrite", "aio", "ssi", "ssl_session_ticket_key"}:
                        if token not in {"aio", "ssi"} or (args and args[0] != "off"):
                            features[token] = number
                    if token == "listen" and any(t in {"quic", "http3"} for t in args):
                        features["http3"] = number
                    if token in {"root", "alias", "access_log", "log_format"} and any(
                        "$" in t for t in args
                    ):
                        features["variable_expression"] = number
                    if token == "include":
                        gaps.append(
                            {
                                "file": rel,
                                "line": number,
                                "reason": "nginx include 未验证展开与生效关系；静态配置不能证明完整触发条件。",
                            }
                        )
        combinations = [
            ("nginx_alias_rewrite", {"alias", "rewrite"}),
            ("nginx_aio_ssi", {"aio", "ssi"}),
            ("nginx_http3", {"http3"}),
            ("nginx_session_ticket_rotation", {"ssl_session_ticket_key"}),
            ("nginx_variable_expression", {"variable_expression"}),
        ]
        for feature, required in combinations:
            if required <= features.keys():
                signal(
                    "nginx",
                    feature,
                    min(features[x] for x in required),
                    "文件内静态配置线索；未证明作用域、构建模块、继承关系或实际可达。",
                )


def scan(
    root,
    inventory=None,
    required=None,
    rules_path=DEFAULT_RULES,
    as_of=None,
    rules_age_days=30,
    max_bytes=8 * 1024 * 1024,
    max_files=30000,
    inventory_only=False,
):
    database = load_rules(rules_path)
    today = dt.date.fromisoformat(as_of) if as_of else dt.datetime.now(dt.timezone.utc).date()
    root = Path(root).absolute()
    report = {
        "schema_version": 1,
        "tool_version": __version__,
        "rules_revision": database["revision"],
        "rules_verified_at": database["verified_at"],
        "as_of": today.isoformat(),
        "assets": [],
        "findings": [],
        "signals": [],
        "gaps": [],
        "not_assessed": NOT_ASSESSED,
        "coverage": {
            "visited_files": 0,
            "visited_directories": 0,
            "read_files": 0,
            "mode": "inventory_only" if inventory_only else "directory_and_inventory",
            "skipped_directories": sorted(SKIP_DIRS),
            "scope": "仅扫描所给目录与清单中的本次事件规则",
        },
    }
    assets, gaps, signals = report["assets"], report["gaps"], report["signals"]
    age = (today - dt.date.fromisoformat(database["verified_at"])).days
    if age > rules_age_days or age < -1:
        gaps.append({"file": "rules", "reason": "规则核实时间已过期或在未来；需重新核对官方来源。"})
    required = set(required or [])
    if inventory:
        try:
            supplied, expected = read_inventory(Path(inventory).absolute(), max_bytes)
            assets.extend(supplied)
            required.update(expected)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            gaps.append(
                {
                    "file": "inventory",
                    "reason": "资产清单读取失败："
                    + type(exc).__name__
                    + "；请核对 schema、字段和权限。",
                }
            )
    if inventory_only:
        if not inventory:
            gaps.append({"file": "inventory", "reason": "仅清单模式必须提供 --inventory。"})
    elif not root.is_dir() or root.is_symlink():
        gaps.append({"file": ".", "reason": "扫描根目录不存在、不是目录或为符号链接。"})
    else:

        def walk_error(exc):
            gaps.append({"file": "directory", "reason": "目录无法遍历：" + type(exc).__name__})

        exhausted = False
        for current, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            report["coverage"]["visited_directories"] += 1
            if report["coverage"]["visited_directories"] > max_files:
                gaps.append({"file": ".", "reason": "超过目录数量上限，扫描不完整。"})
                break
            dirs.sort()
            files.sort()
            kept = []
            for name in dirs:
                child = Path(current) / name
                if name in SKIP_DIRS:
                    continue
                if child.is_symlink():
                    gaps.append(
                        {
                            "file": str(child.relative_to(root)),
                            "reason": "符号链接目录未展开；如需检查请提供真实目录。",
                        }
                    )
                elif len(child.relative_to(root).parts) > 32:
                    gaps.append(
                        {"file": str(child.relative_to(root)), "reason": "超过最大目录深度 32。"}
                    )
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in files:
                report["coverage"]["visited_files"] += 1
                if report["coverage"]["visited_files"] > max_files:
                    gaps.append({"file": ".", "reason": "超过文件数量上限，扫描不完整。"})
                    exhausted = True
                    break
                path = Path(current) / name
                if not is_candidate(path):
                    continue
                rel = str(path.relative_to(root))
                try:
                    text = safe_read(path, root, max_bytes)
                    report["coverage"]["read_files"] += 1
                    collect_file(path, text, rel, assets, signals, gaps)
                except (OSError, ValueError, TypeError, KeyError, ET.ParseError) as exc:
                    # Never include exception text: decoders/parsers may echo source secrets.
                    gaps.append(
                        {
                            "file": rel,
                            "reason": "无法完整读取或解析（链接/大小/格式/编码/权限）："
                            + type(exc).__name__,
                        }
                    )
            if exhausted:
                break
    if not assets:
        gaps.append({"file": ".", "reason": "没有获得支持组件的版本证据；空扫描不能表示通过。"})
    present = {a["component"] for a in assets}
    for component in sorted(required - present):
        gaps.append({"file": "inventory", "reason": "缺少要求检查的组件：" + component})
    for asset in assets:
        assessed = assess_asset(asset, database)
        if not assessed:
            gaps.append(
                {
                    "file": asset["evidence"]["file"],
                    "reason": "规则库没有覆盖已发现组件：" + asset["component"],
                }
            )
        report["findings"].extend(assessed)
    report["findings"].sort(
        key=lambda f: (-RANK[f["priority"]], f["component"], f["asset_id"], f["rule_id"])
    )
    report["summary"] = summarize(report)
    return report


def exit_code(report, fail_on="high"):
    if report["gaps"] or any(f["status"] == "unknown" for f in report["findings"]):
        return 2
    if any(
        f["status"] in {"affected", "artifact_match", "exposure"}
        and RANK[f["priority"]] >= RANK[fail_on]
        for f in report["findings"]
    ):
        return 1
    # Named execution marker clues warrant review even without a collected package version.
    if any(s["feature"] == "litellm_execution_marker" for s in report["signals"]):
        return 2
    return 0


def summarize(report, fail_on="high"):
    code = exit_code(report, fail_on)
    return {
        "gate": {0: "pass_scoped", 1: "fail", 2: "incomplete"}[code],
        "exit_code": code,
        "threshold": fail_on,
        "assets": len(report["assets"]),
        "by_status": dict(collections.Counter(f["status"] for f in report["findings"])),
        "signals": len(report["signals"]),
        "gaps": len(report["gaps"]),
        "meaning": "通过只表示给定证据未触发本次已核实规则的门禁；不是系统安全证明。",
    }


def render_text(report):
    summary = report["summary"]
    lines = [
        "RiskCheck | 离线事件风险检查",
        "规则 " + report["rules_revision"] + "；核实日期 " + report["rules_verified_at"],
        "门禁：" + summary["gate"] + "；退出码 " + str(summary["exit_code"]),
        summary["meaning"],
    ]
    for f in report["findings"]:
        if f["status"] == "not_affected":
            continue
        lines.extend(
            [
                "",
                "["
                + f["priority"].upper()
                + "] "
                + f["rule_id"]
                + " | "
                + STATUS_TEXT[f["status"]],
                "  "
                + f["asset_id"]
                + " | "
                + f["component"]
                + " "
                + f["version"]
                + " | "
                + f["kind"],
                "  " + f["detail"],
                "  建议：" + f["action"],
                "  来源：" + f["source"],
            ]
        )
    for gap in report["gaps"]:
        lines.append("待核实：" + gap["file"] + "：" + gap["reason"])
    for signal in report["signals"]:
        lines.append(
            "静态线索："
            + signal["feature"]
            + " @ "
            + signal["evidence"]["file"]
            + "；"
            + signal["detail"]
        )
    lines.extend(["", "未检测："] + ["- " + x for x in report["not_assessed"]])
    # Strip control characters in terminal-facing data from untrusted filenames/IDs.
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", "\n".join(lines)) + "\n"


def render_html(report):
    def esc(value):
        return html.escape(str(value), quote=True)

    rows = []
    for f in report["findings"]:
        cls = (
            "warn"
            if f["status"] == "unknown"
            else "bad"
            if f["status"] in {"affected", "exposure", "artifact_match"}
            else "quiet"
        )
        rows.append(
            '<tr class="'
            + cls
            + '"><td>'
            + esc(f["priority"])
            + "<br>"
            + esc(STATUS_TEXT[f["status"]])
            + "</td><td>"
            + esc(f["component"])
            + " "
            + esc(f["version"])
            + "<br>"
            + esc(f["asset_id"])
            + "<br>"
            + esc(f["kind"])
            + "</td><td>"
            + esc(f["rule_id"])
            + "<br>"
            + esc(f["title"])
            + '<br><a rel="noreferrer" href="'
            + esc(f["source"])
            + '">官方来源</a></td><td>'
            + esc(f["detail"])
            + "<br>触发前提："
            + esc(f["precondition"])
            + "<br>场景证据："
            + esc(f["reachability"])
            + "<br>建议："
            + esc(f["action"])
            + "</td></tr>"
        )
    notes = "".join(
        "<li>" + esc(g["file"]) + "：" + esc(g["reason"]) + "</li>" for g in report["gaps"]
    )
    hints = "".join(
        "<li>"
        + esc(s["feature"])
        + " · "
        + esc(s["evidence"]["file"])
        + "："
        + esc(s["detail"])
        + "</li>"
        for s in report["signals"]
    )
    return (
        '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        + "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        + "<title>RiskCheck 离线检查报告</title><style>body{font:15px/1.7 system-ui,sans-serif;color:#172436;background:#f5f7fa;margin:0}"
        + "main{max-width:1280px;margin:auto;padding:32px}h1{font-size:30px}p{max-width:90ch}.table{overflow:auto}table{border-collapse:collapse;background:white;width:100%}"
        + "td,th{border:1px solid #dce3ec;padding:14px;text-align:left;vertical-align:top;overflow-wrap:anywhere}td:first-child{min-width:125px}"
        + ".bad td:first-child{border-left:5px solid #b42332}.warn td:first-child{border-left:5px solid #b96900}.quiet{color:#475569}a{color:#1750a5}"
        + "small{color:#526074}li{margin:8px 0}.pill{display:inline-block;background:#e5eaf1;padding:6px 14px;border-radius:20px}</style><main>"
        + '<h1>RiskCheck · 离线事件风险检查</h1><p class="pill">门禁：'
        + esc(report["summary"]["gate"])
        + " · 退出码 "
        + esc(report["summary"]["exit_code"])
        + "</p>"
        + "<p>"
        + esc(report["summary"]["meaning"])
        + "</p><p><small>规则 "
        + esc(report["rules_revision"])
        + " · 核实日期 "
        + esc(report["rules_verified_at"])
        + " · 资产 "
        + esc(len(report["assets"]))
        + " · 读取文件 "
        + esc(report["coverage"]["read_files"])
        + "</small></p>"
        + '<div class="table"><table><thead><tr><th>优先级 / 结论</th><th>资产 / 证据类型</th><th>规则</th><th>依据与处理</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div><h2>待核实与扫描缺口</h2><ul>"
        + notes
        + "</ul><h2>静态线索</h2><ul>"
        + hints
        + "</ul><h2>未检测范围</h2><ul>"
        + "".join("<li>" + esc(n) + "</li>" for n in report["not_assessed"])
        + "</ul></main></html>"
    )


def main(argv=None):
    # Reports use UTF-8 on terminals and pipes, including legacy Windows locales.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(
        description="离线版本、依赖和配置检查；不运行目标代码，不连接网络。"
    )
    parser.add_argument("--version", action="version", version="riskcheck-offline " + __version__)
    parser.add_argument("--root", type=Path, required=True, help="项目、导出文件系统或挂载目录")
    parser.add_argument("--inventory", type=Path, help="schema_version=1 的资产 JSON 清单")
    parser.add_argument(
        "--inventory-only", action="store_true", help="只检查显式资产清单，不遍历目标目录"
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        choices=sorted(COMPONENTS),
        help="要求提供的组件，可重复",
    )
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--format", choices=["text", "json", "html"], default="text")
    parser.add_argument("--output", type=Path, help="仅创建新报告；存在时拒绝覆盖")
    parser.add_argument("--fail-on", choices=list(RANK), default="high")
    parser.add_argument("--as-of", help="仅供复现的 ISO 日期；CI 通常不设置，以自动检查规则时效")
    parser.add_argument("--rules-max-age", type=int, default=30)
    parser.add_argument("--max-files", type=int, default=30000)
    parser.add_argument("--max-file-bytes", type=int, default=8 * 1024 * 1024)
    args = parser.parse_args(argv)
    if min(args.rules_max_age, args.max_files, args.max_file_bytes) < 1:
        parser.error("上限参数必须为正整数")
    try:
        report = scan(
            args.root,
            inventory=args.inventory,
            required=args.require,
            rules_path=args.rules,
            as_of=args.as_of,
            rules_age_days=args.rules_max_age,
            inventory_only=args.inventory_only,
            max_files=args.max_files,
            max_bytes=args.max_file_bytes,
        )
        report["summary"] = summarize(report, args.fail_on)
        rendered = (
            json.dumps(report, ensure_ascii=False, indent=2) + "\n"
            if args.format == "json"
            else render_html(report)
            if args.format == "html"
            else render_text(report)
        )
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        else:
            sys.stdout.write(rendered)
        return report["summary"]["exit_code"]
    except (OSError, ValueError, TypeError, KeyError, ImportError) as exc:
        # No parser content, local environment values, or source snippets in errors.
        sys.stderr.write(
            "检查失败："
            + type(exc).__name__
            + "；请核对规则、日期、输入路径和输出文件是否已存在。\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
