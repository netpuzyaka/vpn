import base64
import json
import shutil
import time
from pathlib import Path

import yaml

import config
from .models import Node


def split_nodes(nodes):
    main = [n for n in nodes if n.status != "dead"]
    dead = [n for n in nodes if n.status == "dead"]
    main.sort(key=lambda n: (n.status != "alive", n.latency_ms if n.latency_ms > 0 else 999999))
    dead.sort(key=lambda n: n.latency_ms if n.latency_ms > 0 else 999999)
    return main, dead


def _clash_proxy(n: Node):
    name = n.name or f"{n.host}:{n.port}"
    p = {"name": name, "type": n.proto, "server": n.host, "port": n.port}
    params = n.params

    if n.proto == "vless":
        p.update(
            {
                "uuid": n.identity,
                "network": params.get("type") or "tcp",
            }
        )
        sec = params.get("security")
        if sec == "reality":
            p["tls"] = True
            ro = {}
            if params.get("pbk"):
                ro["public-key"] = params["pbk"]
            if params.get("sid"):
                ro["short-id"] = params["sid"]
            if ro:
                p["reality-opts"] = ro
        elif sec == "tls":
            p["tls"] = True
        if params.get("flow"):
            p["flow"] = params["flow"]
        if params.get("sni"):
            p["servername"] = params["sni"]
        if params.get("fp"):
            p["client-fingerprint"] = params["fp"]
        if p["network"] == "ws":
            ws = {}
            if params.get("path"):
                ws["path"] = params["path"]
            if params.get("host"):
                ws["headers"] = {"Host": params["host"]}
            if ws:
                p["ws-opts"] = ws
        if p["network"] == "grpc" and params.get("serviceName"):
            p["grpc-opts"] = {"grpc-service-name": params["serviceName"]}
        return p

    if n.proto == "vmess":
        p.update(
            {
                "uuid": n.identity,
                "alterId": int(params.get("aid") or 0),
                "cipher": params.get("scy") or "auto",
                "network": params.get("net") or "tcp",
            }
        )
        if params.get("tls"):
            p["tls"] = True
        if params.get("sni"):
            p["servername"] = params["sni"]
        if params.get("fp"):
            p["client-fingerprint"] = params["fp"]
        if p["network"] == "ws":
            ws = {}
            if params.get("path"):
                ws["path"] = params["path"]
            if params.get("host"):
                ws["headers"] = {"Host": params["host"]}
            if ws:
                p["ws-opts"] = ws
        if p["network"] == "grpc" and params.get("path"):
            p["grpc-opts"] = {"grpc-service-name": params["path"]}
        return p

    if n.proto == "trojan":
        p.update(
            {
                "password": n.identity,
                "network": params.get("type") or "tcp",
            }
        )
        if params.get("sni"):
            p["servername"] = params["sni"]
        if params.get("allowInsecure") == "1":
            p["skip-cert-verify"] = True
        if params.get("fp"):
            p["client-fingerprint"] = params["fp"]
        if p["network"] == "ws" and params.get("path"):
            p["ws-opts"] = {"path": params["path"]}
        if p["network"] == "grpc" and params.get("serviceName"):
            p["grpc-opts"] = {"grpc-service-name": params["serviceName"]}
        return p

    if n.proto == "ss":
        p.update({"cipher": params.get("method") or "aes-256-gcm", "password": n.identity})
        return p

    if n.proto == "ssr":
        p.update(
            {
                "cipher": params.get("method") or "aes-256-cfb",
                "password": n.identity,
                "protocol": params.get("protocol") or "origin",
                "obfs": params.get("obfs") or "plain",
            }
        )
        return p

    if n.proto == "hysteria2":
        p.update(
            {
                "password": n.identity,
            }
        )
        if params.get("sni"):
            p["sni"] = params["sni"]
        if params.get("insecure") == "1":
            p["skip-cert-verify"] = True
        return p

    if n.proto == "tuic":
        p.update({"uuid": n.identity, "password": params.get("password", "")})
        if params.get("sni"):
            p["sni"] = params["sni"]
        if params.get("alpn"):
            p["alpn"] = params["alpn"].split(",")
        return p

    return None


def build_clash_yaml(nodes):
    proxies = []
    for n in nodes:
        p = _clash_proxy(n)
        if p:
            proxies.append(p)
    names = [p["name"] for p in proxies]
    cfg = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "VPN-UNIFIER",
                "type": "url-test",
                "proxies": names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            }
        ],
        "rules": ["MATCH,VPN-UNIFIER"],
    }
    return yaml.safe_dump(
        cfg, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096
    )


def _is_whitelist(node):
    return any(s in config.WHITELIST_SOURCE_NAMES for s in node.sources)


def _bad_reality_sni(raw: str, proto: str) -> bool:
    """Отбрасываем vless reality-конфиги с поддельным SNI (яндекс, lovelive, cloudflare…)."""
    if proto != "vless":
        return False
    if "security=reality" not in raw and "security=%2Freality" not in raw:
        return False
    import re as _re
    m = _re.search(r"sni=([^&#]+)", raw)
    if not m:
        return False
    sni = m.group(1).lower()
    for tok in config.BAD_REALITY_SNIS:
        if tok in sni:
            return True
    return False


def _make_config(nodes, title, desc):
    header = (
        f"# profile-title: {title}\n"
        f"# profile-update-interval: 1\n"
        f"# profile-description: {desc}\n\n"
    )
    body = "\n".join(n.raw for n in nodes)
    b64 = base64.b64encode((header + body).encode("utf-8")).decode().rstrip("=")
    return header + body, b64


def build_outputs(nodes, strict_dead: bool = False, clash: bool = True, max_total: int = None):
    out_dir = config.OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    config.WEB_DATA_DIR.mkdir(parents=True, exist_ok=True)

    if strict_dead:
        main = [n for n in nodes if n.status == "alive"]
        dead = [n for n in nodes if n.status != "alive"]
    else:
        main, dead = split_nodes(nodes)
        main = [n for n in main if n.status == "alive"]

    vip = [n for n in main if _is_whitelist(n)]
    main = [n for n in main if not _is_whitelist(n)]
    main = [n for n in main if not _bad_reality_sni(n.raw, n.proto)]

    if max_total and len(main) > max_total:
        main = main[:max_total]
    if max_total and len(vip) > max_total:
        vip = vip[:max_total]

    alive = [n for n in nodes if n.status == "alive"]
    unknown = [n for n in nodes if n.status == "unknown"]
    dead_nodes = [n for n in nodes if n.status == "dead"]

    unified, b64 = _make_config(main, config.PROFILE_TITLE, config.PROFILE_DESC)
    vip_txt, vip_b64 = _make_config(vip, config.VIP_TITLE, config.VIP_DESC)
    dead_txt = "\n".join(f"{n.raw}" for n in dead)

    (out_dir / "unified_config.txt").write_text(unified, encoding="utf-8")
    (out_dir / "unified_config_b64.txt").write_text(b64, encoding="utf-8")
    (out_dir / "vip_config.txt").write_text(vip_txt, encoding="utf-8")
    (out_dir / "vip_config_b64.txt").write_text(vip_b64, encoding="utf-8")
    (out_dir / "dead_servers.txt").write_text(dead_txt, encoding="utf-8")
    if clash:
        (out_dir / "clash.yaml").write_text(build_clash_yaml(main), encoding="utf-8")
        (out_dir / "clash_vip.yaml").write_text(build_clash_yaml(vip), encoding="utf-8")

    by_proto = {}
    for n in nodes:
        by_proto.setdefault(n.proto, {}).setdefault(n.status, 0)
        by_proto[n.proto][n.status] += 1

    stats = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "updated_ts": int(time.time()),
        "total": len(nodes),
        "alive": len(alive),
        "unknown": len(unknown),
        "dead": len(dead_nodes),
        "in_config": len(main),
        "vip_config": len(vip),
        "protocols": by_proto,
    }
    (out_dir / "stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    files = (
        "unified_config.txt",
        "unified_config_b64.txt",
        "vip_config.txt",
        "vip_config_b64.txt",
        "dead_servers.txt",
        "stats.json",
    )
    for name in files:
        shutil.copyfile(out_dir / name, config.WEB_DATA_DIR / name)
    if clash:
        shutil.copyfile(out_dir / "clash.yaml", config.WEB_DATA_DIR / "clash.yaml")
        shutil.copyfile(out_dir / "clash_vip.yaml", config.WEB_DATA_DIR / "clash_vip.yaml")

    return stats
