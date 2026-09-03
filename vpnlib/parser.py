import base64
import binascii
import json
import re
from urllib.parse import parse_qs, unquote, urlencode, quote

import yaml

from .models import Node, SUPPORTED_PROTOCOLS

LINK_RE = re.compile(
    r"(?:vless|vmess|trojan|ssr?|hysteria2?|tuic)://[^\s\"'<>\[\]]+",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>\[\]]+", re.IGNORECASE)

_TRAILING = ".,;:)]}"


def _clean(raw: str) -> str:
    raw = raw.strip().rstrip(_TRAILING)
    raw = raw.strip("\"'`")
    return raw


def _b64(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.b64decode(data + pad)


def _safe_unquote(s: str) -> str:
    try:
        return unquote(s, errors="replace")
    except Exception:
        return s


def _qs(query: str):
    return {k: (v[0] if v else "") for k, v in parse_qs(query.lstrip("?"), keep_blank_values=True).items()}


def _frag(name: str) -> str:
    return "#" + quote(name, safe="") if name else ""


def extract_links(text: str):
    return [_clean(m.group(0)) for m in LINK_RE.finditer(text)]


def extract_urls(text: str):
    return [_clean(m.group(0)) for m in URL_RE.finditer(text)]


def decode_layer(text: str) -> str:
    t = text.strip()
    if LINK_RE.search(t) or not t:
        return t
    joined = "".join(t.split())
    for attempt in (joined, joined.rstrip("="), joined + "=" * (-len(joined) % 4)):
        try:
            decoded = base64.b64decode(attempt).decode("utf-8", "replace")
        except Exception:
            continue
        if LINK_RE.search(decoded):
            return decoded
        try:
            decoded = base64.b64decode(attempt.encode(), altchars=b"-_").decode("utf-8", "replace")
        except Exception:
            continue
        if LINK_RE.search(decoded):
            return decoded
    return text


def parse_vless(raw: str):
    m = re.match(
        r"^vless://(?P<id>[^@?#/\s]+)@(?P<host>[^:?#/\s]+):(?P<port>\d+)"
        r"(?P<query>\?[^#\s]*)?(?:#(?P<name>.*))?$",
        raw,
        re.I,
    )
    if not m:
        return None
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    params = _qs(m.group("query") or "")
    flow = params.get("flow", "")
    net = (params.get("type") or "tcp").lower()
    if flow.lower().startswith("xtls") and net not in ("tcp", "none", ""):
        return None
    if not _safe_unquote(m.group("id")):
        return None
    return Node(
        proto="vless",
        host=m.group("host"),
        port=port,
        raw=raw,
        name=_safe_unquote(m.group("name") or ""),
        identity=_safe_unquote(m.group("id")),
        params=params,
    )


def parse_vmess(raw: str):
    b64part = raw[len("vmess://"):]
    try:
        data = json.loads(_b64(b64part).decode("utf-8", "replace"))
    except Exception:
        return None
    host = data.get("add")
    port = data.get("port")
    if not host or port is None:
        return None
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None
    params = {
        k: data[k]
        for k in ("net", "type", "path", "host", "tls", "sni", "alpn", "fp", "aid", "scy", "v")
        if data.get(k) not in (None, "")
    }
    return Node(
        proto="vmess",
        host=host,
        port=port,
        raw=raw,
        name=data.get("ps") or "",
        identity=data.get("id") or "",
        params=params,
    )


def parse_trojan(raw: str):
    m = re.match(
        r"^trojan://(?P<pass>[^@?#/\s]+)@(?P<host>[^:?#/\s]+):(?P<port>\d+)"
        r"(?P<query>\?[^#\s]*)?(?:#(?P<name>.*))?$",
        raw,
        re.I,
    )
    if not m:
        return None
    try:
        port = int(m.group("port"))
    except ValueError:
        return None
    params = _qs(m.group("query") or "")
    return Node(
        proto="trojan",
        host=m.group("host"),
        port=port,
        raw=raw,
        name=_safe_unquote(m.group("name") or ""),
        identity=_safe_unquote(m.group("pass")),
        params=params,
    )


def parse_ss(raw: str):
    body = raw[len("ss://"):]
    m = re.match(
        r"^(?P<b64>[A-Za-z0-9+/_\-]+={0,2})@(?P<host>[^:?#/\s]+):(?P<port>\d+)"
        r"(?:/\?(?P<plugin>[^#\s]*))?(?:#(?P<name>.*))?$",
        body,
    )
    method = password = ""
    if m:
        try:
            method, _, password = _b64(m.group("b64")).decode("utf-8", "replace").partition(":")
        except Exception:
            return None
        host, port, name, params = m.group("host"), m.group("port"), m.group("name") or "", {}
        if m.group("plugin"):
            params = _qs(m.group("plugin"))
    else:
        m2 = re.match(
            r"^(?P<method>[^:@/\s]+):(?P<password>[^@?#/\s]*)@(?P<host>[^:?#/\s]+):(?P<port>\d+)"
            r"(?:#(?P<name>.*))?$",
            body,
        )
        if m2:
            method, password = m2.group("method"), _safe_unquote(m2.group("password"))
            host, port, name = m2.group("host"), m2.group("port"), m2.group("name") or ""
            params = {}
        else:
            try:
                decoded = _b64(body).decode("utf-8", "replace")
            except Exception:
                return None
            m3 = re.match(r"^(?P<method>[^:]+):(?P<password>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)$", decoded)
            if not m3:
                return None
            method, password = m3.group("method"), m3.group("password")
            host, port, name = m3.group("host"), m3.group("port"), ""
            params = {}
    try:
        port = int(port)
    except (ValueError, TypeError):
        return None
    params.setdefault("method", method)
    return Node(
        proto="ss",
        host=host,
        port=port,
        raw=raw,
        name=_safe_unquote(name),
        identity=password or method,
        params=params,
    )


def parse_ssr(raw: str):
    b64part = raw[len("ssr://"):]
    try:
        data = _b64(b64part).decode("utf-8", "replace")
    except Exception:
        return None
    main, _, tail = data.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        return None
    host, port_s = parts[0], parts[1]
    try:
        port = int(port_s)
    except ValueError:
        return None
    try:
        password = _b64(parts[5]).decode("utf-8", "replace")
    except Exception:
        password = parts[5]
    params = _qs(tail) if tail else {}
    params.setdefault("method", parts[3])
    params.setdefault("obfs", parts[4])
    params.setdefault("protocol", parts[2])
    name = ""
    remarks = params.get("remarks")
    if remarks:
        try:
            name = _b64(remarks).decode("utf-8", "replace")
        except Exception:
            name = remarks
    return Node(
        proto="ssr",
        host=host,
        port=port,
        raw=raw,
        name=name,
        identity=password,
        params=params,
    )


def parse_hysteria(raw: str):
    if raw.lower().startswith("hysteria2://"):
        m = re.match(
            r"^hysteria2?://(?P<auth>[^@?#/\s]+)@(?P<host>[^:?#/\s]+):(?P<port>\d+)"
            r"(?P<query>\?[^#\s]*)?(?:#(?P<name>.*))?$",
            raw,
            re.I,
        )
        if not m:
            return None
        identity = _safe_unquote(m.group("auth"))
        host, port, query, name = m.group("host"), m.group("port"), m.group("query") or "", m.group("name") or ""
        params = _qs(query)
        return Node("hysteria2", host, int(port), raw, _safe_unquote(name), identity, params)
    m = re.match(
        r"^hysteria://(?P<host>[^:?#/\s]+):(?P<port>\d+)(?P<query>\?[^#\s]*)?(?:#(?P<name>.*))?$",
        raw,
        re.I,
    )
    if not m:
        return None
    params = _qs(m.group("query") or "")
    return Node(
        "hysteria",
        m.group("host"),
        int(m.group("port")),
        raw,
        _safe_unquote(m.group("name") or ""),
        params.get("auth", ""),
        params,
    )


def parse_tuic(raw: str):
    m = re.match(
        r"^tuic://(?P<uuid>[^:?#/\s]+):(?P<pass>[^@?#/\s]+)@(?P<host>[^:?#/\s]+):(?P<port>\d+)"
        r"(?P<query>\?[^#\s]*)?(?:#(?P<name>.*))?$",
        raw,
        re.I,
    )
    if not m:
        return None
    params = _qs(m.group("query") or "")
    return Node(
        "tuic",
        m.group("host"),
        int(m.group("port")),
        raw,
        _safe_unquote(m.group("name") or ""),
        _safe_unquote(m.group("uuid")),
        params,
    )


def parse_link(raw: str):
    raw = _clean(raw)
    if not raw:
        return None
    proto = raw.split("://", 1)[0].lower()
    if proto == "vless":
        return parse_vless(raw)
    if proto == "vmess":
        return parse_vmess(raw)
    if proto == "trojan":
        return parse_trojan(raw)
    if proto == "ss":
        return parse_ss(raw)
    if proto == "ssr":
        return parse_ssr(raw)
    if proto == "hysteria2":
        return parse_hysteria(raw)
    if proto == "hysteria":
        return parse_hysteria(raw)
    if proto == "tuic":
        return parse_tuic(raw)
    return None


def clash_to_url(p: dict):
    t = (p.get("type") or "").lower()
    name = p.get("name") or ""
    frag = _frag(name)
    server = p.get("server")
    port = p.get("port")
    if not server or port is None:
        return None

    if t == "vless":
        uuid = p.get("uuid")
        if not uuid:
            return None
        q = {}
        net = p.get("network") or "tcp"
        q["type"] = net
        if p.get("reality-opts"):
            q["security"] = "reality"
        elif p.get("tls"):
            q["security"] = "tls"
        if p.get("flow"):
            q["flow"] = p["flow"]
        if p.get("servername"):
            q["sni"] = p["servername"]
        if p.get("client-fingerprint"):
            q["fp"] = p["client-fingerprint"]
        ro = p.get("reality-opts") or {}
        if ro.get("public-key"):
            q["pbk"] = ro["public-key"]
        if ro.get("short-id"):
            q["sid"] = str(ro["short-id"])
        ws = p.get("ws-opts") or {}
        if net == "ws" and ws.get("path"):
            q["path"] = ws["path"]
            if (ws.get("headers") or {}).get("Host"):
                q["host"] = ws["headers"]["Host"]
        grpc = p.get("grpc-opts") or {}
        if net == "grpc" and grpc.get("grpc-service-name"):
            q["serviceName"] = grpc["grpc-service-name"]
        return f"vless://{uuid}@{server}:{port}?{urlencode(q)}{frag}"

    if t == "vmess":
        ws = p.get("ws-opts") or {}
        grpc = p.get("grpc-opts") or {}
        j = {
            "v": "2",
            "ps": name,
            "add": server,
            "port": str(port),
            "id": p.get("uuid", ""),
            "aid": str(p.get("alterId") or 0),
            "scy": p.get("cipher") or "auto",
            "net": p.get("network") or "tcp",
            "type": (ws.get("headers") or {}).get("Host", ""),
            "host": ws.get("host") or "",
            "path": ws.get("path") or (grpc.get("grpc-service-name") or ""),
            "tls": "tls" if p.get("tls") else "",
            "sni": p.get("servername") or "",
            "alpn": ",".join(p.get("alpn") or []),
            "fp": p.get("client-fingerprint") or "",
        }
        b64 = base64.urlsafe_b64encode(json.dumps(j, ensure_ascii=False).encode("utf-8")).decode().rstrip("=")
        return "vmess://" + b64

    if t == "trojan":
        q = {}
        if p.get("servername"):
            q["sni"] = p["servername"]
        if p.get("alpn"):
            q["alpn"] = ",".join(p["alpn"])
        if p.get("skip-cert-verify"):
            q["allowInsecure"] = "1"
        query = ("?" + urlencode(q)) if q else ""
        return f"trojan://{p.get('password', '')}@{server}:{port}{query}{frag}"

    if t == "ss":
        method = p.get("cipher")
        password = p.get("password")
        if not method or password is None:
            return None
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}{frag}"

    if t == "ssr":
        method = p.get("cipher") or ""
        password = p.get("password") or ""
        protocol = p.get("protocol") or "origin"
        obfs = p.get("obfs") or "plain"
        pass_b64 = base64.urlsafe_b64encode(password.encode()).decode().rstrip("=")
        main = f"{server}:{port}:{protocol}:{method}:{obfs}:{pass_b64}"
        params = {}
        if name:
            params["remarks"] = base64.urlsafe_b64encode(name.encode()).decode().rstrip("=")
        tail = ("/?" + urlencode(params)) if params else ""
        return "ssr://" + base64.urlsafe_b64encode(f"{main}{tail}".encode()).decode().rstrip("=")

    if t == "hysteria2":
        q = {}
        if p.get("sni"):
            q["sni"] = p["sni"]
        if p.get("insecure"):
            q["insecure"] = "1"
        query = ("?" + urlencode(q)) if q else ""
        return f"hysteria2://{p.get('password', '')}@{server}:{port}{query}{frag}"

    if t == "tuic":
        q = {}
        if p.get("sni"):
            q["sni"] = p["sni"]
        if p.get("alpn"):
            q["alpn"] = ",".join(p["alpn"])
        query = ("?" + urlencode(q)) if q else ""
        return f"tuic://{p.get('uuid', '')}:{p.get('password', '')}@{server}:{port}{query}{frag}"

    return None


def parse_structured(text: str):
    stripped = text.lstrip()
    if "proxies:" not in text[:2000] and not stripped.startswith(("{", "[")):
        return None
    try:
        data = yaml.safe_load(text)
    except Exception:
        return None
    proxies = None
    if isinstance(data, dict):
        proxies = data.get("proxies") or data.get("Proxy")
    elif isinstance(data, list):
        proxies = data
    if not isinstance(proxies, list):
        return None
    urls = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        t = (p.get("type") or "").lower()
        if t not in SUPPORTED_PROTOCOLS:
            continue
        url = clash_to_url(p)
        if url:
            urls.append(url)
    return urls


def parse_blob(text: str, source_name: str):
    text = decode_layer(text or "")
    nodes = []
    seen = set()
    for raw in extract_links(text):
        if raw in seen:
            continue
        seen.add(raw)
        node = parse_link(raw)
        if node:
            node.sources.append(source_name)
            nodes.append(node)
    for url in parse_structured(text) or []:
        node = parse_link(url)
        if node:
            node.sources.append(source_name + " [clash]")
            nodes.append(node)
    return nodes, extract_urls(text)
