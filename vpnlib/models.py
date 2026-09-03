from dataclasses import dataclass, field
from typing import Any, Dict, List

SUPPORTED_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "hysteria",
    "tuic",
)

PROXY_SCHEMES = ("mtproto", "tg", "proxy-mtproto", "socks", "socks5", "socks4", "http")


@dataclass
class Node:
    proto: str
    host: str
    port: int
    raw: str
    name: str = ""
    identity: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    status: str = "unknown"
    latency_ms: int = -1

    @property
    def key(self):
        return (self.proto.lower(), self.host.lower(), int(self.port), self.identity)

    @property
    def display_name(self) -> str:
        return self.name or f"{self.proto}://{self.host}:{self.port}"

    @property
    def short_raw(self) -> str:
        return self.raw if len(self.raw) <= 120 else self.raw[:117] + "..."
