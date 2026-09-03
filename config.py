from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SESSION_DIR = BASE_DIR / "session"
SOURCES_DIR = BASE_DIR / "sources"
OUTPUT_DIR = BASE_DIR / "output"
WEB_DATA_DIR = BASE_DIR / "web" / "data"

TELEGRAM_CHANNELS = [
    "https://t.me/SlivVpn",
    "https://t.me/PluginHappv2rayTun",
]
TELEGRAM_MESSAGE_LIMIT = 150
TELEGRAM_DOC_LIMIT_MB = 2
TELEGRAM_SUB_URL_LIMIT = 25
TELEGRAM_DOC_EXTS = (".txt", ".yaml", ".yml", ".json")

GITHUB_REPOS = [
    "igareck/vpn-configs-for-russia",
]
GITHUB_FILE_LIMIT = 60
GITHUB_SKIP_NAMES = ("WHITE-CIDR", "WHITE-SNI", "TOR-BRIDGES", "QR-", "LICENSE", "README")

RAW_URLS = [
    {
        "url": "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
        "name": "goida-vpn-configs (26.txt)",
        "limit": 1000,
    },
    {
        "url": "https://lk.cdn-assets-pro.com/sub/dXNlcl84NDk2NzkzMDEzX2QxLDE3ODYyMzYyMDAQUA6zcEUjg",
        "name": "cdn-assets подписка",
        "limit": 1000,
    },
    {
        "url": "https://warp-gen.cyb-portal.org/CP-032",
        "name": "warp-gen CP-032 (сборка)",
        "limit": 300,
    },
    {
        "url": "https://warp-gen.cyb-portal.org/CP-042",
        "name": "warp-gen CP-042",
        "limit": 300,
    },
    {
        "url": "https://warp-gen.cyb-portal.org/CP-038",
        "name": "warp-gen CP-038",
        "limit": 300,
    },
    {
        "url": "https://warp-gen.cyb-portal.org/CP-037",
        "name": "warp-gen CP-037",
        "limit": 300,
    },
    {
        "url": "https://warp-gen.cyb-portal.org/CP-019",
        "name": "warp-gen CP-019",
        "limit": 300,
    },
    {
        "url": "https://is.wepogp.gay/bypass-hwid-lock-3z5O6BFAaJQzGlamvtSo?payload=gG/IXjj2tBVY9/4JV3lO3LR8fEj/UerNm8z9mCCsm7SJ3ys2XwiB0%2BDskEqi5KAfMsHsakN5Ts1gfflCuHW4zA%3D%3D",
        "name": "wepogp CP2 (sing-box JSON)",
        "limit": 300,
    },
    {
        "url": "https://is.wepogp.gay/bypass-hwid-lock-3z5O6BFAaJQzGlamvtSo?payload=LoWcw85kRd%2BHRAuaIWWTGQtmHz91ER2Gsf9j8ro4aENKelQom7dBGSEIW11PuLnbJGqHulnnMD/AW2RrnHWKlWFJxvUtqF01SLDdwqY%2Bj9MB2RSD%2BDWEqu7KmBMo/8DS",
        "name": "wepogp CP3",
        "limit": 300,
    },
    {
        "url": "https://is.wepogp.gay/bypass-hwid-lock-3z5O6BFAaJQzGlamvtSo?payload=LoWcw85kRd%2BHRAuaIWWTGSrQUdcV/eGORkiAoI3BsgSObYWaeuC%2BBYXbabYZ%2BZDH/B4IykRnliVs3yXtFIJLootPp9LjxoPrX0EudeB3cRP9FadgPlOCQ7fXa5V66JkPf7449MjjDishvwQEBmO6aQ%3D%3D",
        "name": "wepogp CP1",
        "limit": 300,
    },
]

DEFAULT_SOURCE_LIMIT = 1000
MAX_TOTAL_NODES = 4000

CHECK_TIMEOUT = 5.0
CHECK_CONCURRENCY = 300
CHECK_RETRIES = 1
CACHE_TTL_HOURS = 12

HTTP_TIMEOUT = 25
HTTP_MAX_BYTES = 10 * 1024 * 1024

PROTOCOL_ALIASES = {
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "hysteria": "hysteria",
}
