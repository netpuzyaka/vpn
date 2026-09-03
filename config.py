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
