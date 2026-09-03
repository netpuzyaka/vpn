import asyncio
from pathlib import Path

import httpx

import config
from .parser import URL_RE

_UA = "v2rayN/6.53"

_SKIP_URL_HOSTS = (
    "t.me",
    "telegram.me",
    "telegram.org",
    "github.com",
    "raw.githubusercontent.com",
    "youtube.com",
    "youtu.be",
    "twitter.com",
    "x.com",
    "instagram.com",
    "facebook.com",
    "vk.com",
)


async def fetch_url(url: str, timeout: float = None, max_bytes: int = None):
    timeout = timeout or config.HTTP_TIMEOUT
    max_bytes = max_bytes or config.HTTP_MAX_BYTES
    headers = {"User-Agent": _UA, "Accept": "*/*"}
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers=headers) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        content = resp.content
        if len(content) > max_bytes:
            content = content[:max_bytes]
    return content.decode("utf-8", "replace")


async def fetch_github_repo(repo: str):
    api_url = f"https://api.github.com/repos/{repo}/contents/"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": _UA}
    blobs = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=30, headers=headers) as client:
        resp = await client.get(api_url)
        resp.raise_for_status()
        items = resp.json()
        if not isinstance(items, list):
            return blobs
        files = []
        for it in items:
            if it.get("type") != "file":
                continue
            name = it.get("name") or ""
            lower = name.lower()
            if lower.endswith((".conf", ".md", ".png", ".jpg", ".jpeg", ".svg", ".html", ".pdf")):
                continue
            if any(skip in name for skip in config.GITHUB_SKIP_NAMES):
                continue
            if it.get("size", 0) > config.HTTP_MAX_BYTES:
                continue
            if "." in name and not lower.endswith((".txt", ".yaml", ".yml", ".json")):
                continue
            files.append(it)
        files = files[: config.GITHUB_FILE_LIMIT]
        for it in files:
            try:
                text = await fetch_url(it["download_url"], timeout=30)
                blobs.append((f"{repo} / {it['name']}", text))
            except Exception:
                continue
    return blobs


async def fetch_raw_urls(urls):
    blobs = []
    for entry in urls:
        try:
            text = await fetch_url(entry["url"])
            blobs.append((entry["name"], text))
        except Exception:
            continue
    return blobs


def fetch_local_txts(sources_dir: Path):
    blobs = []
    if not sources_dir.is_dir():
        return blobs
    for path in sorted(sources_dir.glob("*.txt")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        blobs.append((f"local / {path.name}", text))
    return blobs


async def fetch_sub_urls(urls):
    out = []
    sem = asyncio.Semaphore(20)

    async def one(url):
        async with sem:
            try:
                text = await fetch_url(url, timeout=15, max_bytes=3 * 1024 * 1024)
                return url, text
            except Exception:
                return url, None

    results = await asyncio.gather(*[one(u) for u in urls])
    for url, text in results:
        if text:
            out.append((f"подписка / {url[:90]}", text))
    return out


async def fetch_telegram(
    channels,
    limit: int,
    session_path: str = None,
    string_session: str = None,
    api_id=None,
    api_hash=None,
    with_docs: bool = True,
):
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.tl.types import DocumentAttributeFilename, MessageMediaDocument

    if string_session:
        client = TelegramClient(StringSession(string_session), api_id, api_hash)
    else:
        client = TelegramClient(session_path or str(config.SESSION_DIR / "vpn_unifier"), api_id, api_hash)
    await client.start()
    blobs = []
    sub_urls = set()
    for channel in channels:
        try:
            entity = await client.get_entity(channel)
        except Exception:
            continue
        name = getattr(entity, "title", None) or channel
        texts = []
        try:
            async for msg in client.iter_messages(entity, limit=limit):
                if not msg:
                    continue
                if msg.text:
                    texts.append(msg.text)
                    sub_urls.update(URL_RE.findall(msg.text))
                if with_docs and msg.media and isinstance(msg.media, MessageMediaDocument):
                    doc = msg.media.document
                    ext = ""
                    for attr in getattr(doc, "attributes", None) or []:
                        if isinstance(attr, DocumentAttributeFilename):
                            ext = Path(attr.file_name or "").suffix.lower()
                            break
                    if doc.size <= config.TELEGRAM_DOC_LIMIT_MB * 1024 * 1024 and ext in config.TELEGRAM_DOC_EXTS:
                        try:
                            data = await client.download_media(msg, file=bytes)
                            if data:
                                texts.append(data.decode("utf-8", "replace"))
                        except Exception:
                            pass
        except Exception:
            pass
        if texts:
            blobs.append((f"Telegram / {name}", "\n".join(texts)))
    await client.disconnect()
    filtered = {
        u
        for u in sub_urls
        if not any(h in u for h in _SKIP_URL_HOSTS) and u.lower().startswith("http")
    }
    return blobs, list(filtered)[: config.TELEGRAM_SUB_URL_LIMIT * max(len(channels), 1)]
