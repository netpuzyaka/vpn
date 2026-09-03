#!/usr/bin/env python3
"""
Добавляет конфиг как «пасту» и (опционально) автоматически пушит на GitHub,
чтобы Vercel передеплоил сайт и отдавал ссылку /sub/<hash>.

Использование:
    python tools/add_paste.py "vless://..."                     # передать текст
    python tools/add_paste.py path/to/config.txt                # файл
    python tools/add_paste.py https://example.com/sub           # ссылка (скачает)
    Set/pipe:  Get-Content c.txt | python tools/add_paste.py    # из stdin
    python tools/add_paste.py "vless://..." --push              # сразу запуш
    python tools/add_paste.py "vless://..." --push --domain vpn-amber-eight.vercel.app
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
PASTES_DIR = ROOT / "pastes"
WEB_PASTES_DIR = ROOT / "web" / "data" / "pastes"


def read_source(source, use_stdin):
    if use_stdin or not sys.stdin.isatty():
        data = sys.stdin.read().strip()
        if data:
            return data
    if not source:
        return ""
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        import httpx

        return httpx.get(source, timeout=30, follow_redirects=True).text.strip()
    p = Path(source)
    if p.is_file():
        return p.read_text(encoding="utf-8", errors="replace").strip()
    return source.strip()


def slug(data):
    return hashlib.sha1(data.encode("utf-8")).hexdigest()[:8]


def git(cmd):
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return res.returncode, res.stdout, res.stderr


def main():
    ap = argparse.ArgumentParser(description="Создать короткую ссылку /sub/<hash> на конфиг")
    ap.add_argument("source", nargs="?", help="текст, файл или URL конфига (можно stdin)")
    ap.add_argument("--name", help="имя пасты, по умолчанию — хэш")
    ap.add_argument("--push", action="store_true", help="закоммитить и запушить на GitHub автоматически")
    ap.add_argument("--domain", help="домен для ссылки (иначе только путь /sub/<hash>)")
    ap.add_argument("--stdin", action="store_true", help="читать из stdin принудительно")
    a = ap.parse_args()

    data = read_source(a.source, a.stdin)
    if not data:
        ap.print_usage()
        sys.exit("Ошибка: передай конфиг текстом, файлом, URL или через stdin.")

    h = slug(data)
    name = (a.name or "").strip() or h
    PASTES_DIR.mkdir(parents=True, exist_ok=True)
    WEB_PASTES_DIR.mkdir(parents=True, exist_ok=True)

    (PASTES_DIR / f"{h}.txt").write_text(data, encoding="utf-8")
    shutil.copyfile(PASTES_DIR / f"{h}.txt", WEB_PASTES_DIR / f"{h}.txt")

    domain = a.domain or os.environ.get("SITE_DOMAIN") or "vpn-amber-eight.vercel.app"
    url = f"https://{domain}/sub/{h}"

    print(f"  Ссылка:  {url}")
    print(f"  Файл:    {WEB_PASTES_DIR / (h + '.txt')}")

    if a.push:
        _, repo, _ = git(["git", "status", "--porcelain"])
        changed = bool(repo.strip())
        git(["git", "add", "pastes", "web/data/pastes"])
        rc, out, err = git(["git", "diff", "--cached", "--quiet"])
        if rc != 0:
            print("  Коммит и пуш на GitHub...")
            code, _, err2 = git(["git", "commit", "-m", f"add paste {name} ({h})"])
            if code != 0:
                sys.exit(f"Ошибка коммита: {err2}")
            code, out2, err2 = git(["git", "push", "origin", "master"])
            if code != 0:
                sys.exit(f"Ошибка пуша: {err2}")
            print("  ✔ Запушено. Vercel передеплоит в течение минуты.")
        else:
            print("  Изменений нет — этот конфиг уже запушен.")
    else:
        print("  Запуши сам (git add -A && git commit -m '...' && git push) или добавь --push.")


if __name__ == "__main__":
    main()
