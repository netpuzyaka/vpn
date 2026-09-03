import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import config
from vpnlib import builder, sources
from vpnlib.checker import Checker
from vpnlib.parser import parse_blob

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.text import Text

    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

BANNER = r"""
██╗   ██╗██████╗ ███╗   ██╗   ██╗   ██╗███╗   ██╗██╗███████╗██╗███████╗██████╗
██║   ██║██╔══██╗████╗  ██║   ██║   ██║████╗  ██║██║██╔════╝██║██╔════╝██╔══██╗
██║   ██║██████╔╝██╔██╗ ██║   ██║   ██║██╔██╗ ██║██║█████╗  ██║█████╗  ██████╔╝
╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║   ██║   ██║██║╚██╗██║██║██╔══╝  ██║██╔══╝  ██╔══██╗
 ╚████╔╝ ██║     ██║ ╚████║   ╚██████╔╝██║ ╚████║██║██║     ██║███████╗██║  ██║
  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
"""


def pprint(text: str, style: str = ""):
    if RICH:
        console.print(text, style=style)
    else:
        print(text)


def panel(title: str, body: str, style: str = "bold cyan"):
    if RICH:
        console.print(Panel(Text(body, justify="center"), title=title, border_style=style))
    else:
        print(f"=== {title} ===\n{body}\n")


def merge_nodes(nodes):
    merged = {}
    for node in nodes:
        key = node.key
        if key in merged:
            old = merged[key]
            old.sources.extend(s for s in node.sources if s not in old.sources)
            if not old.name and node.name:
                old.raw, old.name, old.params = node.raw, node.name, node.params
            continue
        merged[key] = node
    return list(merged.values())


def parse_args():
    ap = argparse.ArgumentParser(
        prog="vpn-unifier",
        description="Собирает конфиги VPN из Telegram, GitHub, подписок и .txt в единый конфиг",
    )
    ap.add_argument("--no-telegram", action="store_true", help="не сканировать Telegram-каналы")
    ap.add_argument("--channels", help="каналы через запятую (переопределяет config.py)")
    ap.add_argument("--tg-limit", type=int, default=config.TELEGRAM_MESSAGE_LIMIT, help="сообщений на канал")
    ap.add_argument("--no-docs", action="store_true", help="не качать вложения из Telegram")
    ap.add_argument("--no-github", action="store_true", help="не сканировать GitHub-репозитории")
    ap.add_argument("--no-urls", action="store_true", help="не качать внешние подписки/URL")
    ap.add_argument("--no-local", action="store_true", help="не читать локальные .txt (папка sources)")
    ap.add_argument("--no-check", action="store_true", help="не проверять серверы (всё в единый конфиг)")
    ap.add_argument("--fresh", action="store_true", help="игнорировать кэш проверок")
    ap.add_argument("--strict-dead", action="store_true", help="«неизвестные» тоже в мёртвые")
    ap.add_argument("--max-total", type=int, default=config.MAX_TOTAL_NODES, help="максимум серверов в конфиге")
    ap.add_argument("--protocols", help="протоколы через запятую (vless,vmess,trojan,ss,ssr,hysteria2,tuic)")
    ap.add_argument("--timeout", type=float, default=config.CHECK_TIMEOUT, help="таймаут проверки, сек")
    ap.add_argument("--concurrency", type=int, default=config.CHECK_CONCURRENCY, help="параллельных проверок")
    ap.add_argument("--no-clash", action="store_true", help="не генерировать clash.yaml")
    ap.add_argument("--session", help="путь к .session файлу Telethon")
    ap.add_argument("--ci", action="store_true", help="CI-режим: без интерактива (сессия из env)")
    ap.add_argument("--json", action="store_true", help="вывести итоговую статистику в JSON")
    return ap.parse_args()


def wizard(args):
    if not RICH or args.ci or len(sys.argv) > 1:
        return args
    if not Confirm.ask("\n  Запустить мастер настройки?", default=True):
        return args
    args.no_telegram = not Confirm.ask("  [1/4] Сканировать Telegram-каналы?", default=True)
    if not args.no_telegram:
        limit = Prompt.ask("  [2/4] Сколько сообщений на канал?", default=str(args.tg_limit))
        args.tg_limit = int(limit or args.tg_limit)
    args.no_check = not Confirm.ask("  [3/4] Проверять серверы на доступность?", default=True)
    if not args.no_check:
        args.fresh = Confirm.ask("  [4/4] Игнорировать кэш прошлых проверок?", default=False)
    return args


async def collect_blobs(args):
    blobs = []
    if not args.no_local:
        blobs.extend(sources.fetch_local_txts(config.SOURCES_DIR))
    if not args.no_github:
        for repo in config.GITHUB_REPOS:
            try:
                repo_blobs = await sources.fetch_github_repo(repo)
                blobs.extend(repo_blobs)
            except Exception:
                pass
    if not args.no_urls:
        blobs.extend(await sources.fetch_raw_urls(config.RAW_URLS))
    sub_urls = []
    if not args.no_telegram:
        string_session = os.environ.get("TELEGRAM_SESSION")
        api_id = os.environ.get("TELEGRAM_API_ID") or None
        api_hash = os.environ.get("TELEGRAM_API_HASH") or None
        if api_id:
            try:
                api_id = int(api_id)
            except ValueError:
                api_id = None
        channels = config.TELEGRAM_CHANNELS
        if args.channels:
            channels = [c.strip() for c in args.channels.split(",") if c.strip()]
        try:
            tg_blobs, tg_sub_urls = await sources.fetch_telegram(
                channels,
                limit=args.tg_limit,
                session_path=args.session,
                string_session=string_session,
                api_id=api_id,
                api_hash=api_hash,
                with_docs=not args.no_docs,
            )
            blobs.extend(tg_blobs)
            sub_urls.extend(tg_sub_urls)
        except Exception as e:
            pprint(f"  ⚠ Telegram недоступен: {e}", style="yellow")
    if sub_urls:
        blobs.extend(await sources.fetch_sub_urls(sub_urls))
    return blobs


def source_limit(name: str) -> int:
    for entry in config.RAW_URLS:
        if entry["name"] == name:
            return int(entry.get("limit", config.DEFAULT_SOURCE_LIMIT))
    return config.DEFAULT_SOURCE_LIMIT


async def run(args):
    start = time.time()

    pprint(BANNER, style="bold cyan")
    pprint("  Единый VPN-конфиг: Telegram + GitHub + подписки + .txt\n", style="bold")

    blobs = []
    if RICH:
        with console.status("[cyan]Сбор источников конфигов...[/cyan]", spinner="dots"):
            blobs = await collect_blobs(args)
    else:
        print("Сбор источников конфигов...")
        blobs = await collect_blobs(args)

    if not blobs:
        pprint("  ✖ Ничего не удалось собрать. Проверь интернет и настройки.", style="bold red")
        sys.exit(1)

    proto_filter = None
    if args.protocols:
        proto_filter = {p.strip().lower() for p in args.protocols.split(",") if p.strip()}

    table = Table(title="Источники", box=box.ROUNDED) if RICH else None
    if RICH:
        table.add_column("Источник", style="cyan", no_wrap=True, max_width=48, overflow="ellipsis")
        table.add_column("Узлов", justify="right", style="green", min_width=6)
        table.add_column("Пропущено", justify="right", style="dim", min_width=9)

    all_nodes = []
    for name, text in blobs:
        nodes, _ = parse_blob(text, name)
        if proto_filter:
            nodes = [n for n in nodes if n.proto in proto_filter]
        if not nodes:
            continue
        limit = source_limit(name)
        skipped = max(0, len(nodes) - limit)
        nodes = nodes[:limit]
        all_nodes.extend(nodes)
        if RICH:
            table.add_row(name, str(len(nodes)), str(skipped))

    if RICH:
        console.print(table)

    nodes = merge_nodes(all_nodes)
    pprint(f"  Всего уникальных серверов: [bold]{len(nodes)}[/bold]", style="bold cyan" if RICH else "")

    if not nodes:
        pprint("  ✖ В собранных данных не найдено ни одного валидного конфига.", style="bold red")
        sys.exit(1)

    if not args.no_check:
        checker = Checker(
            timeout=args.timeout,
            concurrency=args.concurrency,
            use_cache=not args.fresh,
        )
        counters = {"alive": 0, "dead": 0, "unknown": 0}
        pprint("  Проверка доступности серверов (TCP)...", style="bold cyan" if RICH else "")

        if RICH:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
            )
            task = progress.add_task("[cyan]Проверка", total=len(nodes))
            with Live(progress, console=console, refresh_per_second=10):
                done = 0

                def cb(node):
                    nonlocal done
                    done += 1
                    counters[node.status] += 1
                    progress.update(
                        task,
                        advance=1,
                        description=(
                            f"[cyan]Проверка[/cyan] [green]✓ {counters['alive']}[/green] "
                            f"[red]✗ {counters['dead']}[/red] "
                            f"[yellow]? {counters['unknown']}[/yellow]"
                        ),
                    )

                await checker.check_all(nodes, progress_cb=cb)
        else:
            done = 0
            total = len(nodes)

            def cb(node):
                nonlocal done
                done += 1
                counters[node.status] += 1
                if done % 100 == 0 or done == total:
                    print(
                        f"  [{done}/{total}] alive={counters['alive']} dead={counters['dead']} unknown={counters['unknown']}"
                    )

            await checker.check_all(nodes, progress_cb=cb)
        checker.save_cache()

    if args.max_total and len(nodes) > args.max_total:
        pprint(
            f"  Лимит конфига {args.max_total}: серверы сверх лимита не попадут в единый конфиг.",
            style="yellow",
        )

    stats = builder.build_outputs(
        nodes, strict_dead=args.strict_dead, clash=not args.no_clash, max_total=args.max_total
    )

    alive = [n for n in nodes if n.status == "alive"]
    if alive:
        alive_sorted = sorted(alive, key=lambda n: n.latency_ms)[:5]
        top_table = Table(title="Топ-5 по пингу", box=box.ROUNDED)
        top_table.add_column("Пинг", justify="right", style="green")
        top_table.add_column("Сервер", style="cyan")
        for n in alive_sorted:
            top_table.add_row(f"{n.latency_ms} мс", n.display_name[:80])
        if RICH:
            console.print(top_table)

    summary = Table(title="Итоги", box=box.HEAVY_HEAD)
    summary.add_column("Параметр", style="bold")
    summary.add_column("Значение")
    summary.add_row("Всего найдено", str(stats["total"]))
    summary.add_row("Работают", f"[green]{stats['alive']}[/green]" if RICH else str(stats["alive"]))
    summary.add_row("Не проверены/неуверенно", f"[yellow]{stats['unknown']}[/yellow]" if RICH else str(stats["unknown"]))
    summary.add_row("Мёртвые", f"[red]{stats['dead']}[/red]" if RICH else str(stats["dead"]))
    summary.add_row("В едином конфиге", f"[bold cyan]{stats['in_config']}[/bold cyan]" if RICH else str(stats["in_config"]))
    summary.add_row("Время работы", f"{time.time() - start:.1f} сек")
    summary.add_row("Файл", str(config.OUTPUT_DIR / "unified_config.txt"))
    summary.add_row("Base64-подписка", str(config.OUTPUT_DIR / "unified_config_b64.txt"))
    summary.add_row("Мёртвые серверы", str(config.OUTPUT_DIR / "dead_servers.txt"))
    if RICH:
        console.print(summary)
    else:
        print(f"  alive={stats['alive']} unknown={stats['unknown']} dead={stats['dead']}")

    if RICH:
        console.print(
            f"\n[bold green]✔ Готово![/bold green] Файлы сохранены в [bold]{config.OUTPUT_DIR}[/bold] "
            f"и скопированы в [bold]{config.WEB_DATA_DIR}[/bold] для сайта."
        )
    else:
        print("Готово! Файлы сохранены.")

    if args.json:
        print(json.dumps(stats, ensure_ascii=False))
    return stats


def main():
    args = parse_args()
    args = wizard(args)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
