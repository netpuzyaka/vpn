import asyncio
import sys
from pathlib import Path

from telethon import TelegramClient
from telethon.sessions import StringSession


async def main():
    session_path = sys.argv[1] if len(sys.argv) > 1 else str(Path("session") / "vpn_unifier.session")
    client = TelegramClient(session_path, None, None)
    await client.connect()
    if not await client.is_user_authorized():
        print("Сессия не авторизована. Сначала запустите python main.py и войдите в аккаунт.")
        await client.disconnect()
        return
    ss = StringSession.save(client.session)
    print("STRING_SESSION (добавьте в секреты GitHub Actions):")
    print(ss)
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
