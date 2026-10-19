"""
Alert dispatcher: Discord webhook and Telegram bot.
"""
from __future__ import annotations

import html
import json

import requests

_COLORS = {
    "LOW":      0x95A5A6,
    "MEDIUM":   0xF39C12,
    "HIGH":     0xE74C3C,
    "CRITICAL": 0x8E44AD,
}
_DISCORD_FIELD_MAX = 1024


class AlertDispatcher:
    def __init__(
        self,
        discord_webhook: str | None = None,
        telegram_token: str | None = None,
        telegram_chat_id: str | None = None,
    ) -> None:
        self._discord = discord_webhook or None
        self._tg_token = telegram_token or None
        self._tg_chat = telegram_chat_id or None

    @property
    def channels(self) -> list[str]:
        return [name for name, on in (("discord", self._discord),
                                      ("telegram", self._tg_token and self._tg_chat)) if on]

    def send(self, entry: dict) -> None:
        if self._discord:
            self._send_discord(entry)
        if self._tg_token and self._tg_chat:
            self._send_telegram(entry)

    # ── Discord ─────────────────────────────────────────────────────────────

    def _send_discord(self, e: dict) -> None:
        details = _fmt_details(e["details"])
        block = f"```json\n{details}\n```"
        if len(block) > _DISCORD_FIELD_MAX:
            block = f"```json\n{details[:_DISCORD_FIELD_MAX - 20]}\n…\n```"
        payload = {
            "embeds": [{
                "title": f"[SIEM] {e['rule']}",
                "color": _COLORS.get(e["severity"], 0),
                "description": f"**Severity**: `{e['severity']}`",
                "fields": [
                    {"name": "Source", "value": f"`{e['src']}`", "inline": True},
                    {"name": "Destination", "value": f"`{e['dst']}`", "inline": True},
                    {"name": "Timestamp", "value": e["timestamp"], "inline": False},
                    {"name": "Details", "value": block, "inline": False},
                ],
            }]
        }
        try:
            resp = requests.post(self._discord, json=payload, timeout=5)
            if resp.status_code not in (200, 204):
                print(f"[ALERT] Discord HTTP {resp.status_code}")
        except requests.RequestException as exc:
            print(f"[ALERT] Discord error: {exc}")

    # ── Telegram ─────────────────────────────────────────────────────────────

    def _send_telegram(self, e: dict) -> None:
        # HTML mode: rule names contain underscores, which break Telegram's Markdown parser
        msg = (
            f"<b>[SIEM] {html.escape(e['rule'])}</b>\n"
            f"Severity: <code>{e['severity']}</code>\n"
            f"Source: <code>{e['src']}</code>\n"
            f"Destination: <code>{e['dst']}</code>\n"
            f"Timestamp: <code>{e['timestamp']}</code>\n"
            f"<pre>{html.escape(_fmt_details(e['details']))}</pre>"
        )
        url = f"https://api.telegram.org/bot{self._tg_token}/sendMessage"
        try:
            resp = requests.post(
                url, json={"chat_id": self._tg_chat, "text": msg, "parse_mode": "HTML"}, timeout=5,
            )
            if not resp.ok:
                print(f"[ALERT] Telegram HTTP {resp.status_code}")
        except requests.RequestException as exc:
            print(f"[ALERT] Telegram error: {exc}")


def _fmt_details(details: dict) -> str:
    return json.dumps(details, indent=2, ensure_ascii=False)
