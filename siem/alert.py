"""
Alert dispatcher — Discord webhook + Telegram bot.
"""
from __future__ import annotations
import requests
from typing import Optional


_COLORS = {
    "LOW":      0x95A5A6,  # gris
    "MEDIUM":   0xF39C12,  # orange
    "HIGH":     0xE74C3C,  # rouge
    "CRITICAL": 0x8E44AD,  # violet
}


class AlertDispatcher:
    def __init__(
        self,
        discord_webhook: Optional[str] = None,
        telegram_token:  Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ) -> None:
        self._discord  = discord_webhook or None
        self._tg_token = telegram_token  or None
        self._tg_chat  = telegram_chat_id or None

    def send(self, entry: dict) -> None:
        if self._discord:
            self._send_discord(entry)
        if self._tg_token and self._tg_chat:
            self._send_telegram(entry)

    # ── Discord ─────────────────────────────────────────────────────────────

    def _send_discord(self, e: dict) -> None:
        payload = {
            "embeds": [{
                "title":       f"[SIEM] {e['rule']}",
                "color":       _COLORS.get(e["severity"], 0),
                "description": f"**Sévérité** : `{e['severity']}`",
                "fields": [
                    {"name": "Source",    "value": f"`{e['src']}`",  "inline": True},
                    {"name": "Dest",      "value": f"`{e['dst']}`",  "inline": True},
                    {"name": "Timestamp", "value": e["timestamp"],   "inline": False},
                    {"name": "Détails",   "value": f"```json\n{self._fmt_details(e['details'])}\n```", "inline": False},
                ],
                "footer": {"text": "SIEM Hôpital Mandé — G-SEC-910"},
            }]
        }
        try:
            resp = requests.post(self._discord, json=payload, timeout=5)
            if resp.status_code not in (200, 204):
                print(f"[ALERT] Discord HTTP {resp.status_code}")
        except Exception as exc:
            print(f"[ALERT] Discord error: {exc}")

    # ── Telegram ─────────────────────────────────────────────────────────────

    def _send_telegram(self, e: dict) -> None:
        msg = (
            f"*[SIEM] {e['rule']}*\n"
            f"Sévérité : `{e['severity']}`\n"
            f"Source   : `{e['src']}`\n"
            f"Dest     : `{e['dst']}`\n"
            f"Timestamp: `{e['timestamp']}`\n"
            f"```\n{self._fmt_details(e['details'])}\n```"
        )
        url = f"https://api.telegram.org/bot{self._tg_token}/sendMessage"
        try:
            resp = requests.post(
                url,
                json={"chat_id": self._tg_chat, "text": msg, "parse_mode": "Markdown"},
                timeout=5,
            )
            if not resp.json().get("ok"):
                print(f"[ALERT] Telegram error: {resp.text}")
        except Exception as exc:
            print(f"[ALERT] Telegram error: {exc}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _fmt_details(details: dict) -> str:
        import json
        return json.dumps(details, indent=2, ensure_ascii=False)
