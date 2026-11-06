"""
AegisDPI — Telegram Alerting Client
Sends anomaly notification messages to Telegram via Bot API.
"""

import os
import logging
import requests

logger = logging.getLogger("telegram-client")


def send_telegram_alert(
    source_ip: str,
    dest_ip: str,
    confidence: float,
    description: str,
    auto_mitigated: bool,
    trigger: str = None,
) -> str:
    """
    Sends an anomaly alert message to configured Telegram chat.
    Returns status:
    - "disabled" (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)
    - "sent" (successfully dispatched via Telegram Bot API)
    - "failed" (API error or exception)
    """
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()

    if not bot_token or not chat_id:
        return "disabled"

    mitigation_text = (
        "Enforced (Auto-Mitigated via Nftables)"
        if auto_mitigated
        else "Failed or Disabled"
    )
    conf_pct = f"{confidence * 100:.1f}%"
    trigger_line = f"• *Trigger:* `{trigger.upper()}`\n" if trigger else ""

    message = (
        "🚨 *AEGIS DPI — ANOMALY DETECTED*\n\n"
        f"• *Source IP:* `{source_ip}`\n"
        f"• *Target IP:* `{dest_ip}`\n"
        f"{trigger_line}"
        f"• *Confidence:* *{conf_pct}*\n"
        f"• *Auto-Mitigation:* {mitigation_text}\n\n"
        f"📋 *Summary:*\n{description}\n"
    )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
    }

    try:
        res = requests.post(url, json=payload, timeout=5)
        if res.status_code != 200:
            logger.warning(
                "Telegram alert notification returned status %d: %s",
                res.status_code,
                res.text,
            )
            return "failed"
        else:
            logger.info("Telegram alert dispatched successfully for %s", source_ip)
            return "sent"
    except Exception as e:
        logger.warning("Failed to send Telegram alert: %s", e)
        return "failed"
