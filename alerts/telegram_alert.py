"""
Alert Notification Module.
Sends alerts via Telegram when HIGH or CRITICAL severity attacks are detected.
Also supports email notifications as a fallback.

Configuration:
  Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in config.py or as env vars.
"""

import os
import time
import threading
import json
from datetime import datetime

try:
    import urllib.request
    import urllib.parse
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False


class TelegramAlerter:
    """
    Sends alert notifications to Telegram when high-severity attacks are detected.
    Uses the Telegram Bot API via urllib (no extra dependencies needed).
    """

    def __init__(self, bot_token=None, chat_id=None):
        """
        Initialize the Telegram alerter.

        Args:
            bot_token: Telegram Bot API token (from @BotFather)
            chat_id: Target Telegram chat/group ID
        """
        self.bot_token = bot_token or os.environ.get('TELEGRAM_BOT_TOKEN', '')
        self.chat_id = chat_id or os.environ.get('TELEGRAM_CHAT_ID', '')
        self.enabled = bool(self.bot_token and self.chat_id)

        # Rate limiting: max 1 alert per 30 seconds per alert type
        self._cooldown = {}
        self._cooldown_seconds = 30

        # Statistics
        self.stats = {
            'messages_sent': 0,
            'errors': 0,
            'last_sent': None,
        }

        if self.enabled:
            print(f"[✓] Telegram alerts enabled (chat: {self.chat_id[:6]}...)")
        else:
            print("[*] Telegram alerts disabled. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable.")

    def send_alert(self, alert):
        """
        Send an alert notification via Telegram (non-blocking).
        Only sends for HIGH and CRITICAL severity alerts.

        Args:
            alert: Alert object with severity, alert_type, source_ip, etc.
        """
        if not self.enabled:
            return

        # Only send for high/critical severity
        severity = getattr(alert, 'severity', '') if hasattr(alert, 'severity') else alert.get('severity', '')
        if severity not in ('high', 'critical'):
            return

        # Check cooldown
        alert_type = getattr(alert, 'alert_type', '') if hasattr(alert, 'alert_type') else alert.get('alert_type', '')
        cooldown_key = f"{alert_type}:{getattr(alert, 'source_ip', '') if hasattr(alert, 'source_ip') else alert.get('source_ip', '')}"
        now = time.time()

        if cooldown_key in self._cooldown:
            if now - self._cooldown[cooldown_key] < self._cooldown_seconds:
                return
        self._cooldown[cooldown_key] = now

        # Send asynchronously to avoid blocking packet processing
        thread = threading.Thread(
            target=self._send_message,
            args=(alert,),
            daemon=True,
            name='TelegramAlert',
        )
        thread.start()

    def _send_message(self, alert):
        """Send the actual Telegram message (runs in background thread)."""
        try:
            # Format alert message
            message = self._format_alert(alert)

            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            data = urllib.parse.urlencode({
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': 'true',
            }).encode('utf-8')

            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')

            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    self.stats['messages_sent'] += 1
                    self.stats['last_sent'] = time.time()
                    print(f"[✓] Telegram alert sent: {self._get_attr(alert, 'alert_type')}")
                else:
                    self.stats['errors'] += 1
                    print(f"[!] Telegram API error: {response.status}")

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[!] Telegram alert error: {e}")

    def _format_alert(self, alert):
        """Format an alert into a Telegram-friendly HTML message."""
        severity = self._get_attr(alert, 'severity')
        alert_type = self._get_attr(alert, 'alert_type')
        source_ip = self._get_attr(alert, 'source_ip')
        target_ip = self._get_attr(alert, 'target_ip')
        description = self._get_attr(alert, 'description')
        confidence = self._get_attr(alert, 'confidence')
        detection_method = self._get_attr(alert, 'detection_method')
        evidence = self._get_attr(alert, 'evidence') or []

        # Severity icons
        severity_icons = {
            'critical': '🔴 CRITICAL',
            'high': '🟠 HIGH',
            'medium': '🟣 MEDIUM',
            'low': '🔵 LOW',
        }

        severity_display = severity_icons.get(severity, severity.upper())
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        message = (
            f"🚨 <b>SECURITY ALERT</b> 🚨\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"⚡ <b>Type:</b> {alert_type}\n"
            f"🎯 <b>Severity:</b> {severity_display}\n"
            f"📊 <b>Confidence:</b> {float(confidence) * 100:.0f}%\n"
            f"🔍 <b>Method:</b> {detection_method}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📤 <b>Source:</b> <code>{source_ip}</code>\n"
        )

        if target_ip:
            message += f"📥 <b>Target:</b> <code>{target_ip}</code>\n"

        message += (
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 <b>Details:</b>\n{description}\n"
        )

        if evidence and isinstance(evidence, list):
            message += "\n🔎 <b>Evidence:</b>\n"
            for item in evidence[:5]:  # Limit to 5 evidence items
                message += f"  • {item}\n"

        message += (
            f"\n⏰ <b>Time:</b> {now}\n"
            f"🛡️ <i>NetGuard Smart Firewall & IDS</i>"
        )

        return message

    def _get_attr(self, obj, key):
        """Get attribute from either an object or a dict."""
        if hasattr(obj, key):
            return getattr(obj, key)
        elif isinstance(obj, dict):
            return obj.get(key, '')
        return ''

    def send_firewall_action(self, action):
        """
        Send a firewall BLOCK notification via Telegram.

        Args:
            action: FirewallAction object from decision engine
        """
        if not self.enabled:
            return

        action_type = self._get_attr(action, 'action')
        severity = self._get_attr(action, 'severity')

        # Send for: all BLOCKs, and FLAGs with high/critical severity
        if action_type == 'BLOCK':
            pass  # Always send for blocks
        elif action_type == 'FLAG' and severity in ('high', 'critical'):
            pass  # Send for high-severity flags
        else:
            return

        # Rate limit firewall actions too
        source_ip = self._get_attr(action, 'source_ip')
        cooldown_key = f"firewall:{source_ip}"
        now = time.time()
        if cooldown_key in self._cooldown:
            if now - self._cooldown[cooldown_key] < 60:  # 1 minute for firewall
                return
        self._cooldown[cooldown_key] = now

        thread = threading.Thread(
            target=self._send_firewall_message,
            args=(action,),
            daemon=True,
        )
        thread.start()

    def _send_firewall_message(self, action):
        """Send a firewall block notification."""
        try:
            source_ip = self._get_attr(action, 'source_ip')
            attack_type = self._get_attr(action, 'attack_type')
            reason = self._get_attr(action, 'reason')
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            title = "🔥 <b>FIREWALL ACTION: BLOCKED</b> 🔥"
            if self._get_attr(action, 'action') == 'FLAG':
                title = "⚠️ <b>ACTION REQUIRED: RULE+ML THREAT FLAGGED</b> ⚠️"

            message = (
                f"{title}\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🚫 <b>Target IP:</b> <code>{source_ip}</code>\n"
                f"⚡ <b>Attack Type:</b> {attack_type}\n"
                f"📋 <b>Reason:</b> {reason}\n"
                f"⏰ <b>Time:</b> {now}\n"
                f"🛡️ <i>NetGuard Smart Firewall</i>"
            )

            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            data = urllib.parse.urlencode({
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
            }).encode('utf-8')

            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')

            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    self.stats['messages_sent'] += 1
                    self.stats['last_sent'] = time.time()

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[!] Telegram firewall alert error: {e}")

    def get_stats(self):
        """Get alerter statistics."""
        return dict(self.stats)
