"""
Telegram Alert Channel
Sends notifications to Telegram bot
"""
import os
import aiohttp


class TelegramChannel:
    """Telegram notification channel"""
    
    def __init__(self):
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN', '')
        self.chat_id = os.getenv('TELEGRAM_CHAT_ID', '')
        self.enabled = bool(self.bot_token and self.chat_id)
        
        if self.enabled:
            self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
    
    async def send(self, alert: dict):
        """Send Telegram message"""
        if not self.enabled:
            print("⚠️  Telegram channel not configured (set TELEGRAM_* env vars)")
            return
        
        try:
            message = self._format_message(alert)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.api_url,
                    json={
                        'chat_id': self.chat_id,
                        'text': message,
                        'parse_mode': 'Markdown'
                    }
                ) as response:
                    if response.status == 200:
                        print("✅ Telegram message sent")
                    else:
                        print(f"❌ Telegram send failed: {await response.text()}")
                        
        except Exception as e:
            print(f"❌ Failed to send Telegram message: {e}")
    
    def _format_message(self, alert: dict) -> str:
        """Format Telegram message with Markdown"""
        emoji = {
            "CRITICAL": "🚨🚨🚨",
            "HIGH": "⚠️⚠️",
            "MEDIUM": "⚠️",
            "LOW": "ℹ️"
        }
        
        return f"""
{emoji.get(alert['severity'], '⚠️')} *{alert['severity']} SECURITY ALERT*

*Attacker IP:* `{alert['attacker_ip']}`
*Country:* {alert['country']}
*Attack Type:* {alert['attack_type']}
*Threat Score:* *{alert['threat_score']}/100*

*Honeypot:* {alert['honeypot']}
*Time:* {alert['timestamp']}

_Check dashboard for full details_
        """.strip()
