"""
Slack Alert Channel
Sends notifications to Slack workspace
"""
import os
import aiohttp


class SlackChannel:
    """Slack notification channel"""
    
    def __init__(self):
        self.webhook_url = os.getenv('SLACK_WEBHOOK_URL', '')
        self.enabled = bool(self.webhook_url)
    
    async def send(self, alert: dict, color: str = "warning"):
        """Send Slack message"""
        if not self.enabled:
            print("⚠️  Slack channel not configured (set SLACK_WEBHOOK_URL)")
            return
        
        try:
            payload = self._format_payload(alert, color)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 200:
                        print("✅ Slack message sent")
                    else:
                        print(f"❌ Slack send failed: {await response.text()}")
                        
        except Exception as e:
            print(f"❌ Failed to send Slack message: {e}")
    
    def _format_payload(self, alert: dict, color: str) -> dict:
        """Format Slack message payload"""
        color_map = {
            "danger": "#DC2626",  # Red for critical
            "warning": "#EA580C",  # Orange for high
            "good": "#16A34A"      # Green for resolved
        }
        
        return {
            "attachments": [
                {
                    "color": color_map.get(color, "#D97706"),
                    "title": f"{alert['severity']} Security Alert",
                    "text": f"Attack detected from `{alert['attacker_ip']}`",
                    "fields": [
                        {
                            "title": "Attacker IP",
                            "value": alert['attacker_ip'],
                            "short": True
                        },
                        {
                            "title": "Country",
                            "value": alert['country'],
                            "short": True
                        },
                        {
                            "title": "Attack Type",
                            "value": alert['attack_type'],
                            "short": True
                        },
                        {
                            "title": "Threat Score",
                            "value": f"{alert['threat_score']}/100",
                            "short": True
                        },
                        {
                            "title": "Honeypot",
                            "value": alert['honeypot'],
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": alert['timestamp'],
                            "short": True
                        }
                    ],
                    "footer": "HoneyNet Intelligence Platform",
                    "ts": alert.get('timestamp_unix', 0)
                }
            ]
        }
