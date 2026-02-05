"""
Alert Manager - Multi-channel alerting system
Monitors threat events and sends notifications
"""
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict
import os

from channels.email import EmailChannel
from channels.telegram import TelegramChannel
from channels.slack import SlackChannel


class AlertManager:
    """
    Centralized alert management system
    
    Features:
    - Multi-channel notifications (Email, Telegram, Slack)
    - Severity-based routing
    - Rate limiting to prevent alert fatigue
    - Alert deduplication
    """
    
    def __init__(self):
        self.email_channel = EmailChannel()
        self.telegram_channel = TelegramChannel()
        self.slack_channel = SlackChannel()
        
        # Track recent alerts to prevent duplicates
        self.recent_alerts = {}
        self.alert_window = timedelta(minutes=5)
    
    async def process_event(self, event: Dict):
        """
        Process security event and determine if alert needed
        
        Args:
            event: Attack event with threat_score, src_ip, etc.
        """
        threat_score = event.get('threat_score', 0)
        src_ip = event.get('src_ip', 'unknown')
        
        # Check if we already alerted for this IP recently
        alert_key = f"{src_ip}_{event.get('eventid')}"
        if self._is_duplicate(alert_key):
            return
        
        # Determine severity
        severity = self._calculate_severity(threat_score)
        
        # Route based on severity
        if threat_score >= 90:
            # CRITICAL - All channels
            await self._send_critical_alert(event)
        elif threat_score >= 76:
            # HIGH - Email + Telegram
            await self._send_high_alert(event)
        elif threat_score >= 51:
            # MEDIUM - Email only
            await self._send_medium_alert(event)
        
        # Mark as alerted
        self.recent_alerts[alert_key] = datetime.utcnow()
    
    def _is_duplicate(self, alert_key: str) -> bool:
        """Check if we already sent this alert recently"""
        if alert_key in self.recent_alerts:
            last_alert = self.recent_alerts[alert_key]
            if datetime.utcnow() - last_alert < self.alert_window:
                return True
        return False
    
    def _calculate_severity(self, score: int) -> str:
        """Map threat score to severity level"""
        if score >= 76:
            return "CRITICAL" if score >= 90 else "HIGH"
        elif score >= 51:
            return "MEDIUM"
        elif score >= 26:
            return "LOW"
        return "INFO"
    
    async def _send_critical_alert(self, event: Dict):
        """Send critical alert to all channels"""
        message = self._format_alert_message(event, "CRITICAL")
        
        # Send to all channels in parallel
        await asyncio.gather(
            self.email_channel.send(message, priority="urgent"),
            self.telegram_channel.send(message),
            self.slack_channel.send(message, color="danger"),
            return_exceptions=True
        )
        
        print(f"🚨 CRITICAL ALERT sent for {event.get('src_ip')}")
    
    async def _send_high_alert(self, event: Dict):
        """Send high severity alert"""
        message = self._format_alert_message(event, "HIGH")
        
        await asyncio.gather(
            self.email_channel.send(message, priority="high"),
            self.telegram_channel.send(message),
            return_exceptions=True
        )
        
        print(f"⚠️  HIGH ALERT sent for {event.get('src_ip')}")
    
    async def _send_medium_alert(self, event: Dict):
        """Send medium severity alert"""
        message = self._format_alert_message(event, "MEDIUM")
        
        await self.email_channel.send(message, priority="normal")
        print(f"📧 MEDIUM ALERT sent for {event.get('src_ip')}")
    
    def _format_alert_message(self, event: Dict, severity: str) -> Dict:
        """Format event into alert message"""
        return {
            "severity": severity,
            "timestamp": event.get('@timestamp', datetime.utcnow().isoformat()),
            "attacker_ip": event.get('src_ip', 'unknown'),
            "country": event.get('geoip', {}).get('country_name', 'Unknown'),
            "attack_type": event.get('eventid', 'unknown'),
            "threat_score": event.get('threat_score', 0),
            "honeypot": event.get('honeypot_type', 'unknown'),
            "details": event.get('message', 'No details available'),
            "mitre_techniques": event.get('mitre_techniques', [])
        }
    
    async def cleanup_old_alerts(self):
        """Remove old alert keys to prevent memory growth"""
        cutoff = datetime.utcnow() - self.alert_window
        self.recent_alerts = {
            k: v for k, v in self.recent_alerts.items()
            if v > cutoff
        }


# Background task to monitor for threats
async def monitor_threats():
    """
    Background worker that monitors Elasticsearch for new threats
    and triggers alerts
    """
    from database.elasticsearch_client import get_es_client
    
    alert_manager = AlertManager()
    last_check = datetime.utcnow()
    
    while True:
        try:
            es = get_es_client()
            
            # Query for high-severity events since last check
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": last_check.isoformat()}}},
                            {"range": {"threat_score": {"gte": 51}}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "asc"}}]
            }
            
            result = await es.search(
                index="cowrie-*,dionaea-*,snort-*",
                body=query,
                size=100
            )
            
            # Process each event
            for hit in result["hits"]["hits"]:
                await alert_manager.process_event(hit["_source"])
            
            # Update last check time
            if result["hits"]["hits"]:
                last_check = datetime.fromisoformat(
                    result["hits"]["hits"][-1]["_source"]["@timestamp"]
                )
            else:
                last_check = datetime.utcnow()
            
            # Cleanup old alerts
            await alert_manager.cleanup_old_alerts()
            
            # Wait before next check
            await asyncio.sleep(30)  # Check every 30 seconds
            
        except Exception as e:
            print(f"Error in threat monitor: {e}")
            await asyncio.sleep(60)  # Wait longer on error


if __name__ == "__main__":
    print("🔔 Starting Alert Manager...")
    asyncio.run(monitor_threats())
