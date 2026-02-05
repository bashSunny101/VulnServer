"""
Email Alert Channel
Sends email notifications for security alerts
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


class EmailChannel:
    """Email notification channel"""
    
    def __init__(self):
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.from_email = os.getenv('ALERT_FROM_EMAIL', self.smtp_user)
        self.to_emails = os.getenv('ALERT_TO_EMAILS', '').split(',')
        
        self.enabled = bool(self.smtp_user and self.smtp_password)
    
    async def send(self, alert: dict, priority: str = "normal"):
        """Send email alert"""
        if not self.enabled:
            print("⚠️  Email channel not configured (set SMTP_* env vars)")
            return
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = self._format_subject(alert, priority)
            
            # Create HTML body
            body = self._format_html_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            print(f"✅ Email sent to {', '.join(self.to_emails)}")
            
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
    
    def _format_subject(self, alert: dict, priority: str) -> str:
        """Format email subject"""
        emoji = "🚨" if alert['severity'] == "CRITICAL" else "⚠️"
        return f"{emoji} [{alert['severity']}] HoneyNet Alert - {alert['attacker_ip']}"
    
    def _format_html_body(self, alert: dict) -> str:
        """Format HTML email body"""
        severity_color = {
            "CRITICAL": "#DC2626",
            "HIGH": "#EA580C",
            "MEDIUM": "#D97706",
            "LOW": "#16A34A"
        }
        
        color = severity_color.get(alert['severity'], "#6B7280")
        
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <div style="background-color: {color}; color: white; padding: 15px; border-radius: 5px;">
                <h2 style="margin: 0;">{alert['severity']} SECURITY ALERT</h2>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #F3F4F6; border-radius: 5px;">
                <h3>Attack Details</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Timestamp:</td>
                        <td style="padding: 8px;">{alert['timestamp']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Attacker IP:</td>
                        <td style="padding: 8px; font-family: monospace;">{alert['attacker_ip']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Country:</td>
                        <td style="padding: 8px;">{alert['country']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Attack Type:</td>
                        <td style="padding: 8px;">{alert['attack_type']}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Threat Score:</td>
                        <td style="padding: 8px;"><strong>{alert['threat_score']}/100</strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold;">Honeypot:</td>
                        <td style="padding: 8px;">{alert['honeypot']}</td>
                    </tr>
                </table>
            </div>
            
            <div style="margin-top: 20px; padding: 15px; background-color: #FEF3C7; border-radius: 5px;">
                <h3>Details</h3>
                <p>{alert['details']}</p>
            </div>
            
            {self._format_mitre_section(alert)}
            
            <div style="margin-top: 30px; padding: 15px; background-color: #DBEAFE; border-radius: 5px;">
                <h3>Recommended Actions</h3>
                <ul>
                    <li>Review full attack session in Kibana</li>
                    <li>Check if attacker IP is in threat intelligence feeds</li>
                    <li>Consider blocking IP at firewall level</li>
                    <li>Document findings for incident report</li>
                </ul>
            </div>
            
            <p style="margin-top: 20px; color: #6B7280; font-size: 12px;">
                This is an automated alert from HoneyNet Intelligence Platform
            </p>
        </body>
        </html>
        """
    
    def _format_mitre_section(self, alert: dict) -> str:
        """Format MITRE ATT&CK section"""
        techniques = alert.get('mitre_techniques', [])
        if not techniques:
            return ""
        
        return f"""
        <div style="margin-top: 20px; padding: 15px; background-color: #FEE2E2; border-radius: 5px;">
            <h3>MITRE ATT&CK Techniques</h3>
            <ul>
                {''.join([f'<li>{t}</li>' for t in techniques])}
            </ul>
        </div>
        """
