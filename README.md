# 🛡️ HoneyNet - Real-Time Cyber Threat Intelligence Platform

I built a system that captures actual hackers attacking fake servers and shows where they're from, what they're trying to do, and how dangerous they are. All visualized on a live dashboard.

## What Does This Do?

**Simple version:** Sets up "honeypot" servers that look vulnerable. When hackers attack them, I capture everything - their location, techniques, commands typed, malware uploaded. Then I display it all on a real-time map and dashboard.

**Technical version:** Distributed honeypot network with automated threat intelligence pipeline. Captures attacks via Cowrie (SSH), Dionaea (SMB/FTP/HTTP), and Snort (IDS). Processes logs through ELK stack with GeoIP enrichment and MITRE ATT&CK mapping. Serves analytics via FastAPI backend to React dashboard.

## Why Did I Build This?

To learn how real cyber attacks work and build a complete security monitoring system from scratch. After deploying this on AWS, I captured **300+ attacks in 24 hours** from hackers worldwide trying to break in.

## Tech Stack

**Honeypots & Detection:**
- Cowrie - Fake SSH server that logs login attempts and commands  
- Dionaea - Emulates FTP, HTTP, SMB, MySQL to catch malware  
- Snort - Network intrusion detection system

**Data Pipeline:**
- Filebeat → Logstash → Elasticsearch (ELK stack)
- Automatic GeoIP location lookup (IP → Country/City)
- MITRE ATT&CK technique classification
- Threat scoring algorithm (0-100 scale)

**Application:**
- Backend: Python FastAPI (REST API)
- Frontend: React + Vite (real-time dashboard)
- Databases: PostgreSQL, MongoDB, Redis
- Infrastructure: Docker (13 containers), Nginx, AWS EC2

## Features

✅ **Live Attack Map** - See attacks happening on a world map with pins  
✅ **Real-Time Feed** - Watch hackers trying to break in as it happens  
✅ **Geographic Tracking** - Know exactly where attacks are coming from  
✅ **Attack Analysis** - See what commands hackers are typing, what they're looking for  
✅ **Threat Scoring** - Automatic danger level calculation  
✅ **Auto-Refresh Dashboard** - Updates every 10-30 seconds  

## Quick Start

```bash
# 1. Clone and enter directory
git clone https://github.com/bashSunny101/VulnServer.git
cd VulnServer

# 2. Start everything (13 containers)
docker-compose up -d

# 3. Wait 2 minutes, then open dashboard
# http://localhost:3000 - Main dashboard
# http://localhost:8000 - API endpoints
# http://localhost:5601 - Kibana (optional)
```

## Test It Out

Attack your own honeypot to see it working:

```bash
# Try to "hack" your SSH honeypot
ssh root@localhost -p 2222
# (Try any password, type some commands)

# Wait 10 seconds, refresh dashboard - you'll see your attack appear!
```

## What I Learned

**DevOps Skills:**
- Orchestrating 13+ Docker containers
- ELK stack configuration and log parsing  
- Production deployment on AWS with security groups

**Security Concepts:**
- How real attacks happen (brute force, scanning, exploitation)
- MITRE ATT&CK framework for classifying threats
- Network traffic analysis and intrusion detection

**Full-Stack Development:**
- Built async REST API with Python FastAPI
- Created real-time React dashboard with auto-refresh
- Integrated multiple databases (SQL, NoSQL, cache)

## Architecture

```
Hacker Attack → Honeypot → Logs → Filebeat → Logstash (adds location data) 
→ Elasticsearch (stores everything) → Backend API → React Dashboard (you see it)
```

## Sample Results

After 24 hours live on the internet:
- 🎯 **362 total attacks** captured
- 🌍 Attacks from **India, USA, Russia** (and counting)
- 🔐 **150+ SSH login attempts** with various passwords
- 🗺️ All mapped on dashboard with exact locations

## License

MIT - Do whatever you want with it

## Author

Built by **Sunny** to learn cybersecurity and full-stack development

GitHub: [@bashSunny101](https://github.com/bashSunny101)

---

⭐ **Star this repo** if you find it interesting! Every star motivates me to keep learning.

*Deployed on AWS EC2. Capturing real attacks 24/7.*
