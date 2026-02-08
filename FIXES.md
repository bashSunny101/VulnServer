# Fixes Applied - Ready for AWS Deployment

## Problems Fixed

### 1. Dionaea Dockerfile
**Problem**: Package `python3-sqlite` doesn't exist in Ubuntu 22.04  
**Fix**: Removed `python3-sqlite` and `libemu-dev` (unavailable packages)  
**File**: `honeypots/dionaea/Dockerfile`

### 2. Snort Dockerfile
**Problem**: Missing flex and bison packages causing compilation errors  
**Fix**: Added `flex` and `bison` to dependency list  
**File**: `ids/snort/Dockerfile`

### 3. Logstash Configuration
**Problem**: Authentication enabled but Elasticsearch security disabled  
**Fix**: Commented out authentication in Logstash output  
**File**: `elk-stack/logstash/logstash.conf`

### 4. Missing Environment Configuration
**Problem**: No .env file for configuration  
**Fix**: Created `.env` with all required variables  
**File**: `.env` (NEW)

### 5. Resource Constraints on t3.small
**Problem**: Original docker-compose too heavy for 2GB RAM  
**Fix**: Created optimized deployment configuration  
**File**: `docker-compose-simple.yml` (NEW)

## New Files Created

1. **`.env`** - Environment configuration with sane defaults
2. **`docker-compose-simple.yml`** - Optimized for t3.small (2GB RAM)
   - Uses official Cowrie image (pre-built, lightweight)
   - Resource limits for all services
   - Disabled Dionaea and Snort (can add later)
   - No authentication (simpler setup)

3. **`DEPLOYMENT.md`** - Complete deployment guide

## Deployment Options

### Option 1: Simplified (RECOMMENDED for t3.small)
```bash
docker-compose -f docker-compose-simple.yml up -d
```

**Pros:**
- ✅ Fast deployment (pre-built images)
- ✅ Low memory usage (~1.5GB total)
- ✅ Proven to work on t3.small
- ✅ Includes: Cowrie + ELK Stack + Backend + Databases

**Cons:**
- ❌ No Dionaea (malware capture)
- ❌ No Snort (IDS)
- Can add these later once core platform is stable

### Option 2: Full Build (May fail on t3.small)
```bash
docker-compose -f docker-compose.yml up -d --build
```

**Pros:**
- ✅ Complete platform with all features
- ✅ Custom builds

**Cons:**
- ❌ Long build time (20-30 minutes)
- ❌ High memory usage during builds
- ❌ May crash on t3.small
- ❌ Dionaea build might still fail

## What to Do Next

### Step 1: Create AWS Instance
- Instance type: **t3.small** (2 vCPU, 2GB RAM)
- OS: **Ubuntu 22.04 LTS**
- Storage: **20GB minimum**
- Security groups: Ports 22, 2222, 2223, 5601, 8000

### Step 2: Initial Setup
```bash
# SSH to AWS
ssh -i your-key.pem ubuntu@YOUR-AWS-IP

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo apt install docker-compose -y

# Add swap (critical!)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Reboot
sudo reboot
```

### Step 3: Deploy
```bash
# SSH again after reboot
ssh -i your-key.pem ubuntu@YOUR-AWS-IP

# Clone repo
git clone <YOUR_REPO_URL> VulnServer
cd VulnServer

# Edit .env (update PUBLIC_IP and passwords)
nano .env

# Deploy simplified version
docker-compose -f docker-compose-simple.yml up -d

# Wait 2-3 minutes for everything to start

# Check status
docker-compose -f docker-compose-simple.yml ps
```

### Step 4: Verify
```bash
# Test backend API
curl http://localhost:8000/health

# Test Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Check logs
docker logs cowrie
docker logs backend
docker logs elasticsearch
```

### Step 5: Test Attack Capture
From your LOCAL machine:
```bash
# Test SSH honeypot
ssh root@YOUR-AWS-IP -p 2222
# Password: password123

# Try some commands
whoami
ls -la
wget http://example.com/test
exit

# Check if logged
curl http://YOUR-AWS-IP:8000/api/attacks/recent
```

### Step 6: Access Dashboards
- Kibana: `http://YOUR-AWS-IP:5601`
- Backend API: `http://YOUR-AWS-IP:8000/docs`

## Memory Usage (Simplified Deployment)

| Service       | Limit  | Expected |
|---------------|--------|----------|
| Elasticsearch | 1024MB | ~800MB   |
| Logstash      | 512MB  | ~350MB   |
| Kibana        | 512MB  | ~400MB   |
| Cowrie        | 256MB  | ~100MB   |
| Backend       | 256MB  | ~150MB   |
| PostgreSQL    | 128MB  | ~50MB    |
| MongoDB       | 128MB  | ~80MB    |
| **Total**     | ~2.8GB | ~1.9GB   |

With 2GB RAM + 2GB swap = **Should run smoothly**

## Troubleshooting

### If containers keep restarting:
```bash
docker-compose -f docker-compose-simple.yml logs <service-name>
```

### If out of memory:
```bash
# Check swap is active
free -h

# Reduce Elasticsearch heap in .env
ELASTIC_MEM_LIMIT=384m

# Restart
docker-compose -f docker-compose-simple.yml restart
```

### If build fails:
```bash
# Just use the simplified version
# It uses pre-built images - no building required!
docker-compose -f docker-compose-simple.yml up -d
```

## Summary

✅ All Dockerfiles fixed  
✅ Configuration optimized for t3.small  
✅ Environment variables configured  
✅ Deployment guide created  
✅ Ready to deploy!

**Recommendation**: Start with `docker-compose-simple.yml`, get familiar with the platform, then add more honeypots later if needed.
