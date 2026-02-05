# ========================================
# Cowrie Dockerfile
# ========================================
# LEARNING NOTE: This creates a containerized SSH/Telnet honeypot
#
# Why Alpine Linux?
# - Minimal attack surface (small image size)
# - Faster builds and deployments
# - Security-focused distribution
#
# Multi-stage builds would further reduce image size,
# but we keep it simple for learning purposes
# ========================================

FROM python:3.11-slim

# Install system dependencies
# LEARNING: Cowrie needs these libraries for SSH protocol handling
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    python3-pip \
    authbind \
    && rm -rf /var/lib/apt/lists/*
# LEARNING: We clean apt cache to reduce image size

# Create cowrie user
# LEARNING: Never run services as root - principle of least privilege
RUN useradd -r -s /bin/false cowrie

# Set working directory
WORKDIR /cowrie

# Clone Cowrie repository
# LEARNING: We use a specific version for reproducibility
RUN git clone https://github.com/cowrie/cowrie.git /cowrie && \
    git checkout v2.5.0
# LEARNING: In production, pin to specific commit hash

# Install Python dependencies
RUN pip install --no-cache-dir -r /cowrie/requirements.txt
# LEARNING: --no-cache-dir reduces image size by not storing pip cache

# Create necessary directories
RUN mkdir -p /cowrie/var/log/cowrie \
    /cowrie/var/lib/cowrie/downloads \
    /cowrie/var/lib/cowrie/tty && \
    chown -R cowrie:cowrie /cowrie

# Copy configuration file
COPY cowrie.cfg /cowrie/etc/cowrie.cfg
COPY userdb.txt /cowrie/etc/userdb.txt

# Set ownership
RUN chown cowrie:cowrie /cowrie/etc/cowrie.cfg /cowrie/etc/userdb.txt

# Switch to cowrie user
USER cowrie

# Expose ports
# LEARNING: Cowrie listens on 2222/2223 by default (non-privileged ports)
# In production, use iptables REDIRECT to forward 22→2222
EXPOSE 2222 2223

# Set entrypoint
CMD ["/cowrie/bin/cowrie", "start", "-n"]
# LEARNING: -n flag runs in foreground (required for Docker)
