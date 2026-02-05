# ========================================
# Dionaea Dockerfile
# ========================================
# LEARNING: Dionaea is a low-interaction honeypot
# that captures malware by emulating vulnerable services
#
# It's particularly good at catching:
# - SMB/CIFS worms (like WannaCry, NotPetya)
# - HTTP exploit attempts
# - FTP malware distribution
# - MSSQL attacks
# ========================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
# LEARNING: Dionaea needs these for protocol emulation
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-dev \
    python3-pip \
    libglib2.0-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libreadline-dev \
    libsqlite3-dev \
    python3-sqlite \
    libemu-dev \
    libev-dev \
    libudns-dev \
    libgc-dev \
    libpcap-dev \
    libnl-genl-3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create dionaea user
RUN useradd -r -s /bin/false dionaea

# Clone and build dionaea
WORKDIR /opt
RUN git clone https://github.com/DinoTools/dionaea.git && \
    cd dionaea && \
    git checkout 0.11.0

WORKDIR /opt/dionaea

# Build dionaea
RUN mkdir build && \
    cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea .. && \
    make && \
    make install

# Create necessary directories
RUN mkdir -p /opt/dionaea/var/dionaea/bistreams \
    /opt/dionaea/var/dionaea/binaries \
    /opt/dionaea/var/dionaea/log \
    /opt/dionaea/var/dionaea/rtp && \
    chown -R dionaea:dionaea /opt/dionaea/var

# Copy configuration
COPY dionaea.cfg /opt/dionaea/etc/dionaea/dionaea.cfg

# Set ownership
RUN chown -R dionaea:dionaea /opt/dionaea

# Switch to dionaea user
USER dionaea

# Expose vulnerable service ports
# LEARNING: These are the services Dionaea emulates
# FTP
EXPOSE 20 21
# HTTP/HTTPS
EXPOSE 80 443
# SMB
EXPOSE 445
# MSSQL
EXPOSE 1433
# MySQL
EXPOSE 3306
# SIP
EXPOSE 5060
# TFTP
EXPOSE 69

# Start dionaea
CMD ["/opt/dionaea/bin/dionaea", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg", "-l", "all,-debug", "-L", "*"]

# ========================================
# LEARNING: What Makes Dionaea Special?
# ========================================
# 1. Protocol Emulation: Responds realistically to exploit attempts
# 2. Shellcode Detection: Uses libemu to detect and analyze shellcode
# 3. Malware Capture: Downloads and stores malware payloads
# 4. Multiple Services: One container emulates many vulnerable services
# 5. Low Resource: Doesn't execute code, just logs and captures
#
# Real-world example:
# - Attacker scans for SMB (port 445)
# - Dionaea responds as vulnerable Windows SMB
# - Attacker sends EternalBlue exploit
# - Dionaea captures the payload
# - Malware is stored for analysis
# - We have a sample without running it!
# ========================================
