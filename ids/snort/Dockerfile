# ========================================
# Snort IDS Dockerfile
# ========================================
# LEARNING: Snort is a signature-based network IDS
# It analyzes packets in real-time and matches them
# against a database of attack signatures
#
# Why Snort?
# - Industry standard (used by Fortune 500)
# - Large community rule database
# - Can write custom rules for our environment
# - Real-time detection vs log analysis
# ========================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    libpcre3-dev \
    libdumbnet-dev \
    zlib1g-dev \
    liblzma-dev \
    openssl \
    libssl-dev \
    libnghttp2-dev \
    wget \
    git \
    autoconf \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install DAQ (Data Acquisition library)
# LEARNING: DAQ is Snort's packet capture abstraction layer
WORKDIR /tmp
RUN wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz && \
    tar xvfz daq-2.0.7.tar.gz && \
    cd daq-2.0.7 && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Install Snort
RUN wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz && \
    tar xvfz snort-2.9.20.tar.gz && \
    cd snort-2.9.20 && \
    ./configure --enable-sourcefire && \
    make && \
    make install && \
    ldconfig

# Create snort user and directories
RUN groupadd snort && \
    useradd -r -s /bin/false -g snort snort && \
    mkdir -p /etc/snort/rules /var/log/snort /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort/preproc_rules /etc/snort/so_rules

# Set ownership
RUN chown -R snort:snort /etc/snort /var/log/snort /usr/local/lib/snort_dynamicrules

# Copy configuration files
COPY snort.conf /etc/snort/snort.conf
COPY rules/ /etc/snort/rules/

# Download community rules
# LEARNING: Community rules are free, frequently updated signatures
WORKDIR /tmp
RUN wget https://www.snort.org/downloads/community/community-rules.tar.gz && \
    tar -xvzf community-rules.tar.gz && \
    cp community-rules/*.rules /etc/snort/rules/ || true && \
    chown -R snort:snort /etc/snort/rules

# Set ownership
RUN chown -R snort:snort /etc/snort /var/log/snort

# Switch to snort user
USER snort

# Entrypoint
CMD ["/usr/local/bin/snort", "-c", "/etc/snort/snort.conf", "-i", "eth0", "-A", "full", "-l", "/var/log/snort"]

# ========================================
# LEARNING: Snort Detection Modes
# ========================================
# Snort can run in three modes:
#
# 1. Sniffer Mode (-v): Just displays packets
#    Example: snort -v -i eth0
#
# 2. Packet Logger Mode (-l): Logs packets to disk
#    Example: snort -l /var/log/snort -i eth0
#
# 3. NIDS Mode (-c): Full IDS with rule matching
#    Example: snort -c snort.conf -i eth0 -A full
#
# We use NIDS mode with:
# -c: Configuration file
# -i: Interface to monitor
# -A full: Full alert mode (detailed logs)
# -l: Log directory
# ========================================
