# ========================================
# Filebeat Dockerfile
# ========================================
# LEARNING: Filebeat is a lightweight log shipper
# It tails log files and sends them to Logstash/Elasticsearch
#
# Why Filebeat instead of direct logging?
# - Decoupling: Services don't need to know about Elasticsearch
# - Resilience: Buffers data if destination is unavailable
# - Efficiency: More lightweight than Logstash on each host
# ========================================

FROM docker.elastic.co/beats/filebeat:8.11.0

# Copy configuration
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# Set proper permissions
USER root
RUN chown root:filebeat /usr/share/filebeat/filebeat.yml && \
    chmod 640 /usr/share/filebeat/filebeat.yml

# Switch back to filebeat user
USER filebeat

# ========================================
# LEARNING: Filebeat Architecture
# ========================================
# Filebeat has three main components:
#
# 1. Inputs: What to monitor
#    - Log files
#    - Docker containers
#    - System logs
#
# 2. Processors: How to transform
#    - Add fields
#    - Drop events
#    - Parse JSON
#
# 3. Outputs: Where to send
#    - Logstash (for further processing)
#    - Elasticsearch (direct indexing)
#    - Redis (buffering)
# ========================================
