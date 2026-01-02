#!/bin/bash
#
# C-Sentinel Installation Script
# Installs sentinel as a systemd service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}C-Sentinel Installer${NC}"
echo "========================"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Check if binary exists
if [ ! -f "bin/sentinel" ]; then
    echo -e "${YELLOW}Building sentinel...${NC}"
    make clean && make
fi

# Create sentinel user if it doesn't exist
if ! id "sentinel" &>/dev/null; then
    echo -e "${YELLOW}Creating sentinel user...${NC}"
    useradd --system --no-create-home --shell /usr/sbin/nologin sentinel
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p /var/lib/sentinel
mkdir -p /etc/sentinel
chown sentinel:sentinel /var/lib/sentinel

# Install binary
echo -e "${YELLOW}Installing binary...${NC}"
cp bin/sentinel /usr/local/bin/sentinel
chmod 755 /usr/local/bin/sentinel

# Install config file template
if [ ! -f /etc/sentinel/config ]; then
    echo -e "${YELLOW}Installing default config...${NC}"
    cat > /etc/sentinel/config << 'EOF'
# C-Sentinel Configuration
# /etc/sentinel/config

# API Keys (can also use environment variables)
# anthropic_api_key = sk-ant-...
# openai_api_key = sk-...
ollama_host = http://localhost:11434

# Default AI model: claude, openai, or ollama
default_model = ollama
ollama_model = llama3.2:3b

# Thresholds
zombie_threshold = 0
high_fd_threshold = 100
unusual_port_threshold = 3
memory_warn_percent = 80.0
memory_crit_percent = 95.0

# Webhook (Slack-compatible)
# webhook_url = https://hooks.slack.com/services/...
webhook_on_critical = true
webhook_on_warning = false

# Watch mode defaults
default_interval = 300
network_by_default = true
EOF
    chown sentinel:sentinel /etc/sentinel/config
    chmod 600 /etc/sentinel/config
fi

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp deploy/sentinel.service /etc/systemd/system/sentinel.service
systemctl daemon-reload

echo
echo -e "${GREEN}Installation complete!${NC}"
echo
echo "Next steps:"
echo "  1. Edit config:        sudo nano /etc/sentinel/config"
echo "  2. Enable service:     sudo systemctl enable sentinel"
echo "  3. Start service:      sudo systemctl start sentinel"
echo "  4. Check status:       sudo systemctl status sentinel"
echo "  5. View logs:          sudo journalctl -u sentinel -f"
echo
echo "To learn baseline:       sudo -u sentinel /usr/local/bin/sentinel --learn --network"
echo
