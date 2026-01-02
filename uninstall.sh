#!/bin/bash
#
# C-Sentinel Uninstall Script
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}C-Sentinel Uninstaller${NC}"
echo "========================"
echo

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo ./uninstall.sh)${NC}"
    exit 1
fi

# Stop and disable service
echo -e "${YELLOW}Stopping service...${NC}"
systemctl stop sentinel 2>/dev/null || true
systemctl disable sentinel 2>/dev/null || true

# Remove systemd service
echo -e "${YELLOW}Removing systemd service...${NC}"
rm -f /etc/systemd/system/sentinel.service
systemctl daemon-reload

# Remove binary
echo -e "${YELLOW}Removing binary...${NC}"
rm -f /usr/local/bin/sentinel

# Ask about config and data
echo
read -p "Remove config files in /etc/sentinel? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/sentinel
    echo "Config removed."
fi

read -p "Remove data in /var/lib/sentinel? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /var/lib/sentinel
    echo "Data removed."
fi

read -p "Remove sentinel user? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    userdel sentinel 2>/dev/null || true
    echo "User removed."
fi

echo
echo -e "${GREEN}Uninstall complete.${NC}"
