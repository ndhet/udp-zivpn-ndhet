#!/bin/bash
# Install ZIVPN Menu + command "menu"

set -e

MENU_URL="https://raw.githubusercontent.com/ndhet/udp-zivpn-ndhet/main/zivpn-menu.sh"
MENU_PATH="/usr/bin/zivpn-menu"

CMD_URL="https://raw.githubusercontent.com/ndhet/udp-zivpn-ndhet/main/menu"
CMD_PATH="/usr/bin/menu"

echo "Installing ZIVPN Menu..."

# install main menu
curl -fsSL "$MENU_URL" -o "$MENU_PATH"
chmod +x "$MENU_PATH"

# install command: menu
curl -fsSL "$CMD_URL" -o "$CMD_PATH"
chmod +x "$CMD_PATH"

echo "=================================="
echo " ZIVPN MENU INSTALLED SUCCESSFULLY"
echo " Type command : menu"
echo "=================================="
