#!/bin/bash

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo "Node.js not found. Installing..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    apt-get install -y nodejs
fi

# Go to api directory
cd "$(dirname "$0")"

# Install dependencies
echo "Installing dependencies..."
npm install

# Setup Systemd Service
echo "Setting up Systemd service..."
cp zivpn-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable zivpn-api
systemctl restart zivpn-api

echo "ZIVPN API Installed and Started on port 5888"
