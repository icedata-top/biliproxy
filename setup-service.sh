#!/bin/bash

# Setup script for Bilibili Proxy systemd service

set -e

echo "🚀 Setting up Bilibili Proxy systemd service..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run this script as root or with sudo"
    exit 1
fi

# Create nodejs user if it doesn't exist
if ! id -u nodejs > /dev/null 2>&1; then
    echo "👤 Creating nodejs user..."
    useradd --system --home /opt/biliproxyjs --shell /bin/false nodejs
    echo "✅ nodejs user created"
else
    echo "✅ nodejs user already exists"
fi

# Set correct ownership and permissions
echo "🔒 Setting ownership and permissions..."
chown -R nodejs:nodejs /opt/biliproxyjs
chmod 755 /opt/biliproxyjs
chmod 644 /opt/biliproxyjs/*.js
chmod 644 /opt/biliproxyjs/package.json
chmod 600 /opt/biliproxyjs/.env

# Copy service file
echo "📋 Installing systemd service..."
cp biliproxy.service /etc/systemd/system/

# Reload systemd
echo "🔄 Reloading systemd..."
systemctl daemon-reload

# Enable the service
echo "⚡ Enabling service..."
systemctl enable biliproxy.service

# Start the service
echo "🎯 Starting service..."
systemctl start biliproxy.service

# Check status
echo ""
echo "📊 Service status:"
systemctl status biliproxy.service --no-pager

echo ""
echo "✅ Setup complete!"
echo ""
echo "Service management commands:"
echo "  Start:   sudo systemctl start biliproxy"
echo "  Stop:    sudo systemctl stop biliproxy"
echo "  Restart: sudo systemctl restart biliproxy"
echo "  Status:  sudo systemctl status biliproxy"
echo "  Logs:    sudo journalctl -u biliproxy -f"
echo ""
echo "🌐 Your Bilibili proxy should now be running on:"
echo "   http://localhost:3000"
