#!/bin/bash

# Mauritania Eye - Hypervision Mode Installation Script
# Author: Mohamed Lemine Ahmed Jidou 🇲🇷

echo "🌐🧿 Mauritania Eye - Hypervision Mode Installation"
echo "Professional Network Intelligence Framework"
echo "Author: Mohamed Lemine Ahmed Jidou 🇲🇷"
echo "=================================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "⚠️  This script should not be run as root for security reasons"
   echo "Run without sudo, but ensure your user has sudo privileges"
   exit 1
fi

# Check if running on Kali Linux
if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    echo "⚠️  Warning: This script is optimized for Kali Linux"
    echo "Some tools may not be available on other distributions"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update system packages
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv

# Install network security tools
echo "🔧 Installing network security tools..."
sudo apt install -y \
    nmap \
    nikto \
    wireshark \
    tshark \
    netdata \
    ntopng \
    kismet \
    macchanger \
    whois \
    geoip-bin \
    geoip-database \
    tcpdump \
    net-tools \
    iproute2

# Create virtual environment
echo "🏗️  Creating Python virtual environment..."
python3 -m venv mauritania_eye_env
source mauritania_eye_env/bin/activate

# Install Python packages
echo "📚 Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Set up permissions for packet capture
echo "🔐 Setting up packet capture permissions..."
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Create logs directory
echo "📁 Creating logs directory..."
mkdir -p logs/{reports,packets,alerts,sessions}

# Make main script executable
chmod +x mauritania_eye.py

# Create desktop shortcut (optional)
if command -v desktop-file-install &> /dev/null; then
    echo "🖥️  Creating desktop shortcut..."
    cat > mauritania-eye.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Mauritania Eye - Hypervision Mode
Comment=Professional Network Intelligence Framework
Exec=$(pwd)/mauritania_eye_env/bin/python $(pwd)/mauritania_eye.py
Icon=network-workgroup
Terminal=true
Categories=Network;Security;
EOF
    
    desktop-file-install --dir=$HOME/.local/share/applications mauritania-eye.desktop
    rm mauritania-eye.desktop
fi

# Create activation script
echo "📝 Creating activation script..."
cat > activate_mauritania_eye.sh << 'EOF'
#!/bin/bash
echo "🌐🧿 Activating Mauritania Eye - Hypervision Mode"
source mauritania_eye_env/bin/activate
echo "✅ Virtual environment activated"
echo "Run: python3 mauritania_eye.py --help"
EOF

chmod +x activate_mauritania_eye.sh

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "🚀 To get started:"
echo "1. Activate the environment: source activate_mauritania_eye.sh"
echo "2. Run Mauritania Eye: python3 mauritania_eye.py --help"
echo ""
echo "📖 Usage examples:"
echo "   python3 mauritania_eye.py --auto                    # Full automated scan"
echo "   python3 mauritania_eye.py --manual                  # Interactive mode"
echo "   python3 mauritania_eye.py --auto --target 192.168.1.0/24  # Scan specific network"
echo ""
echo "⚠️  Note: Some features require root privileges"
echo "   Run with sudo for full functionality"
echo ""
echo "🌐🧿 Mauritania Eye - Hypervision Mode is ready!"