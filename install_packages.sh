#!/bin/bash
# ============================================================
# Package Installer — Amazon Linux (yum)
# Run as ec2-user: bash install_packages.sh
# ============================================================
set -e

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector — Package Installer"
echo " Amazon Linux / yum"
echo "═══════════════════════════════════════════════════════"

# ── System packages ──────────────────────────────────────────
echo ""
echo "[1/5] Installing system packages via yum..."
sudo yum update -y

sudo yum install -y \
    python3 \
    python3-pip \
    python3-devel \
    git \
    gcc \
    gcc-c++ \
    make \
    openssl-devel \
    libffi-devel \
    bzip2-devel \
    wget \
    curl \
    net-tools \
    nmap \
    telnet \
    nc \
    iptables \
    iptables-services \
    rsyslog

echo "[✓] System packages installed"

# ── pip upgrade ──────────────────────────────────────────────
echo ""
echo "[2/5] Upgrading pip..."
sudo pip3 install --upgrade pip
echo "[✓] pip upgraded"

# ── PyTorch (CPU) ────────────────────────────────────────────
echo ""
echo "[3/5] Installing PyTorch (CPU build)..."
pip3 install --user \
    torch \
    --index-url https://download.pytorch.org/whl/cpu
echo "[✓] PyTorch installed"

# ── torch-geometric + deps ───────────────────────────────────
echo ""
echo "[4/5] Installing torch-geometric and dependencies..."
pip3 install --user \
    torch-scatter \
    torch-sparse \
    torch-geometric
echo "[✓] torch-geometric installed"

# ── Python application packages ──────────────────────────────
echo ""
echo "[5/5] Installing Python application packages..."
pip3 install --user \
    websockets \
    aiohttp \
    aiohttp-cors \
    scikit-learn \
    joblib \
    numpy \
    pandas
echo "[✓] Application packages installed"

# ── Verify ───────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo " Verifying installs..."
echo "═══════════════════════════════════════════════════════"

python3 -c "import torch;           print(f'  ✓  torch          {torch.__version__}')"
python3 -c "import torch_geometric; print(f'  ✓  torch_geometric {torch_geometric.__version__}')"
python3 -c "import websockets;      print(f'  ✓  websockets      {websockets.__version__}')"
python3 -c "import aiohttp;         print(f'  ✓  aiohttp         {aiohttp.__version__}')"
python3 -c "import sklearn;         print(f'  ✓  scikit-learn    {sklearn.__version__}')"
python3 -c "import numpy;           print(f'  ✓  numpy           {numpy.__version__}')"
python3 -c "import joblib;          print(f'  ✓  joblib          {joblib.__version__}')"

echo ""
echo "═══════════════════════════════════════════════════════"
echo " All packages installed. Next steps:"
echo "   bash setup_iptables.sh"
echo "   bash setup_aws.sh"
echo "═══════════════════════════════════════════════════════"
