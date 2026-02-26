#!/bin/bash
# ============================================================
# Package Installer — Amazon Linux 2023 (yum)
# Run as ec2-user: bash install_packages.sh
# ============================================================
set -e

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector — Package Installer"
echo " Amazon Linux 2023 / yum"
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
    net-tools \
    nmap \
    nmap-ncat \
    telnet \
    iptables \
    iptables-services \
    rsyslog

echo "[✓] System packages installed"

# ── pip upgrade (user space only — avoids rpm-managed pip conflict) ──
echo ""
echo "[2/5] Upgrading pip in user space..."
python3 -m pip install --upgrade pip --user
echo "[✓] pip upgraded"

# ── PyTorch (CPU) ────────────────────────────────────────────
echo ""
echo "[3/5] Installing PyTorch (CPU build)..."
python3 -m pip install --user \
    torch \
    --index-url https://download.pytorch.org/whl/cpu
echo "[✓] PyTorch installed"

# ── torch-geometric + deps ───────────────────────────────────
echo ""
echo "[4/5] Installing torch-geometric and dependencies..."
python3 -m pip install --user \
    torch-scatter \
    torch-sparse \
    torch-geometric
echo "[✓] torch-geometric installed"

# ── Python application packages ──────────────────────────────
echo ""
echo "[5/5] Installing Python application packages..."
python3 -m pip install --user \
    websockets \
    aiohttp \
    aiohttp-cors \
    scikit-learn \
    joblib \
    numpy \
    pandas
echo "[✓] Application packages installed"

# ── Add ~/.local/bin to PATH if not already there ────────────
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
    export PATH=$HOME/.local/bin:$PATH
    echo "[✓] Added ~/.local/bin to PATH"
fi

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
