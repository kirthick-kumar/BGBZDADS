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

# ── pip upgrade (user space only) ────────────────────────────
echo ""
echo "[2/5] Upgrading pip in user space..."
python3 -m pip install --upgrade pip --user
echo "[✓] pip upgraded"

# ── Add ~/.local/bin to PATH now so subsequent installs can find things ──
export PATH=$HOME/.local/bin:$PATH
export PYTHONPATH=$HOME/.local/lib/python3.9/site-packages:$PYTHONPATH

# ── PyTorch (CPU) ────────────────────────────────────────────
echo ""
echo "[3/5] Installing PyTorch (CPU build)..."
python3 -m pip install --user \
    torch \
    --index-url https://download.pytorch.org/whl/cpu
echo "[✓] PyTorch installed"

# ── torch-geometric (prebuilt wheels — no source build needed) ──
echo ""
echo "[4/5] Installing torch-geometric from prebuilt wheels..."

# Get torch version for wheel URL
TORCH_VER=$(python3 -c "import torch; print(torch.__version__.split('+')[0])")
echo "    Detected torch version: $TORCH_VER"

# Install torch-scatter + torch-sparse from PyG's own wheel server
# These are prebuilt so no source compilation, no torch import at build time
python3 -m pip install --user \
    torch-scatter \
    torch-sparse \
    -f https://data.pyg.org/whl/torch-${TORCH_VER}+cpu.html

# Install torch-geometric itself (pure Python, no build needed)
python3 -m pip install --user torch-geometric

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

# ── Persist PATH in ~/.bashrc ─────────────────────────────────
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
fi
grep -q "PYTHONPATH.*local/lib" ~/.bashrc 2>/dev/null || \
    echo 'export PYTHONPATH=$HOME/.local/lib/python3.9/site-packages:$PYTHONPATH' >> ~/.bashrc

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
