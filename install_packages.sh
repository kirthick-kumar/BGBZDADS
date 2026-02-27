#!/bin/bash
# ============================================================
# Step 1: Package Installer — Amazon Linux 2023
# Run: bash install_packages.sh
# NOTE: curl excluded — curl-minimal pre-installed on AL2023
# ============================================================
set -e

echo "═══════════════════════════════════════════════════════"
echo " GCN Probe Detector — Package Installer"
echo "═══════════════════════════════════════════════════════"

echo "[1/5] Installing system packages..."
sudo yum install -y \
    python3 \
    python3-pip \
    python3-devel \
    python3.11 \
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
    rsyslog \
    nginx
echo "[✓] System packages done"

echo "[2/5] Upgrading pip (user space only — avoids rpm conflict)..."
python3 -m pip install --upgrade pip --user
echo "[✓] pip upgraded"

echo "[3/5] Installing PyTorch CPU..."
export PATH=$HOME/.local/bin:$PATH
export PYTHONPATH=$HOME/.local/lib/python3.9/site-packages:$PYTHONPATH
python3 -m pip install --user torch --index-url https://download.pytorch.org/whl/cpu
echo "[✓] PyTorch installed"

echo "[4/5] Installing torch-geometric (prebuilt wheels — no source build)..."
TORCH_VER=$(python3 -c "import torch; print(torch.__version__.split('+')[0])")
echo "    Detected torch: $TORCH_VER"
python3 -m pip install --user \
    torch-scatter torch-sparse \
    -f https://data.pyg.org/whl/torch-${TORCH_VER}+cpu.html
python3 -m pip install --user torch-geometric
echo "[✓] torch-geometric installed"

echo "[5/5] Installing application packages..."
python3 -m pip install --user \
    websockets \
    aiohttp \
    aiohttp-cors \
    scikit-learn \
    joblib \
    numpy \
    pandas
echo "[✓] App packages installed"

# Persist PATH so agent can find user-installed packages
grep -q "local/bin" ~/.bashrc || \
    echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
grep -q "local/lib/python3.9" ~/.bashrc || \
    echo 'export PYTHONPATH=$HOME/.local/lib/python3.9/site-packages:$PYTHONPATH' >> ~/.bashrc

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
echo ""
echo " All done. Next step: bash setup_aws.sh"
echo "═══════════════════════════════════════════════════════"
