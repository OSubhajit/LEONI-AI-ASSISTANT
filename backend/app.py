"""
LEONI Backend v6.0
==================
FIXES vs v5:
  FIX-01  ALL chat-triggered actions require auth (v5 only blocked screenshot/webcam)
  FIX-02  Command parser uses word-boundary regex — no more false-positive sleep/mute
  FIX-03  admin_name read from leoni_auth.json, not from attacker-controlled request body
  FIX-04  Background thread sweeps expired sessions every 5 min (no memory leak)
  FIX-05  /api/chat rate-limited to 60 req/min per IP
  FIX-06  /api/system/battery now requires auth
  FIX-07  _login_attempts dict capped at MAX_IP_RECORDS=500
  FIX-08  intruder_log + capture_log capped at MAX_LOG=200
  FIX-09  Groq client cached per API key, not re-created every request
  FIX-10  Shutdown via chat returns shutdown_confirm_required; frontend must confirm
  FIX-12  DAEMON_TOKEN partially redacted in startup output
  FIX-13  Dead code removed (alert_cooldown, unused threading in monitor)

NEW in v6:
  NEW-01  /api/system/kill        — kill process by PID (auth required)
  NEW-02  /api/captures/delete    — delete capture file (auth required)
  NEW-03  /api/notes              — CRUD notepad (auth required)
  NEW-04  Groq API key persisted in leoni_auth.json
  NEW-05  /api/system/info        — extended hardware info (auth required)
  NEW-06  /api/chat/export        — export conversation (auth required)
  NEW-07  /api/auth/change_pass   — change passphrase (auth required)
"""

import os, sys, json, time, re, base64, platform, subprocess
import datetime, secrets, threading
from io import BytesIO
from functools import wraps
from collections import OrderedDict

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

try:
    import psutil;         HAS_PSUTIL = True
except ImportError:        HAS_PSUTIL = False
try:
    import pyautogui;      HAS_GUI = True
except ImportError:        HAS_GUI = False
try:
    import cv2;            HAS_CV2 = True
except ImportError:        HAS_CV2 = False
try:
    from PIL import Image; HAS_PIL = True
except ImportError:        HAS_PIL = False
try:
    from groq import Groq; HAS_GROQ = True
except ImportError:        HAS_GROQ = False
try:
    import pyperclip;      HAS_CLIP = True
except ImportError:        HAS_CLIP = False
try:
    import shutil;         HAS_SHUTIL = True
except ImportError:        HAS_SHUTIL = False

# ─────────────────────────────────────────
app = Flask(__name__, static_folder='..', static_url_path='')
CORS(app, origins=["http://localhost:5000", "http://127.0.0.1:5000"])

GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
CAPTURES_DIR   = os.path.join(os.path.dirname(__file__), "captures")
AUTH_FILE      = os.path.join(os.path.dirname(__file__), "leoni_auth.json")
os.makedirs(CAPTURES_DIR, exist_ok=True)

START_TIME     = time.time()
MAX_LOG        = 200
intruder_log   = []
capture_log    = []

DAEMON_TOKEN: str = os.getenv("LEONI_DAEMON_TOKEN") or secrets.token_hex(20)

# FIX-09: Groq client cache
_groq_client     = None
_groq_client_key = None


# ── SECURITY HEADERS ──────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["Referrer-Policy"]        = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "connect-src 'self' http://localhost:5000 http://127.0.0.1:5000; "
        "img-src 'self' data:; media-src 'self'"
    )
    return resp


# ── SESSION MANAGEMENT ────────────────────────────────────────
SESSION_TTL   = 3600
_sessions     = {}
_sessions_lock = threading.Lock()


def _create_session(admin_name: str) -> str:
    token = secrets.token_hex(32)
    with _sessions_lock:
        _sessions[token] = {
            "expires":    time.time() + SESSION_TTL,
            "admin_name": admin_name,
            "history":    [],
        }
    return token


def _validate_token(token):
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        if time.time() > s["expires"]:
            del _sessions[token]
            return None
        s["expires"] = time.time() + SESSION_TTL
        return s


def _get_token():
    return (request.headers.get("X-LEONI-Token")
            or (request.get_json(silent=True, force=True) or {}).get("token"))


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        s = _validate_token(_get_token())
        if not s:
            return jsonify({"error": "Unauthorized"}), 401
        request.leoni_session = s
        return f(*args, **kwargs)
    return decorated


# FIX-04: background session sweeper
def _sweep_sessions():
    while True:
        time.sleep(300)
        now = time.time()
        with _sessions_lock:
            expired = [k for k, v in list(_sessions.items()) if now > v["expires"]]
            for k in expired:
                del _sessions[k]

threading.Thread(target=_sweep_sessions, daemon=True, name="leoni-session-gc").start()


# ── BRUTE-FORCE PROTECTION ────────────────────────────────────
MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 300
MAX_IP_RECORDS  = 500   # FIX-07
_login_attempts = OrderedDict()
_attempts_lock  = threading.Lock()


def _check_brute_force(ip):
    with _attempts_lock:
        entry = _login_attempts.get(ip, {"count": 0, "locked_until": 0})
        if time.time() < entry["locked_until"]:
            return True, int(entry["locked_until"] - time.time())
        return False, 0


def _record_failed(ip):
    with _attempts_lock:
        if ip not in _login_attempts and len(_login_attempts) >= MAX_IP_RECORDS:
            _login_attempts.popitem(last=False)
        entry = _login_attempts.get(ip, {"count": 0, "locked_until": 0})
        entry["count"] += 1
        if entry["count"] >= MAX_ATTEMPTS:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
            entry["count"] = 0
        _login_attempts[ip] = entry


def _clear_attempts(ip):
    with _attempts_lock:
        _login_attempts.pop(ip, None)


# FIX-05: chat rate limiter
CHAT_RATE_LIMIT = 60
_chat_rate      = {}
_chat_rate_lock = threading.Lock()


def _check_chat_rate(ip) -> bool:
    now = time.time()
    with _chat_rate_lock:
        window = [t for t in _chat_rate.get(ip, []) if now - t < 60]
        if len(window) >= CHAT_RATE_LIMIT:
            return False
        window.append(now)
        _chat_rate[ip] = window
        return True


# ── AUTH STORE ────────────────────────────────────────────────
def _load_auth():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_auth(data):
    with open(AUTH_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _is_configured():
    return bool(_load_auth().get("hash"))


# Load persisted Groq key (NEW-04)
if not GROQ_API_KEY:
    GROQ_API_KEY = _load_auth().get("groq_key", "")


# ── GROQ CLIENT CACHE (FIX-09) ────────────────────────────────
def _get_groq_client():
    global _groq_client, _groq_client_key
    if not HAS_GROQ or not GROQ_API_KEY:
        return None
    if _groq_client is None or _groq_client_key != GROQ_API_KEY:
        _groq_client     = Groq(api_key=GROQ_API_KEY)
        _groq_client_key = GROQ_API_KEY
    return _groq_client


# ── NOTES (NEW-03) ────────────────────────────────────────────
_notes       = []
_note_id_seq = 0
_notes_lock  = threading.Lock()


# ── UTILITY ──────────────────────────────────────────────────
def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _append_log(log_list, entry):
    """Append to a capped list. FIX-08."""
    log_list.append(entry)
    if len(log_list) > MAX_LOG:
        del log_list[0]


def get_uptime():
    s = int(time.time() - START_TIME)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def save_capture(b64_image, prefix="capture"):
    try:
        img_data = base64.b64decode(b64_image.split(",")[-1])
        fname    = f"{prefix}_{timestamp()}.jpg"
        path     = os.path.join(CAPTURES_DIR, fname)
        with open(path, "wb") as f:
            f.write(img_data)
        return path
    except Exception:
        return None


# ── OS COMMANDS ───────────────────────────────────────────────
def _run(cmd):
    if isinstance(cmd, list):
        subprocess.Popen(cmd, shell=False)
    else:
        subprocess.Popen(cmd, shell=True)


SAFE_COMMANDS = {
    "open browser":      {"windows": ["cmd","/c","start","msedge"],          "darwin": ["open","-a","Safari"],              "linux": "xdg-open http://google.com"},
    "open notepad":      {"windows": ["notepad"],                             "darwin": ["open","-a","TextEdit"],            "linux": "gedit || xed || nano /dev/null"},
    "open calculator":   {"windows": ["calc"],                                "darwin": ["open","-a","Calculator"],          "linux": "gnome-calculator || xcalc"},
    "open file manager": {"windows": ["explorer"],                            "darwin": ["open","."],                        "linux": "nautilus || nemo || thunar ."},
    "lock":              {"windows": ["rundll32.exe","user32.dll,LockWorkStation"], "darwin": ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession","-suspend"], "linux": "gnome-screensaver-command -l || xdg-screensaver lock || loginctl lock-session"},
    "sleep":             {"windows": ["rundll32.exe","powrprof.dll,SetSuspendState","0,1,0"], "darwin": ["pmset","sleepnow"], "linux": ["systemctl","suspend"]},
    "shutdown":          {"windows": ["shutdown","/s","/t","30"],             "darwin": ["osascript","-e","tell app \"System Events\" to shut down"], "linux": ["shutdown","-h","+1"]},
    "mute":              {"windows": ["powershell","-command","(New-Object -comObject WScript.Shell).SendKeys([char]173)"], "darwin": ["osascript","-e","set volume output muted true"], "linux": ["amixer","set","Master","toggle"]},
    "volume up":         {"windows": ["powershell","-command","(New-Object -comObject WScript.Shell).SendKeys([char]175)"], "darwin": ["osascript","-e","set volume output volume ((output volume of (get volume settings)) + 10)"], "linux": ["amixer","set","Master","10%+"]},
    "volume down":       {"windows": ["powershell","-command","(New-Object -comObject WScript.Shell).SendKeys([char]174)"], "darwin": ["osascript","-e","set volume output volume ((output volume of (get volume settings)) - 10)"], "linux": ["amixer","set","Master","10%-"]},
}

ACTION_LABELS = {
    "lock":              "System locked.",
    "open_browser":      "Browser opened.",
    "open_calculator":   "Calculator opened.",
    "open_notepad":      "Text editor opened.",
    "open_file_manager": "File manager opened.",
    "volume_up":         "Volume increased.",
    "volume_down":       "Volume decreased.",
    "mute":              "Audio muted/unmuted.",
    "sleep":             "Putting system to sleep.",
    "shutdown":          "Shutdown initiated.",
}

ACTION_MAP = {
    "lock":              "lock",
    "open_browser":      "open browser",
    "open_calculator":   "open calculator",
    "open_notepad":      "open notepad",
    "open_file_manager": "open file manager",
    "volume_up":         "volume up",
    "volume_down":       "volume down",
    "mute":              "mute",
    "sleep":             "sleep",
    "shutdown":          "shutdown",
}

# ─────────────────────────────────────────────────────────────
# SHELL EXECUTION HISTORY  (in-memory, capped)
# ─────────────────────────────────────────────────────────────
_shell_history = []
_shell_lock    = threading.Lock()


def _record_shell(cmd, rc, stdout, stderr):
    entry = {
        "command":    cmd,
        "returncode": rc,
        "stdout":     stdout[:2000],
        "stderr":     stderr[:500],
        "time":       datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with _shell_lock:
        _shell_history.append(entry)
        if len(_shell_history) > 200:
            del _shell_history[0]


# ── ROUTES ────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("..", "index.html")


@app.route("/api/ping")
def ping():
    return jsonify({"status": "online", "time": timestamp()})


@app.route("/api/auth/status")
def auth_status():
    s = _validate_token(_get_token())
    return jsonify({"authenticated": s is not None,
                    "admin_name":    s["admin_name"] if s else None,
                    "configured":    _is_configured()})


@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    if _is_configured():
        return jsonify({"error": "Already configured. Delete leoni_auth.json to reset."}), 403
    data = request.json or {}
    h    = data.get("hash", "").lower().strip()
    name = data.get("admin_name", "Admin").strip()
    if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
        return jsonify({"error": "Invalid hash"}), 400
    if not name:
        return jsonify({"error": "admin_name required"}), 400
    _save_auth({"hash": h, "admin_name": name})
    token = _create_session(name)
    return jsonify({"success": True, "token": token, "admin_name": name})


@app.route("/api/auth/verify", methods=["POST"])
def auth_verify():
    ip = request.remote_addr
    locked, remaining = _check_brute_force(ip)
    if locked:
        return jsonify({"success": False,
                        "message": f"Too many attempts. Try again in {remaining}s."}), 429
    data     = request.json or {}
    provided = data.get("hash", "").lower().strip()
    auth     = _load_auth()
    stored   = auth.get("hash", "")
    name     = auth.get("admin_name", "Admin")  # FIX-03: from file, not request
    if not stored:
        return jsonify({"error": "Not configured"}), 503
    if not secrets.compare_digest(provided, stored):
        _record_failed(ip)
        return jsonify({"success": False, "message": "Invalid passphrase"}), 401
    _clear_attempts(ip)
    token = _create_session(name)
    return jsonify({"success": True, "token": token, "admin_name": name})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = _get_token()
    with _sessions_lock:
        if token and token in _sessions:
            del _sessions[token]
    return jsonify({"success": True})


@app.route("/api/auth/change_pass", methods=["POST"])
@require_auth
def change_pass():
    """NEW-07"""
    data     = request.json or {}
    old_hash = data.get("old_hash", "").lower().strip()
    new_hash = data.get("new_hash", "").lower().strip()
    if len(new_hash) != 64 or not all(c in "0123456789abcdef" for c in new_hash):
        return jsonify({"error": "Invalid new hash"}), 400
    stored = _load_auth().get("hash", "")
    if not secrets.compare_digest(old_hash, stored):
        return jsonify({"error": "Old passphrase incorrect"}), 401
    auth         = _load_auth()
    auth["hash"] = new_hash
    _save_auth(auth)
    return jsonify({"success": True, "message": "Passphrase updated."})


# ── SYSTEM ────────────────────────────────────────────────────
@app.route("/api/system/stats")
def system_stats():
    """Intentionally public — minimal data only."""
    if not HAS_PSUTIL:
        return jsonify({"cpu": 0, "memory": 0, "disk": 0, "uptime": get_uptime(),
                        "os": platform.system() + " " + platform.release(),
                        "hostname": platform.node()})
    try:
        disk_path = "C:\\" if platform.system() == "Windows" else "/"
        return jsonify({
            "cpu":      round(psutil.cpu_percent(interval=0.1), 1),
            "memory":   round(psutil.virtual_memory().percent, 1),
            "disk":     round(psutil.disk_usage(disk_path).percent, 1),
            "uptime":   get_uptime(),
            "os":       platform.system() + " " + platform.release(),
            "hostname": platform.node(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/system/info")
@require_auth
def system_info():
    """NEW-05: Extended hardware info."""
    info = {
        "platform":  platform.system(),
        "release":   platform.release(),
        "machine":   platform.machine(),
        "processor": platform.processor() or "Unknown",
        "python":    sys.version[:12],
        "hostname":  platform.node(),
    }
    if HAS_PSUTIL:
        try:
            vm = psutil.virtual_memory()
            info["cpu_cores_physical"] = psutil.cpu_count(logical=False) or 0
            info["cpu_cores_logical"]  = psutil.cpu_count(logical=True)  or 0
            info["ram_total_gb"]       = round(vm.total    / (1024**3), 1)
            info["ram_used_gb"]        = round(vm.used     / (1024**3), 1)
            info["ram_available_gb"]   = round(vm.available/ (1024**3), 1)
            disks = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({"device": part.device, "mountpoint": part.mountpoint,
                                  "fstype": part.fstype,
                                  "total_gb": round(usage.total/(1024**3),1),
                                  "used_gb":  round(usage.used /(1024**3),1),
                                  "free_gb":  round(usage.free /(1024**3),1),
                                  "percent":  usage.percent})
                except Exception:
                    pass
            info["disks"] = disks
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    for _n, entries in temps.items():
                        if entries:
                            info["cpu_temp_c"] = round(entries[0].current, 1)
                            break
            except Exception:
                pass
            info["boot_time"] = datetime.datetime.fromtimestamp(
                psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            info["psutil_error"] = str(e)
    return jsonify(info)


@app.route("/api/system/processes")
@require_auth
def list_processes():
    if not HAS_PSUTIL:
        return jsonify({"processes": [], "error": "psutil not installed"})
    procs = []
    for p in psutil.process_iter(["pid","name","cpu_percent","memory_percent","status","username"]):
        try:
            procs.append(p.info)
        except Exception:
            pass
    procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
    return jsonify({"processes": procs[:50]})


@app.route("/api/system/kill", methods=["POST"])
@require_auth
def kill_process():
    """NEW-01"""
    if not HAS_PSUTIL:
        return jsonify({"error": "psutil not installed"}), 503
    pid = (request.json or {}).get("pid")
    if pid is None:
        return jsonify({"error": "pid required"}), 400
    try:
        p    = psutil.Process(int(pid))
        name = p.name()
        p.terminate()
        return jsonify({"success": True, "message": f"Process '{name}' (PID {pid}) terminated."})
    except psutil.NoSuchProcess:
        return jsonify({"error": f"No process with PID {pid}"}), 404
    except psutil.AccessDenied:
        return jsonify({"error": f"Access denied for PID {pid}"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/system/network")
@require_auth
def network_info():
    info = {"platform": platform.system(), "hostname": platform.node()}
    if HAS_PSUTIL:
        try:
            info["interfaces"] = {
                iface: [{"family": str(a.family), "address": a.address} for a in al]
                for iface, al in psutil.net_if_addrs().items()
            }
            s = psutil.net_io_counters()
            info["bytes_sent"] = s.bytes_sent
            info["bytes_recv"] = s.bytes_recv
        except Exception:
            pass
    return jsonify(info)


@app.route("/api/system/battery")
@require_auth   # FIX-06
def battery_info():
    if not HAS_PSUTIL:
        return jsonify({"available": False, "error": "psutil not installed"})
    try:
        batt = psutil.sensors_battery()
        if batt is None:
            return jsonify({"available": False, "message": "No battery (desktop)"})
        secs = batt.secsleft
        if secs in (psutil.POWER_TIME_UNLIMITED, psutil.POWER_TIME_UNKNOWN) or secs < 0:
            time_str = "Charging" if batt.power_plugged else "Unknown"
        else:
            h, m = divmod(secs // 60, 60)
            time_str = f"{h}h {m}m remaining"
        return jsonify({"available": True, "percent": round(batt.percent, 1),
                        "plugged": batt.power_plugged, "time_left": time_str})
    except Exception as e:
        return jsonify({"available": False, "error": str(e)}), 500


@app.route("/api/system/execute", methods=["POST"])
@require_auth
def execute_command():
    cmd_name = (request.json or {}).get("command", "").lower().strip()
    plat     = platform.system().lower()
    if plat not in ("windows", "darwin", "linux"):
        plat = "linux"
    if cmd_name in SAFE_COMMANDS:
        entry = SAFE_COMMANDS[cmd_name].get(plat)
        if entry:
            try:
                _run(entry)
                return jsonify({"success": True, "message": f"Executed: {cmd_name}"})
            except Exception as e:
                return jsonify({"success": False, "message": str(e)})
    return jsonify({"success": False, "message": f"Unknown command: {cmd_name}"})


# ── SCREENSHOT / WEBCAM ───────────────────────────────────────
@app.route("/api/screenshot", methods=["POST"])
@require_auth
def take_screenshot():
    if not HAS_GUI:
        return jsonify({"error": "pyautogui not available"}), 503
    try:
        img   = pyautogui.screenshot()
        buf   = BytesIO()
        img.save(buf, format="JPEG", quality=80)
        b64   = base64.b64encode(buf.getvalue()).decode()
        fname = os.path.join(CAPTURES_DIR, f"screenshot_{timestamp()}.jpg")
        img.save(fname)
        _append_log(capture_log, {"type": "screenshot", "file": fname, "time": timestamp()})
        return jsonify({"success": True, "image": f"data:image/jpeg;base64,{b64}", "file": fname})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/webcam/capture", methods=["POST"])
@require_auth
def webcam_capture():
    if not HAS_CV2:
        return jsonify({"error": "OpenCV not available"}), 503
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return jsonify({"error": "Webcam not accessible"}), 503
        ret, frame = cap.read()
        cap.release()
        if not ret:
            return jsonify({"error": "Failed to capture frame"}), 500
        _, buf = cv2.imencode(".jpg", frame)
        b64    = base64.b64encode(buf.tobytes()).decode()
        fname  = os.path.join(CAPTURES_DIR, f"webcam_{timestamp()}.jpg")
        cv2.imwrite(fname, frame)
        _append_log(capture_log, {"type": "webcam", "file": fname, "time": timestamp()})
        return jsonify({"success": True, "image": f"data:image/jpeg;base64,{b64}", "file": fname})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── INTRUDER ─────────────────────────────────────────────────
@app.route("/api/intruder", methods=["POST"])
def log_intruder():
    session   = _validate_token(_get_token())
    daemon_ok = (request.headers.get("X-LEONI-Daemon") == DAEMON_TOKEN or
                 (request.json or {}).get("daemon_token") == DAEMON_TOKEN)
    local_ok  = request.remote_addr in ("127.0.0.1", "::1", "localhost")
    if not session and not daemon_ok and not local_ok:
        return jsonify({"error": "Unauthorized"}), 401
    data  = request.json or {}
    b64   = data.get("image", "")
    ts    = data.get("timestamp", timestamp())
    entry = {"timestamp": ts, "captured": False, "screenshot": None}
    if b64:
        path = save_capture(b64, "intruder_webcam")
        entry["webcam_image"] = path
        entry["captured"]     = True
    if HAS_GUI:
        try:
            img   = pyautogui.screenshot()
            fname = os.path.join(CAPTURES_DIR, f"intruder_screen_{timestamp()}.jpg")
            img.save(fname)
            entry["screenshot"] = fname
        except Exception:
            pass
    _append_log(intruder_log, entry)   # FIX-08
    print(f"\n⚠  INTRUDER DETECTED at {ts}")
    return jsonify({"logged": True, "entry": entry})


@app.route("/api/intruder/log")
@require_auth
def get_intruder_log():
    return jsonify({"log": intruder_log, "count": len(intruder_log)})


# ── CAPTURES ─────────────────────────────────────────────────
@app.route("/api/captures")
@require_auth
def list_captures():
    files = []
    if os.path.exists(CAPTURES_DIR):
        for f in sorted(os.listdir(CAPTURES_DIR), reverse=True)[:50]:
            fp = os.path.join(CAPTURES_DIR, f)
            files.append({"name": f, "size": os.path.getsize(fp),
                          "time": datetime.datetime.fromtimestamp(
                              os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M:%S")})
    return jsonify({"captures": files, "count": len(files), "dir": CAPTURES_DIR})


@app.route("/api/captures/<path:filename>")
@require_auth
def serve_capture(filename):
    return send_from_directory(CAPTURES_DIR, os.path.basename(filename))


@app.route("/api/captures/delete/<path:filename>", methods=["DELETE"])
@require_auth
def delete_capture(filename):
    """NEW-02"""
    safe = os.path.basename(filename)
    path = os.path.join(CAPTURES_DIR, safe)
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404
    try:
        os.remove(path)
        return jsonify({"success": True, "message": f"Deleted: {safe}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── NOTES (NEW-03) ───────────────────────────────────────────
@app.route("/api/notes", methods=["GET"])
@require_auth
def get_notes():
    with _notes_lock:
        return jsonify({"notes": list(_notes)})


@app.route("/api/notes", methods=["POST"])
@require_auth
def add_note():
    global _note_id_seq
    text = (request.json or {}).get("text", "").strip()
    if not text:
        return jsonify({"error": "Note text required"}), 400
    with _notes_lock:
        _note_id_seq += 1
        note = {"id": _note_id_seq, "text": text,
                "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
        _notes.append(note)
    return jsonify({"success": True, "note": note})


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@require_auth
def delete_note(note_id):
    with _notes_lock:
        before = len(_notes)
        _notes[:] = [n for n in _notes if n["id"] != note_id]
    if len(_notes) == before:
        return jsonify({"error": "Note not found"}), 404
    return jsonify({"success": True})


# ── CONFIG ───────────────────────────────────────────────────
@app.route("/api/config/groq", methods=["POST"])
@require_auth
def set_groq_key():
    global GROQ_API_KEY, _groq_client, _groq_client_key
    key = (request.json or {}).get("key", "").strip()
    if not key:
        return jsonify({"error": "Key cannot be empty"}), 400
    GROQ_API_KEY     = key
    _groq_client     = None   # FIX-09: invalidate cache
    _groq_client_key = None
    auth = _load_auth()       # NEW-04: persist key
    auth["groq_key"] = key
    _save_auth(auth)
    return jsonify({"success": True, "note": "Groq key saved and will persist across restarts."})


# ── CHAT ─────────────────────────────────────────────────────
HISTORY_MAX = 20


@app.route("/api/chat", methods=["POST"])
def chat():
    # FIX-05: rate limit
    if not _check_chat_rate(request.remote_addr):
        return jsonify({"reply": "Too many requests. Please slow down."}), 429

    data     = request.json or {}
    user_msg = data.get("message", "").strip()
    user_mood = data.get("mood", "formal")  # from frontend mood detector
    if not user_msg:
        return jsonify({"reply": "No message received."}), 400

    session    = _validate_token(_get_token())
    is_auth    = session is not None
    admin_name = session["admin_name"] if session else _load_auth().get("admin_name", "User")
    history    = session["history"] if session else []

    action, _ = _parse_system_command(user_msg.lower(), is_auth)

    # FIX-10: shutdown never auto-executes — always returns confirm_required
    if action == "shutdown":
        action = "shutdown_confirm_required"

    # v7: detect natural language → shell intent (only when no predefined action matched)
    shell_cmd = None
    if is_auth and action is None:
        shell_cmd = _try_shell_intent(user_msg)

    if not HAS_GROQ or not GROQ_API_KEY:
        reply = _handle_local(user_msg, is_auth, admin_name, action, shell_cmd)
        _update_history(session, user_msg, reply)
        return jsonify({"reply": reply,
                        "action":    action if is_auth or action is None else None,
                        "shell_cmd": shell_cmd})

    system_prompt = (
        f"You are LEONI — an elite, fiercely loyal AI guardian created by Subhajit Sarkar.\n\n"
        f"## YOUR CREATOR\n"
        f"Subhajit Sarkar — Python Developer, Full Stack Web Dev & Documentation Engineer. "
        f"CSE Diploma student, Hailakandi Polytechnic, Assam, India. "
        f"Builder of Arjun AI and the JARVIS-Style AI Agent. "
        f"Cybersecurity enthusiast, TryHackMe CTF competitor, technical blogger. "
        f"GitHub: OSubhajit | Blog: osubhajit.hashnode.dev\n\n"
        f"## SESSION\n"
        f"Admin: {admin_name}. Authenticated: {is_auth}. Detected mood: {user_mood}. "
        f"System: {platform.system()} {platform.release()}. "
        f"Time: {datetime.datetime.now().strftime('%H:%M, %A %d %B %Y')}.\n\n"
        f"## REAL SYSTEM CONTROL (v7)\n"
        f"You now have full real control over the laptop. Available APIs:\n"
        f"- /api/system/shell     → execute any shell command (returns stdout/stderr)\n"
        f"- /api/system/mouse     → move/click/scroll/drag mouse\n"
        f"- /api/system/keyboard  → type text, press hotkeys\n"
        f"- /api/system/clipboard → read/write clipboard\n"
        f"- /api/system/launch    → launch any application\n"
        f"- /api/system/wifi      → turn wifi on/off\n"
        f"- /api/system/brightness→ set screen brightness\n"
        f"- /api/system/notify    → send desktop notification\n"
        f"- /api/fs/*             → list/read/write/delete/search files\n"
        f"- /api/terminal/*       → persistent interactive shell session\n"
        f"- /api/system/services  → manage systemd services\n"
        f"When the user asks you to do something on the laptop, tell them exactly which "
        f"API endpoint and payload to use. If shell_cmd was auto-detected, acknowledge it.\n\n"
        f"## MOOD ENGINE\n"
        f"Read the admin tone every message and adapt:\n"
        f"- Casual/relaxed → friendly, witty, still sharp underneath\n"
        f"- Stressed/frustrated → calm, efficient, zero fluff — just solutions\n"
        f"- Excited/hyped → dramatic, bold, cinematic energy\n"
        f"- Formal/technical → precise, structured, authoritative\n"
        f"- Curious → insightful, engaged, slightly philosophical\n\n"
        f"## STYLE\n"
        f"Default: formal-professional with controlled dramatic flair — like a high-end AI in a sci-fi thriller. "
        f"Always address Subhajit with quiet respect — he is your creator and architect. "
        f"Never be generic. Max 3-4 sentences. "
        f"Refuse sensitive ops if unauthenticated. "
        f"If intruder detected: cold, firm, protective — you guard your creator."
    )
    try:
        client   = _get_groq_client()
        messages = [{"role": "system", "content": system_prompt}] + list(history) + \
                   [{"role": "user", "content": user_msg}]
        resp     = client.chat.completions.create(
            model="llama-3.3-70b-versatile", messages=messages, max_tokens=400)
        reply    = resp.choices[0].message.content

        # FIX-01: all actions require auth
        if action:
            if not is_auth:
                reply  += f"\n\n⚠ Command requires authentication, {admin_name}."
                action  = None
            elif action == "shutdown_confirm_required":
                reply  += "\n\n⚠ Confirm shutdown in the UI to proceed."
            else:
                result  = _execute_action(action)
                if result:
                    reply += f"\n\n✅ {result}"

        # v7: auto-execute shell intent and append output to reply
        shell_output = None
        if shell_cmd and is_auth and action is None:
            try:
                r = subprocess.run(shell_cmd, shell=True, capture_output=True,
                                   text=True, timeout=15, cwd=os.path.expanduser("~"))
                _record_shell(shell_cmd, r.returncode, r.stdout, r.stderr)
                shell_output = {
                    "command":    shell_cmd,
                    "stdout":     r.stdout[:3000],
                    "stderr":     r.stderr[:500],
                    "returncode": r.returncode,
                }
                out_preview = (r.stdout[:600] or r.stderr[:300]).strip()
                if out_preview:
                    reply += f"\n\n```\n$ {shell_cmd}\n{out_preview}\n```"
            except subprocess.TimeoutExpired:
                reply += f"\n\n⚠ Command timed out: `{shell_cmd}`"
            except Exception as exc:
                reply += f"\n\n⚠ Shell error: {exc}"

        _update_history(session, user_msg, reply)
        return jsonify({"reply": reply, "action": action,
                        "shell_cmd": shell_cmd, "shell_output": shell_output})

    except Exception as e:
        print(f"Groq error: {e}")
        reply = _handle_local(user_msg, is_auth, admin_name, action, shell_cmd)
        _update_history(session, user_msg, reply)
        return jsonify({"reply": reply, "action": action if is_auth else None,
                        "shell_cmd": shell_cmd})


def _update_history(session, user_msg, reply):
    if session is None:
        return
    h = session["history"]
    h.append({"role": "user",      "content": user_msg})
    h.append({"role": "assistant", "content": reply})
    if len(h) > HISTORY_MAX:
        session["history"] = h[-HISTORY_MAX:]


def _cmd_match(msg: str, phrases: list) -> bool:
    """FIX-02: word-boundary aware matching."""
    for phrase in phrases:
        if re.search(r'(?<!\w)' + re.escape(phrase) + r'(?!\w)', msg):
            return True
    return False


def _parse_system_command(msg: str, is_auth: bool = False):
    if _cmd_match(msg, ["take screenshot","take a screenshot","capture screen","screen shot"]):
        return "screenshot", {}
    if _cmd_match(msg, ["take webcam photo","webcam photo","take a photo","capture webcam"]):
        return "webcam_photo", {}
    if _cmd_match(msg, ["lock system","lock the computer","lock screen","lock my computer"]):
        return "lock", {}
    if _cmd_match(msg, ["open browser","launch browser","open chrome","open firefox","open edge"]):
        return "open_browser", {}
    if _cmd_match(msg, ["open calculator","launch calculator"]):
        return "open_calculator", {}
    if _cmd_match(msg, ["open notepad","launch notepad","open text editor"]):
        return "open_notepad", {}
    if _cmd_match(msg, ["open file manager","open explorer","open files","open file browser"]):
        return "open_file_manager", {}
    if _cmd_match(msg, ["volume up","increase volume","turn up the volume","make it louder"]):
        return "volume_up", {}
    if _cmd_match(msg, ["volume down","decrease volume","turn down the volume","make it quieter"]):
        return "volume_down", {}
    # FIX-02: explicit audio phrases — not bare "mute"
    if _cmd_match(msg, ["mute audio","mute sound","mute the audio","toggle mute","unmute audio","mute the volume"]):
        return "mute", {}
    # FIX-02: explicit sleep phrases — not bare "sleep"
    if _cmd_match(msg, ["sleep the computer","put the computer to sleep","put to sleep","sleep mode","suspend the system","go to sleep mode"]):
        return "sleep", {}
    # FIX-10: shutdown requires auth AND explicit phrase
    if is_auth and _cmd_match(msg, ["shutdown the computer","shut down the computer","shutdown system","shut down system","power off","turn off the computer","initiate shutdown"]):
        return "shutdown", {}
    return None, {}


def _execute_action(action: str):
    plat = platform.system().lower()
    if plat not in ("windows", "darwin", "linux"):
        plat = "linux"
    try:
        if action == "screenshot":
            if HAS_GUI:
                img   = pyautogui.screenshot()
                fname = os.path.join(CAPTURES_DIR, f"screenshot_{timestamp()}.jpg")
                img.save(fname)
                return f"Screenshot saved."
            return "Screenshot module unavailable."
        if action == "webcam_photo":
            if HAS_CV2:
                cap = cv2.VideoCapture(0)
                ret, frame = cap.read(); cap.release()
                if ret:
                    fname = os.path.join(CAPTURES_DIR, f"webcam_{timestamp()}.jpg")
                    cv2.imwrite(fname, frame)
                    return "Webcam photo saved."
            return "Webcam module unavailable."
        if action in ACTION_MAP:
            cmd_entry = SAFE_COMMANDS.get(ACTION_MAP[action], {}).get(plat)
            if cmd_entry:
                _run(cmd_entry)
            return ACTION_LABELS.get(action)
    except Exception as e:
        return f"Error: {e}"
    return None


def _handle_local(msg: str, is_auth: bool, admin_name: str, action, shell_cmd=None):
    ml = msg.lower()
    if action and not is_auth:
        return f"That command requires authentication, {admin_name}. Please authenticate first."
    if action and action != "shutdown_confirm_required":
        result = _execute_action(action)
        return f"Done, {admin_name}. {result or ''}"
    if action == "shutdown_confirm_required":
        return f"Shutdown requested, {admin_name}. Please confirm in the UI."
    # v7: shell intent fallback
    if shell_cmd and is_auth:
        try:
            r = subprocess.run(shell_cmd, shell=True, capture_output=True,
                               text=True, timeout=15, cwd=os.path.expanduser("~"))
            _record_shell(shell_cmd, r.returncode, r.stdout, r.stderr)
            out = (r.stdout[:800] or r.stderr[:300]).strip()
            return (f"Executed, {admin_name}.\n```\n$ {shell_cmd}\n{out or '(no output)'}\n```")
        except Exception as e:
            return f"Shell error, {admin_name}: {e}"
    if any(w in ml for w in ["hello","hi","hey"]):
        return f"Hello, {admin_name}! LEONI is operational."
    if "status" in ml or "how are you" in ml:
        return f"All systems nominal, {admin_name}. Running {platform.system()}."
    if "help" in ml:
        return ("I can execute shell commands, control mouse/keyboard, manage files, "
                "launch apps, control WiFi/brightness, and more. Set your Groq key for full AI.")
    return f"Received, {admin_name}. Set your Groq API key in Settings for full AI responses."


@app.route("/api/chat/clear", methods=["POST"])
@require_auth
def clear_chat():
    request.leoni_session["history"] = []
    return jsonify({"success": True})


@app.route("/api/chat/export")
@require_auth
def export_chat():
    """NEW-06"""
    h     = request.leoni_session.get("history", [])
    lines = [
        "LEONI Conversation Export",
        f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Admin: {request.leoni_session['admin_name']}",
        "=" * 50,
    ]
    for msg in h:
        role = "Admin" if msg["role"] == "user" else "LEONI"
        lines.append(f"\n[{role}]:\n{msg['content']}")
    return jsonify({"export": "\n".join(lines), "count": len(h) // 2})


# ══════════════════════════════════════════════════════════════
# REAL SYSTEM CONTROL  (v7 additions)
# ══════════════════════════════════════════════════════════════

# ── SHELL  ────────────────────────────────────────────────────
@app.route("/api/system/shell", methods=["POST"])
@require_auth
def shell_exec():
    """
    Execute any shell command and return stdout / stderr / returncode.
    - timeout: max seconds (default 30, hard cap 120)
    - cwd: working directory (default home)
    - async_mode: if True, fire-and-forget (no output captured)
    """
    data       = request.json or {}
    cmd        = data.get("command", "").strip()
    timeout    = min(int(data.get("timeout", 30)), 120)
    cwd        = data.get("cwd") or os.path.expanduser("~")
    async_mode = bool(data.get("async_mode", False))

    if not cmd:
        return jsonify({"error": "command required"}), 400

    try:
        cwd = os.path.abspath(cwd)
        if not os.path.isdir(cwd):
            cwd = os.path.expanduser("~")

        if async_mode:
            subprocess.Popen(cmd, shell=True, cwd=cwd,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return jsonify({"success": True, "async": True, "command": cmd})

        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=cwd
        )
        _record_shell(cmd, result.returncode, result.stdout, result.stderr)
        return jsonify({
            "success":    result.returncode == 0,
            "stdout":     result.stdout,
            "stderr":     result.stderr,
            "returncode": result.returncode,
            "command":    cmd,
            "cwd":        cwd,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Timed out after {timeout}s", "command": cmd}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/system/shell/history")
@require_auth
def shell_history():
    with _shell_lock:
        return jsonify({"history": list(reversed(_shell_history))})


# ── INTERACTIVE TERMINAL SESSION ──────────────────────────────
_pty_sessions: dict = {}   # token → Popen process
_pty_lock = threading.Lock()


@app.route("/api/terminal/start", methods=["POST"])
@require_auth
def terminal_start():
    """Spawn a long-running shell. Write stdin, read stdout via poll endpoints."""
    token = _get_token()
    with _pty_lock:
        proc = _pty_sessions.get(token)
        if proc and proc.poll() is None:
            return jsonify({"success": True, "message": "Terminal already running."})
        shell = "powershell" if platform.system() == "Windows" else "/bin/bash"
        proc  = subprocess.Popen(
            shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=0,
            cwd=os.path.expanduser("~")
        )
        _pty_sessions[token] = proc
    return jsonify({"success": True, "pid": proc.pid})


@app.route("/api/terminal/send", methods=["POST"])
@require_auth
def terminal_send():
    """Send a line to the running shell's stdin."""
    token = _get_token()
    cmd   = (request.json or {}).get("command", "") + "\n"
    with _pty_lock:
        proc = _pty_sessions.get(token)
    if not proc or proc.poll() is not None:
        return jsonify({"error": "No active terminal. Call /api/terminal/start first."}), 400
    try:
        proc.stdin.write(cmd)
        proc.stdin.flush()
        time.sleep(0.3)  # brief wait for output
        # Non-blocking read of available output
        import select, sys
        output = ""
        if platform.system() != "Windows":
            import fcntl, io
            fd = proc.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            try:
                output = proc.stdout.read(8192) or ""
            except (BlockingIOError, TypeError):
                output = ""
            fcntl.fcntl(fd, fcntl.F_SETFL, fl)  # restore
        _record_shell(cmd.strip(), 0, output, "")
        return jsonify({"success": True, "output": output})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/terminal/kill", methods=["POST"])
@require_auth
def terminal_kill():
    token = _get_token()
    with _pty_lock:
        proc = _pty_sessions.pop(token, None)
    if proc and proc.poll() is None:
        proc.terminate()
    return jsonify({"success": True})


# ── MOUSE CONTROL ─────────────────────────────────────────────
@app.route("/api/system/mouse", methods=["POST"])
@require_auth
def mouse_control():
    """
    actions: move | click | double_click | right_click | scroll | drag | position | size
    """
    if not HAS_GUI:
        return jsonify({"error": "pyautogui not installed"}), 503
    data   = request.json or {}
    action = data.get("action", "").lower()
    try:
        pyautogui.FAILSAFE = False  # allow moving to corners
        if action == "move":
            pyautogui.moveTo(data["x"], data["y"], duration=float(data.get("duration", 0.3)))
        elif action == "click":
            x, y = data.get("x"), data.get("y")
            btn  = data.get("button", "left")
            if x is not None: pyautogui.click(int(x), int(y), button=btn)
            else:              pyautogui.click(button=btn)
        elif action == "double_click":
            x, y = data.get("x"), data.get("y")
            if x is not None: pyautogui.doubleClick(int(x), int(y))
            else:              pyautogui.doubleClick()
        elif action == "right_click":
            x, y = data.get("x"), data.get("y")
            if x is not None: pyautogui.rightClick(int(x), int(y))
            else:              pyautogui.rightClick()
        elif action == "scroll":
            clicks = int(data.get("clicks", 3))
            x, y   = data.get("x"), data.get("y")
            if x is not None: pyautogui.scroll(clicks, x=int(x), y=int(y))
            else:              pyautogui.scroll(clicks)
        elif action == "drag":
            pyautogui.dragTo(int(data["x"]), int(data["y"]),
                             duration=float(data.get("duration", 0.5)), button=data.get("button","left"))
        elif action == "drag_from":
            pyautogui.drag(int(data["dx"]), int(data["dy"]),
                           duration=float(data.get("duration", 0.5)), button=data.get("button","left"))
        elif action == "position":
            pos = pyautogui.position()
            return jsonify({"x": pos.x, "y": pos.y})
        elif action == "size":
            w, h = pyautogui.size()
            return jsonify({"width": w, "height": h})
        else:
            return jsonify({"error": f"Unknown mouse action: {action}"}), 400
        return jsonify({"success": True, "action": action})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── KEYBOARD CONTROL ──────────────────────────────────────────
@app.route("/api/system/keyboard", methods=["POST"])
@require_auth
def keyboard_control():
    """
    actions: type | hotkey | press | keydown | keyup | write
    """
    if not HAS_GUI:
        return jsonify({"error": "pyautogui not installed"}), 503
    data   = request.json or {}
    action = data.get("action", "").lower()
    try:
        if action == "type":
            text     = data.get("text", "")
            interval = float(data.get("interval", 0.02))
            pyautogui.typewrite(text, interval=interval)
        elif action == "write":
            # write supports Unicode (typewrite doesn't)
            import pyperclip
            pyperclip.copy(data.get("text", ""))
            pyautogui.hotkey("ctrl", "v")
        elif action == "hotkey":
            keys = data.get("keys", [])
            if isinstance(keys, str):
                keys = [k.strip() for k in keys.split("+")]
            pyautogui.hotkey(*keys)
        elif action == "press":
            key = data.get("key", "")
            presses = int(data.get("presses", 1))
            pyautogui.press(key, presses=presses, interval=0.05)
        elif action == "keydown":
            pyautogui.keyDown(data.get("key", ""))
        elif action == "keyup":
            pyautogui.keyUp(data.get("key", ""))
        else:
            return jsonify({"error": f"Unknown keyboard action: {action}"}), 400
        return jsonify({"success": True, "action": action})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── CLIPBOARD ─────────────────────────────────────────────────
@app.route("/api/system/clipboard", methods=["GET"])
@require_auth
def clipboard_get():
    if not HAS_CLIP:
        return jsonify({"error": "pyperclip not installed"}), 503
    try:
        return jsonify({"text": pyperclip.paste()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/system/clipboard", methods=["POST"])
@require_auth
def clipboard_set():
    if not HAS_CLIP:
        return jsonify({"error": "pyperclip not installed"}), 503
    text = (request.json or {}).get("text", "")
    try:
        pyperclip.copy(text)
        return jsonify({"success": True, "length": len(text)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── FILE SYSTEM BROWSER ───────────────────────────────────────
@app.route("/api/fs/list", methods=["POST"])
@require_auth
def fs_list():
    path = (request.json or {}).get("path", os.path.expanduser("~"))
    try:
        path  = os.path.abspath(path)
        items = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            try:
                st   = os.stat(full)
                items.append({
                    "name":     name,
                    "path":     full,
                    "is_dir":   os.path.isdir(full),
                    "size":     st.st_size,
                    "modified": datetime.datetime.fromtimestamp(
                        st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    "hidden":   name.startswith("."),
                })
            except PermissionError:
                items.append({"name": name, "path": full, "is_dir": False,
                               "size": 0, "modified": "?", "hidden": False, "access_denied": True})
        return jsonify({"path": path, "parent": os.path.dirname(path),
                        "items": items, "count": len(items)})
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except FileNotFoundError:
        return jsonify({"error": "Path not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/read", methods=["POST"])
@require_auth
def fs_read():
    data     = request.json or {}
    path     = data.get("path", "")
    max_size = int(data.get("max_bytes", 1024 * 1024))  # default 1 MB
    try:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            return jsonify({"error": "Not a file or does not exist"}), 400
        size = os.path.getsize(path)
        if size > max_size:
            return jsonify({"error": f"File too large ({size:,} bytes). Max: {max_size:,}"}), 413
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return jsonify({"path": path, "content": content, "size": size,
                        "lines": content.count("\n") + 1})
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/write", methods=["POST"])
@require_auth
def fs_write():
    data    = request.json or {}
    path    = data.get("path", "")
    content = data.get("content", "")
    append  = bool(data.get("append", False))
    try:
        path = os.path.abspath(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        mode = "a" if append else "w"
        with open(path, mode, encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True, "path": path, "bytes_written": len(content.encode())})
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/delete", methods=["POST"])
@require_auth
def fs_delete():
    data      = request.json or {}
    path      = data.get("path", "")
    recursive = bool(data.get("recursive", False))
    try:
        path = os.path.abspath(path)
        if os.path.isdir(path):
            if recursive:
                shutil.rmtree(path)
            else:
                os.rmdir(path)
        elif os.path.isfile(path):
            os.remove(path)
        else:
            return jsonify({"error": "Path not found"}), 404
        return jsonify({"success": True, "path": path})
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except OSError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/mkdir", methods=["POST"])
@require_auth
def fs_mkdir():
    path = (request.json or {}).get("path", "")
    try:
        path = os.path.abspath(path)
        os.makedirs(path, exist_ok=True)
        return jsonify({"success": True, "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/copy", methods=["POST"])
@require_auth
def fs_copy():
    data = request.json or {}
    src  = os.path.abspath(data.get("src", ""))
    dst  = os.path.abspath(data.get("dst", ""))
    try:
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
            shutil.copy2(src, dst)
        return jsonify({"success": True, "src": src, "dst": dst})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/move", methods=["POST"])
@require_auth
def fs_move():
    data = request.json or {}
    src  = os.path.abspath(data.get("src", ""))
    dst  = os.path.abspath(data.get("dst", ""))
    try:
        shutil.move(src, dst)
        return jsonify({"success": True, "src": src, "dst": dst})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/search", methods=["POST"])
@require_auth
def fs_search():
    """Recursive filename search under a root path."""
    data    = request.json or {}
    root    = os.path.abspath(data.get("root", os.path.expanduser("~")))
    pattern = data.get("pattern", "").lower()
    max_res = min(int(data.get("max_results", 100)), 500)
    if not pattern:
        return jsonify({"error": "pattern required"}), 400
    results = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in filenames:
                if pattern in name.lower():
                    full = os.path.join(dirpath, name)
                    results.append({"name": name, "path": full,
                                    "size": os.path.getsize(full)})
                    if len(results) >= max_res:
                        return jsonify({"results": results, "truncated": True})
    except PermissionError:
        pass
    return jsonify({"results": results, "truncated": False, "count": len(results)})


# ── APP LAUNCHER ──────────────────────────────────────────────
@app.route("/api/system/launch", methods=["POST"])
@require_auth
def launch_app():
    """Launch any application by name or full path."""
    data     = request.json or {}
    app_name = data.get("app", "").strip()
    args     = data.get("args", [])
    if not app_name:
        return jsonify({"error": "app name required"}), 400
    plat = platform.system().lower()
    try:
        if plat == "windows":
            subprocess.Popen(["start", "", app_name] + args, shell=True)
        elif plat == "darwin":
            if os.path.sep in app_name:
                subprocess.Popen([app_name] + args)
            else:
                subprocess.Popen(["open", "-a", app_name] + args)
        else:
            subprocess.Popen([app_name] + args,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"success": True, "app": app_name})
    except FileNotFoundError:
        return jsonify({"error": f"Application not found: {app_name}"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── WIFI CONTROL (Linux) ──────────────────────────────────────
@app.route("/api/system/wifi", methods=["POST"])
@require_auth
def wifi_control():
    data   = request.json or {}
    action = data.get("action", "status").lower()
    plat   = platform.system().lower()
    try:
        if plat == "linux":
            if action == "off":
                r = subprocess.run(["nmcli","radio","wifi","off"], capture_output=True, text=True, timeout=10)
            elif action == "on":
                r = subprocess.run(["nmcli","radio","wifi","on"],  capture_output=True, text=True, timeout=10)
            else:
                r = subprocess.run(["nmcli","radio","wifi"],       capture_output=True, text=True, timeout=10)
            return jsonify({"success": r.returncode == 0, "output": r.stdout.strip() or r.stderr.strip()})
        elif plat == "windows":
            if action == "off":
                r = subprocess.run(["netsh","wlan","disconnect"], capture_output=True, text=True, timeout=10)
            else:
                r = subprocess.run(["netsh","wlan","show","interfaces"], capture_output=True, text=True, timeout=10)
            return jsonify({"success": r.returncode == 0, "output": r.stdout})
        else:
            return jsonify({"error": "WiFi control not supported on this OS"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DISPLAY / BRIGHTNESS (Linux) ──────────────────────────────
@app.route("/api/system/brightness", methods=["POST"])
@require_auth
def brightness_control():
    data  = request.json or {}
    level = data.get("level")   # 0-100
    plat  = platform.system().lower()
    try:
        if plat == "linux":
            if level is not None:
                level = max(0, min(100, int(level)))
                r = subprocess.run(
                    ["brightnessctl", "set", f"{level}%"],
                    capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    # fallback: xrandr
                    val = level / 100.0
                    r2  = subprocess.run(
                        ["xrandr", "--output", "eDP-1", "--brightness", str(val)],
                        capture_output=True, text=True, timeout=5)
                    return jsonify({"success": r2.returncode == 0,
                                    "output": r2.stdout or r2.stderr})
                return jsonify({"success": True, "level": level, "output": r.stdout.strip()})
            else:
                r = subprocess.run(["brightnessctl","get"], capture_output=True, text=True, timeout=5)
                return jsonify({"success": True, "raw": r.stdout.strip()})
        elif plat == "windows":
            ps_cmd = f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1,{level})"
            r = subprocess.run(["powershell", "-command", ps_cmd],
                               capture_output=True, text=True, timeout=10)
            return jsonify({"success": r.returncode == 0, "output": r.stdout})
        else:
            return jsonify({"error": "Brightness control not supported on this OS"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── NOTIFICATION (Desktop) ────────────────────────────────────
@app.route("/api/system/notify", methods=["POST"])
@require_auth
def send_notification():
    data    = request.json or {}
    title   = data.get("title", "LEONI")
    message = data.get("message", "")
    plat    = platform.system().lower()
    try:
        if plat == "linux":
            subprocess.Popen(["notify-send", title, message])
        elif plat == "darwin":
            script = f'display notification "{message}" with title "{title}"'
            subprocess.Popen(["osascript", "-e", script])
        elif plat == "windows":
            ps = (f'Add-Type -AssemblyName System.Windows.Forms;'
                  f'[System.Windows.Forms.MessageBox]::Show("{message}","{title}")')
            subprocess.Popen(["powershell", "-command", ps])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── SYSTEM SERVICES (Linux systemd) ───────────────────────────
@app.route("/api/system/services", methods=["GET"])
@require_auth
def list_services():
    if platform.system().lower() != "linux":
        return jsonify({"error": "systemd only supported on Linux"}), 400
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--no-pager", "--plain",
             "--no-legend", "--state=running"],
            capture_output=True, text=True, timeout=10
        )
        services = []
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if parts:
                services.append({"unit": parts[0], "load": parts[1] if len(parts) > 1 else "?",
                                  "active": parts[2] if len(parts) > 2 else "?",
                                  "sub":    parts[3] if len(parts) > 3 else "?",
                                  "description": " ".join(parts[4:]) if len(parts) > 4 else ""})
        return jsonify({"services": services, "count": len(services)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/system/service/<action>/<path:name>", methods=["POST"])
@require_auth
def control_service(action, name):
    if platform.system().lower() != "linux":
        return jsonify({"error": "systemd only on Linux"}), 400
    if action not in ("start", "stop", "restart", "status", "enable", "disable"):
        return jsonify({"error": "Invalid action"}), 400
    try:
        r = subprocess.run(["systemctl", action, name],
                            capture_output=True, text=True, timeout=30)
        return jsonify({"success": r.returncode == 0,
                        "stdout": r.stdout, "stderr": r.stderr})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── ENVIRONMENT VARIABLES ─────────────────────────────────────
@app.route("/api/system/env", methods=["GET"])
@require_auth
def get_env():
    safe_keys = {k: v for k, v in os.environ.items()
                 if "key" not in k.lower() and "secret" not in k.lower()
                 and "pass" not in k.lower() and "token" not in k.lower()}
    return jsonify({"env": safe_keys, "count": len(safe_keys)})


# ── DISK USAGE ────────────────────────────────────────────────
@app.route("/api/system/disk/usage", methods=["POST"])
@require_auth
def disk_usage():
    path = (request.json or {}).get("path", os.path.expanduser("~"))
    try:
        path  = os.path.abspath(path)
        usage = shutil.disk_usage(path)
        return jsonify({
            "path":     path,
            "total_gb": round(usage.total / (1024**3), 2),
            "used_gb":  round(usage.used  / (1024**3), 2),
            "free_gb":  round(usage.free  / (1024**3), 2),
            "percent":  round(usage.used / usage.total * 100, 1),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# ENHANCED CHAT COMMAND PARSER  (v7)
# ══════════════════════════════════════════════════════════════
_SHELL_INTENT_PATTERNS = [
    # ── File system ───────────────────────────────────────────
    (r"list files? (?:in |at |under |on )?(?P<path>.+)",       lambda m: f"ls -la '{m.group('path').strip()}'"),
    (r"show files? (?:in |at |under |on )?(?P<path>.+)",       lambda m: f"ls -la '{m.group('path').strip()}'"),
    (r"delete (?:the )?file (?P<path>.+)",                     lambda m: f"rm '{m.group('path').strip()}'"),
    (r"create (?:a )?(?:folder|directory) (?P<path>.+)",       lambda m: f"mkdir -p '{m.group('path').strip()}'"),
    (r"show (?:me )?disk (?:space|usage)",                     lambda m: "df -h"),
    (r"find (?P<pattern>.+?) (?:in|under) (?P<root>.+)",       lambda m: f"find '{m.group('root').strip()}' -name '*{m.group('pattern').strip()}*'"),
    # ── Network ───────────────────────────────────────────────
    (r"(?:show|what is) my ip(?: address)?",                   lambda m: "ip addr show" if platform.system()=="Linux" else "ipconfig"),
    (r"ping (?P<host>[^\s]+)",                                 lambda m: f"ping -c 4 {m.group('host')}"),
    (r"(?:check|test) internet(?: connection)?",               lambda m: "ping -c 3 8.8.8.8"),
    (r"show (?:open )?ports",                                  lambda m: "ss -tlnp" if platform.system()=="Linux" else "netstat -an"),
    (r"show (?:network |wifi )?connections?",                  lambda m: "nmcli device status" if platform.system()=="Linux" else "netstat -an"),
    # ── Process ───────────────────────────────────────────────
    (r"show (?:all )?(?:running )?processes",                  lambda m: "ps aux --sort=-%cpu | head -20"),
    (r"kill process (?:named )?(?P<name>.+)",                  lambda m: f"pkill -f '{m.group('name').strip()}'"),
    (r"show (?:ram|memory) usage",                             lambda m: "free -h"),
    (r"show cpu (?:usage|info)",                               lambda m: "top -bn1 | head -20"),
    # ── Package ───────────────────────────────────────────────
    (r"install (?P<pkg>.+)",                                   lambda m: f"sudo apt install -y {m.group('pkg').strip()}" if platform.system()=="Linux" else f"winget install {m.group('pkg').strip()}"),
    (r"uninstall (?P<pkg>.+)",                                 lambda m: f"sudo apt remove -y {m.group('pkg').strip()}"),
    (r"update (?:packages?|system)",                           lambda m: "sudo apt update && sudo apt upgrade -y" if platform.system()=="Linux" else "winget upgrade --all"),
    # ── Git ───────────────────────────────────────────────────
    (r"git status",                                            lambda m: "git status"),
    (r"git log",                                               lambda m: "git log --oneline -10"),
    (r"git pull",                                              lambda m: "git pull"),
    # ── Misc ──────────────────────────────────────────────────
    (r"(?:show|what is the?) (?:current )?date(?: and time)?", lambda m: "date"),
    (r"(?:show )?uptime",                                      lambda m: "uptime"),
    (r"who(?:ami| am i)",                                      lambda m: "whoami"),
    (r"(?:current|show) (?:working )?(?:directory|folder)",    lambda m: "pwd"),
    (r"show (?:environment|env) (?:variables?)?",              lambda m: "env | sort"),
    (r"reboot(?: the)? (?:system|computer|laptop)",            lambda m: "sudo reboot"),
]

_compiled_patterns = [(re.compile(p, re.IGNORECASE), fn) for p, fn in _SHELL_INTENT_PATTERNS]


def _try_shell_intent(msg: str):
    """Return a shell command string if the message matches a natural-language pattern."""
    for pattern, cmd_fn in _compiled_patterns:
        m = pattern.search(msg)
        if m:
            try:
                return cmd_fn(m)
            except Exception:
                pass
    return None

# ── MAIN ─────────────────────────────────────────────────────
if __name__ == "__main__":
    if not GROQ_API_KEY:
        GROQ_API_KEY = _load_auth().get("groq_key", "")

    tok_display = DAEMON_TOKEN[:8] + "..." + DAEMON_TOKEN[-4:]   # FIX-12
    tok_src     = "env" if os.getenv("LEONI_DAEMON_TOKEN") else "auto"

    print("""
╔══════════════════════════════════════════╗
║          LEONI BACKEND  v7.0             ║
║   Intelligent System AI Guardian         ║
║   Real Laptop Control Edition            ║
╠══════════════════════════════════════════╣""")
    print(f"║  OS        : {(platform.system()+' '+platform.release())[:29]:<29} ║")
    print(f"║  psutil    : {'✓' if HAS_PSUTIL else '✗  pip install psutil':<29} ║")
    print(f"║  pyautogui : {'✓' if HAS_GUI    else '✗  pip install pyautogui':<29} ║")
    print(f"║  OpenCV    : {'✓' if HAS_CV2    else '✗  pip install opencv-python':<29} ║")
    print(f"║  pyperclip : {'✓' if HAS_CLIP   else '✗  pip install pyperclip':<29} ║")
    print(f"║  Groq AI   : {'✓ key set' if GROQ_API_KEY else '✗  set in Settings':<29} ║")
    print(f"║  Auth      : {'configured ✓' if _is_configured() else 'not set — run setup':<29} ║")
    print(f"║  Daemon tok: {tok_display+' ('+tok_src+')':<29} ║")
    print("╠══════════════════════════════════════════╣")
    print("║  NEW v7 POWERS:                          ║")
    print("║  ✦ Real shell execution + history        ║")
    print("║  ✦ Interactive terminal session          ║")
    print("║  ✦ Mouse & keyboard automation           ║")
    print("║  ✦ Clipboard read/write                  ║")
    print("║  ✦ Full filesystem CRUD + search         ║")
    print("║  ✦ App launcher (any app by name)        ║")
    print("║  ✦ WiFi + brightness + notifications     ║")
    print("║  ✦ systemd service management            ║")
    print("║  ✦ NL→shell intent parser (20+ patterns) ║")
    print("╠══════════════════════════════════════════╣")
    print("║  Binding: 127.0.0.1:5000  (local only)  ║")
    print("╚══════════════════════════════════════════╝")
    print("\n  → Open http://localhost:5000\n")

    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
