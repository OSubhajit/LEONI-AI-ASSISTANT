"""
LEONI Background Guardian Daemon  v3.0

FIXES vs v2:
  FIX-13a  Removed unused threading module (was imported but never used)
  FIX-13b  Removed dead cooldown global (logic uses last_alert_time instead)
  FIX-13c  Clean shutdown on Ctrl-C

Usage:
  export LEONI_DAEMON_TOKEN="<token from app.py startup>"
  python backend/leoni_monitor.py
"""

import cv2, time, os, base64, datetime, subprocess, platform, sys
import requests

BACKEND_URL    = os.getenv("LEONI_BACKEND",      "http://localhost:5000")
DAEMON_TOKEN   = os.getenv("LEONI_DAEMON_TOKEN", "")
SENSITIVITY    = int(os.getenv("LEONI_SENSITIVITY",  "25"))   # 1-100
CHECK_INTERVAL = float(os.getenv("LEONI_INTERVAL",   "1.5"))  # seconds
MIN_ALERT_GAP  = int(os.getenv("LEONI_ALERT_GAP",   "15"))   # seconds
CAPTURES_DIR   = os.path.join(os.path.dirname(__file__), "captures")
os.makedirs(CAPTURES_DIR, exist_ok=True)


def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def play_warning():
    try:
        plat = platform.system().lower()
        if plat == "windows":
            import winsound
            winsound.Beep(1000, 500)
        elif plat == "darwin":
            subprocess.Popen(["afplay", "/System/Library/Sounds/Sosumi.aiff"])
        else:
            subprocess.Popen(["paplay",
                "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"],
                stderr=subprocess.DEVNULL)
    except Exception:
        sys.stdout.write("\a"); sys.stdout.flush()


def capture_frame(cap):
    ret, frame = cap.read()
    if not ret:
        return None, None
    _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
    b64 = "data:image/jpeg;base64," + base64.b64encode(buf.tobytes()).decode()
    return frame, b64


def detect_motion(frame, prev_frame) -> bool:
    g1 = cv2.GaussianBlur(cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY), (21, 21), 0)
    g2 = cv2.GaussianBlur(cv2.cvtColor(frame,      cv2.COLOR_BGR2GRAY), (21, 21), 0)
    _, thresh = cv2.threshold(cv2.absdiff(g1, g2), 25, 255, cv2.THRESH_BINARY)
    h, w      = thresh.shape
    pct       = (cv2.countNonZero(thresh) / (h * w)) * 100
    return pct > (SENSITIVITY / 10.0)


def notify_backend(b64: str) -> bool:
    if not DAEMON_TOKEN:
        print("   ⚠  LEONI_DAEMON_TOKEN not set — skipping notification.")
        return False
    try:
        r = requests.post(f"{BACKEND_URL}/api/intruder",
            headers={"X-LEONI-Daemon": DAEMON_TOKEN},
            json={"image": b64, "timestamp": datetime.datetime.now().isoformat(),
                  "source": "leoni_monitor_daemon"},
            timeout=5)
        return r.ok
    except Exception:
        return False


def monitor_loop():
    print("╔═══════════════════════════════════╗")
    print("║  LEONI GUARDIAN DAEMON  v3.0      ║")
    print("╠═══════════════════════════════════╣")
    print(f"║  Backend    : {BACKEND_URL[:22]:<22} ║")
    print(f"║  Sensitivity: {SENSITIVITY:<23} ║")
    print(f"║  Interval   : {CHECK_INTERVAL}s{' '*20}║")
    print(f"║  Token      : {'✓ set' if DAEMON_TOKEN else '✗ NOT SET':<23} ║")
    print("╠═══════════════════════════════════╣")
    print("║  Ctrl+C to stop                   ║")
    print("╚═══════════════════════════════════╝\n")

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("❌  Cannot open webcam.")
        return

    print("✅  Monitoring started...\n")
    prev_frame      = None
    last_alert_time = 0.0

    try:
        while True:
            frame, b64 = capture_frame(cap)
            if frame is None:
                time.sleep(CHECK_INTERVAL)
                continue

            now = time.time()

            if prev_frame is not None and detect_motion(frame, prev_frame):
                if (now - last_alert_time) > MIN_ALERT_GAP:
                    last_alert_time = now
                    ts_str = datetime.datetime.now().strftime("%H:%M:%S")
                    print(f"\n⚠  [{ts_str}] MOTION DETECTED")
                    fname = os.path.join(CAPTURES_DIR, f"intruder_{timestamp()}.jpg")
                    cv2.imwrite(fname, frame)
                    print(f"   Saved: {fname}")
                    sent = notify_backend(b64)
                    print(f"   Backend: {'✓ notified' if sent else '✗ unreachable'}\n")
                    play_warning()
                    try:
                        disp = frame.copy()
                        cv2.putText(disp, "LEONI: UNAUTHORIZED ACCESS",
                            (10, 35), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,0,255), 2)
                        cv2.imshow("LEONI SECURITY ALERT", disp)
                        cv2.waitKey(3000)
                        cv2.destroyAllWindows()
                    except Exception:
                        pass
            else:
                sys.stdout.write(
                    f"\r  🟢 Monitoring... {datetime.datetime.now().strftime('%H:%M:%S')}  ")
                sys.stdout.flush()

            prev_frame = frame
            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        pass
    finally:
        cap.release()
        cv2.destroyAllWindows()
        print("\n\n🔴  Guardian stopped.")


if __name__ == "__main__":
    monitor_loop()
