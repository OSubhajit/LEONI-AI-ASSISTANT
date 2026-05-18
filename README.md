# LEONI v6.0 — Intelligent System AI Guardian

```
██╗     ███████╗ ██████╗ ███╗   ██╗██╗
██║     ██╔════╝██╔═══██╗████╗  ██║██║
██║     █████╗  ██║   ██║██╔██╗ ██║██║
██║     ██╔══╝  ██║   ██║██║╚██╗██║██║
███████╗███████╗╚██████╔╝██║ ╚████║██║
╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝
```

> Your personal AI-powered system guardian — runs entirely on your own machine.

---

## What is LEONI?

LEONI is a local-only AI assistant and security guardian that runs on `localhost:5000`. It combines:

- 🤖 **AI Chat** powered by Groq (llama-3.3-70b) — free, fast
- 🔒 **Voice + text authentication** with SHA-256 hashed passphrase
- 📸 **Screenshot & webcam capture** on command
- 👁 **Guardian mode** — motion detection, intruder alerts, auto-capture
- ⚙️ **System monitoring** — CPU, RAM, disk, uptime, processes, network
- 🖥️ **System commands** — lock, sleep, volume, open apps (all auth-gated)
- 🗒️ **Notes** — in-session notepad
- 📤 **Chat export** — save your conversation as a text file
- 🔑 **Passphrase management** — change passphrase from Settings

Everything runs on `127.0.0.1` only. Nothing leaves your machine except the chat messages sent to Groq's API.

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.9+ | 3.11+ recommended |
| Chrome, Edge, or Firefox | Voice recognition works best in Chrome/Edge |
| Webcam (optional) | Required for guardian mode and webcam captures |
| Microphone (optional) | Required for voice authentication and voice commands |
| Groq API key (optional) | Free at [console.groq.com](https://console.groq.com) — required for AI chat |

---

## Installation

### Windows

1. **Extract** `LEONI_v6.zip` to a folder (e.g. `C:\LEONI_v6\`)
2. **Double-click** `setup_windows.bat` — installs all Python dependencies
3. Enter your **Groq API key** when prompted (or skip and set it later in Settings)
4. **Done** — run LEONI via `START_LEONI.bat`

### Linux / macOS

```bash
# 1. Extract the zip
unzip LEONI_v6.zip
cd LEONI_v6

# 2. Run setup (installs deps, saves Groq key)
bash setup_linux_mac.sh

# 3. Start LEONI
bash start_leoni.sh
```

---

## First Run (Setup Wizard)

When you open `http://localhost:5000` for the first time, LEONI will walk you through a 3-step setup:

1. **Your name** — how LEONI addresses you
2. **Secret passphrase** — used for voice and text authentication (min 4 chars)
   - This is hashed with SHA-256 before being stored — plaintext is never saved
3. **Backend URL** — leave as `http://localhost:5000` unless you changed the port

After setup, LEONI greets you and you're ready to go.

---

## Authentication

LEONI uses a passphrase to protect sensitive operations:

- Click **🎤 VOICE AUTHENTICATE** and speak your passphrase, or
- Type it in the text field in the auth modal

Once authenticated, your session lasts **1 hour** from last activity. Click **🔒 LOCK SESSION** to end it early.

**Sensitive operations that require authentication:**
- All system commands (lock, sleep, shutdown, volume, open apps)
- Screenshot and webcam capture
- Process list, network info, battery status, system info
- Captures viewer, notes, chat export
- Changing the Groq API key or passphrase

---

## Getting a Free Groq API Key

1. Go to [console.groq.com](https://console.groq.com)
2. Sign up (free, no credit card)
3. Click **API Keys → Create API Key**
4. Copy the key (starts with `gsk_`)
5. Either:
   - Paste it during `setup_windows.bat` / `setup_linux_mac.sh`, or
   - Open LEONI → ⚙ Settings → paste under **GROQ API KEY** → Save

Without a Groq key, LEONI works in **local mode**: system commands work, but AI chat responses are basic.

---

## Guardian Mode (Intruder Detection)

1. Click **ACTIVATE CAMERA** in the left panel
2. Toggle **GUARDIAN MODE** in the right panel
3. LEONI monitors for motion via your webcam
4. If motion is detected **while no admin session is active**, LEONI:
   - Captures the intruder's photo
   - Takes a screenshot
   - Plays an audio alert
   - Displays the intruder overlay
   - Logs the event

**Tip:** Guardian mode triggers only when you are NOT authenticated. This is intentional — it's a security monitor, not a constant recorder.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Space` (unfocused) | Toggle voice listening |
| `Escape` | Close any open modal |
| `Enter` (in text input) | Send message |
| `Enter` (in note input) | Add note |

---

## Running the Background Daemon (Optional)

For always-on protection even when the browser is closed:

```bash
# Get the daemon token from app.py startup output, then:
export LEONI_DAEMON_TOKEN="your-token-here"
python backend/leoni_monitor.py
```

The daemon independently monitors your webcam and pushes intruder alerts to the backend.

**Environment variables:**
| Variable | Default | Description |
|---|---|---|
| `LEONI_DAEMON_TOKEN` | (none) | Must match token from app.py startup |
| `LEONI_BACKEND` | `http://localhost:5000` | Backend URL |
| `LEONI_SENSITIVITY` | `25` | Motion sensitivity (1–100) |
| `LEONI_INTERVAL` | `1.5` | Seconds between frames |
| `LEONI_ALERT_GAP` | `15` | Min seconds between alerts |

---

## File Structure

```
LEONI_v6/
├── index.html              ← Complete single-file frontend
├── README.md               ← This file
├── setup_windows.bat       ← Windows one-click setup
├── setup_linux_mac.sh      ← Linux/macOS setup
├── START_LEONI.bat         ← Windows launcher
├── start_leoni.sh          ← Linux/macOS launcher
└── backend/
    ├── app.py              ← Flask backend (all logic lives here)
    ├── leoni_monitor.py    ← Optional background guardian daemon
    ├── requirements.txt    ← Python dependencies
    ├── leoni_auth.json     ← Created on first run (admin hash + config)
    └── captures/           ← Created automatically (screenshots, webcam photos)
```

---

## Troubleshooting

**"Backend offline" warning in LEONI**
→ Make sure `python backend/app.py` is running. Check the terminal for errors.

**"psutil not available" / stats show N/A**
→ Run `pip install psutil --break-system-packages` (Linux) or `pip install psutil` (Windows)

**Webcam not working**
→ Allow camera access in your browser when prompted. Only one app can use the webcam at a time — close other apps using it.

**Voice authentication not working**
→ Use Chrome or Edge. Firefox has limited Web Speech API support.
→ Allow microphone access in the browser when prompted.

**AI chat says "set GROQ_API_KEY"**
→ Add your Groq key in ⚙ Settings → GROQ API KEY → Save.

**Setup wizard keeps appearing**
→ The backend must be running and reachable before completing setup. Start `app.py` first.

**Shutdown/sleep not working on Linux**
→ Your user may need `sudo` rights for `systemctl suspend` / `shutdown`. Run: `sudo visudo` and add your user to the sudoers file for those commands.

---

## Security Notes

- LEONI binds to `127.0.0.1` only — it cannot be accessed from other devices on your network
- Passphrases are hashed with SHA-256 before storage — the raw passphrase is never written anywhere
- Session tokens are in-memory only — they are lost when the backend restarts
- All sensitive endpoints require a valid session token
- The brute-force lockout triggers after 5 failed attempts (5-minute lockout)
- The Groq API key is stored in `leoni_auth.json` — keep this file private

---

## Changelog

### v6.0 (current)
- **FIX:** All chat-triggered system commands now require authentication
- **FIX:** Command parser uses word-boundary matching — no more false positives
- **FIX:** `admin_name` is read from stored auth, not from the request
- **FIX:** Background session cleanup (no memory leak)
- **FIX:** Rate limiting on `/api/chat` (60 req/min per IP)
- **FIX:** Battery endpoint now requires auth
- **FIX:** Login attempts dict capped at 500 IPs
- **FIX:** Intruder and capture logs capped at 200 entries
- **FIX:** Groq client cached per API key
- **FIX:** Shutdown always requires explicit UI confirmation
- **FIX:** Daemon token partially redacted in startup output
- **FIX:** Dead code removed (`threading`, `alert_cooldown` in monitor)
- **NEW:** Kill process from the process list UI
- **NEW:** Delete captures from the captures viewer
- **NEW:** In-session notes (add / delete)
- **NEW:** Groq API key persists across restarts
- **NEW:** Extended system info modal (cores, temps, disks)
- **NEW:** Chat export to `.txt` file
- **NEW:** Change passphrase from Settings
- **NEW:** Escape key closes any open modal

### v5.0
- BUG-2 fix: intruder endpoint accepts localhost without session
- BUG-3 fix: screenshot/webcam blocked for unauthenticated chat users (incomplete)
- SHA-256 hashing for passphrases

---

*LEONI runs entirely on your machine. Your data stays with you.*
#   L E O N I - A I - A S S I S T A N T  
 