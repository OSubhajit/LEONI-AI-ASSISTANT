<div align="center">

```
██╗     ███████╗ ██████╗ ███╗   ██╗██╗
██║     ██╔════╝██╔═══██╗████╗  ██║██║
██║     █████╗  ██║   ██║██╔██╗ ██║██║
██║     ██╔══╝  ██║   ██║██║╚██╗██║██║
███████╗███████╗╚██████╔╝██║ ╚████║██║
╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝
```

# LEONI v6.0 — Intelligent System AI Guardian

**Model: LN-07 · Type: Humanoid Android · Role: Scout / Assassin / Intelligence Operative**

*"I was not built to be human. But I chose to understand it."* — Leoni

![LEONI Portrait](leoni_portrait.jpg)

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Backend-lightgrey?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Groq](https://img.shields.io/badge/Groq-LLaMA%203.3--70B-orange?style=flat-square)](https://console.groq.com)
[![License](https://img.shields.io/badge/License-Personal%20Use-green?style=flat-square)](./LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

> Your personal AI-powered system guardian — runs entirely on your own machine.

</div>

---

## 🤖 What is LEONI?

LEONI is a **local-only AI assistant and security guardian** that runs on `localhost:5000`. She's your intelligent digital sentinel — combining natural language AI, real-time system monitoring, and physical security through your webcam. Everything stays on your machine.

<div align="center">

![LEONI Blueprint](leoni_blueprint.jpg)

*LEONI LN-07 · Full System Blueprint & Design Overview · Manufactured by Nexus Dynamics*

</div>

---

## ✨ Core Capabilities

| Feature | Description |
|---|---|
| 🤖 **AI Chat** | Powered by Groq (llama-3.3-70b) — free, fast, local |
| 🔒 **Authentication** | Voice + text auth with SHA-256 hashed passphrase |
| 📸 **Captures** | Screenshot & webcam capture on command |
| 👁 **Guardian Mode** | Motion detection, intruder alerts, auto-capture |
| ⚙️ **System Monitor** | CPU, RAM, disk, uptime, processes, network |
| 🖥️ **System Commands** | Lock, sleep, volume, open apps (all auth-gated) |
| 🗒️ **Notes** | In-session notepad with add/delete |
| 📤 **Chat Export** | Save your conversation as a `.txt` file |
| 🔑 **Passphrase Management** | Change passphrase from Settings |

> Everything runs on `127.0.0.1` only. Nothing leaves your machine except chat messages sent to Groq's API.

---

## 📋 Requirements

| Requirement | Notes |
|---|---|
| **Python 3.9+** | 3.11+ recommended |
| **Chrome, Edge, or Firefox** | Voice recognition works best in Chrome/Edge |
| **Webcam** *(optional)* | Required for Guardian Mode and webcam captures |
| **Microphone** *(optional)* | Required for voice authentication and voice commands |
| **Groq API key** *(optional)* | Free at [console.groq.com](https://console.groq.com) — required for AI chat |

---

## 🚀 Installation

### Windows

```bat
REM 1. Extract LEONI_v6.zip to a folder, e.g. C:\LEONI_v6\
REM 2. Double-click setup_windows.bat — installs all Python dependencies
REM 3. Enter your Groq API key when prompted (or skip and add later in Settings)
REM 4. Launch LEONI
START_LEONI.bat
```

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

## 🧭 First Run — Setup Wizard

When you open `http://localhost:5000` for the first time, LEONI walks you through a **3-step setup**:

```
Step 1 → Your name          How LEONI addresses you
Step 2 → Secret passphrase  Min 4 chars · Hashed with SHA-256 before storage
Step 3 → Backend URL        Leave as http://localhost:5000 unless you changed the port
```

After setup, LEONI greets you and you're ready to go.

---

## 🔐 Authentication

LEONI uses a passphrase to protect sensitive operations:

- Click **🎤 VOICE AUTHENTICATE** and speak your passphrase, **or**
- Type it in the text field in the auth modal

Once authenticated, your session lasts **1 hour** from last activity. Click **🔒 LOCK SESSION** to end it early.

**Operations that require authentication:**

```
System commands (lock, sleep, shutdown, volume, open apps)
Screenshot and webcam capture
Process list, network info, battery status, system info
Captures viewer, notes, chat export
Changing the Groq API key or passphrase
```

---

## 🔑 Getting a Free Groq API Key

```
1. Visit  → https://console.groq.com
2. Sign up  → Free, no credit card required
3. Navigate → API Keys → Create API Key
4. Copy key → Starts with gsk_
5. Paste it → During setup OR via ⚙ Settings → GROQ API KEY → Save
```

> Without a Groq key, LEONI works in **local mode** — system commands work, but AI chat responses are basic.

---

## 👁 Guardian Mode — Intruder Detection

```
1. Click  → ACTIVATE CAMERA in the left panel
2. Toggle → GUARDIAN MODE in the right panel
3. LEONI  → Monitors for motion via your webcam
```

If motion is detected **while no admin session is active**, LEONI will:

- 📷 Capture the intruder's photo
- 🖥️ Take a screenshot
- 🔊 Play an audio alert
- 🚨 Display the intruder overlay
- 📝 Log the event

> **Tip:** Guardian Mode triggers only when you are **NOT** authenticated. This is intentional — it's a security monitor, not a constant recorder.

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|---|---|
| `Space` *(unfocused)* | Toggle voice listening |
| `Escape` | Close any open modal |
| `Enter` *(in text input)* | Send message |
| `Enter` *(in note input)* | Add note |

---

## 🔁 Background Daemon (Optional)

For always-on protection even when the browser is closed:

```bash
# Get the daemon token from app.py startup output, then:
export LEONI_DAEMON_TOKEN="your-token-here"
python backend/leoni_monitor.py
```

**Environment Variables:**

| Variable | Default | Description |
|---|---|---|
| `LEONI_DAEMON_TOKEN` | *(none)* | Must match token from app.py startup |
| `LEONI_BACKEND` | `http://localhost:5000` | Backend URL |
| `LEONI_SENSITIVITY` | `25` | Motion sensitivity (1–100) |
| `LEONI_INTERVAL` | `1.5` | Seconds between frames |
| `LEONI_ALERT_GAP` | `15` | Min seconds between alerts |

---

## 📁 File Structure

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

## 🛠️ Troubleshooting

| Symptom | Fix |
|---|---|
| **"Backend offline" warning** | Ensure `python backend/app.py` is running. Check terminal for errors. |
| **"psutil not available" / stats N/A** | `pip install psutil --break-system-packages` (Linux) or `pip install psutil` (Windows) |
| **Webcam not working** | Allow camera access in browser. Only one app can use webcam at a time. |
| **Voice auth not working** | Use Chrome or Edge. Firefox has limited Web Speech API support. Allow mic access. |
| **AI chat says "set GROQ_API_KEY"** | Add your key in ⚙ Settings → GROQ API KEY → Save |
| **Setup wizard keeps appearing** | Backend must be running and reachable before completing setup. Start `app.py` first. |
| **Shutdown/sleep not working (Linux)** | Your user may need `sudo` rights. Run `sudo visudo` and add permissions for `systemctl suspend` / `shutdown`. |

---

## 🔒 Security Notes

```
✔  LEONI binds to 127.0.0.1 only — not accessible from other network devices
✔  Passphrases hashed with SHA-256 — raw passphrase is never written anywhere
✔  Session tokens are in-memory only — lost when backend restarts
✔  All sensitive endpoints require a valid session token
✔  Brute-force lockout after 5 failed attempts (5-minute lockout)
✔  Groq API key stored in leoni_auth.json — keep this file private
```

---

## 📦 Identity Card

```
NAME          LEONI
MODEL         LN-07
MANUFACTURER  Nexus Dynamics
SERIAL        07-LEO-2117
HEIGHT        168 cm
WEIGHT        52 kg
VOICE         Calm / Soft
AI CORE       NYX V.3
STATUS        ACTIVE
```

**Color Palette:**

| Swatch | Name |
|---|---|
| ⬜ | Ceramic White |
| ⬛ | Graphite Black |
| 🩶 | Silver Metal |
| 🌸 | Rose Gold Accent |
| 🔵 | Neon Blue (Light) |
| 🟤 | Soft Skin Tone |

---

## 📝 Changelog

### v6.0 *(current)*

**Fixes:**
- All chat-triggered system commands now require authentication
- Command parser uses word-boundary matching — no more false positives
- `admin_name` is read from stored auth, not from the request
- Background session cleanup (no memory leak)
- Rate limiting on `/api/chat` (60 req/min per IP)
- Battery endpoint now requires auth
- Login attempts dict capped at 500 IPs
- Intruder and capture logs capped at 200 entries
- Groq client cached per API key
- Shutdown always requires explicit UI confirmation
- Daemon token partially redacted in startup output
- Dead code removed (`threading`, `alert_cooldown` in monitor)

**New Features:**
- Kill process from the process list UI
- Delete captures from the captures viewer
- In-session notes (add / delete)
- Groq API key persists across restarts
- Extended system info modal (cores, temps, disks)
- Chat export to `.txt` file
- Change passphrase from Settings
- Escape key closes any open modal

### v5.0
- BUG-2 fix: intruder endpoint accepts localhost without session
- BUG-3 fix: screenshot/webcam blocked for unauthenticated chat users (incomplete)
- SHA-256 hashing for passphrases

---

<div align="center">

**LEONI runs entirely on your machine. Your data stays with you.**

*"I was not built to be human. But I chose to understand it."*

`LN-07 · Nexus Dynamics · NYX V.3 Core · Status: ACTIVE`

</div>
