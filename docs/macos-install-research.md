# Odysseus on Apple Silicon macOS: install and run research

Scope: the freshly cloned canonical repository at
`/Users/welisbesse/Code/personal/OdysseusNew` (local checkout: `dev`). I inspected
the repository's first-party README, setup guide, launcher, configuration, and
source. No dependencies were installed, the application was not started, and no
data was copied or migrated.

## Branch choice

The clone is on `dev`, which the project documents as the default branch with the
newest changes first; the setup guide warns that it may be unstable. `main` is the
more curated/stable branch. Use `dev` when latest changes are intentional; use
`main` for a conservative first install. ([`README.md:26-31`](../README.md#L26-L31), [`docs/setup.md:5-7`](setup.md#L5-L7))

## Recommended M-series procedure

Use the native launcher so Cookbook can use the Mac's Metal GPU. Docker on
macOS runs in a Linux VM without Metal access, so its Cookbook model serving is
CPU-only. ([`docs/setup.md:30-37`](setup.md#L30-L37), [`start-macos.sh:11-12`](../start-macos.sh#L11-L12))

```bash
cd /Users/welisbesse/Code/personal/OdysseusNew
./start-macos.sh
```

The launcher requires Homebrew but deliberately does not install it. On arm64 it
searches `/opt/homebrew/bin/python3.13`, `.12`, then `.11` for Python 3.11+;
if none is available it installs Homebrew's `python@3.11`. It creates/reuses
`venv/`, installs `requirements.txt`, runs `setup.py`, starts local helper
services when applicable, and launches Uvicorn. `tmux`, `llama.cpp`, and `apfel`
support optional Cookbook/local-model workflows; failures to install those are
warnings, while Python is required for the core launch. ([`start-macos.sh:54-95`](../start-macos.sh#L54-L95), [`start-macos.sh:130-166`](../start-macos.sh#L130-L166), [`start-macos.sh:167-177`](../start-macos.sh#L167-L177))

The documented manual fallback is Python 3.11+, a venv, `pip install -r
requirements.txt`, `python setup.py`, and Uvicorn. Its generic example uses port
7000; the macOS launcher uses 7860 to avoid the common AirPlay Receiver conflict
on 7000. ([`docs/setup.md:39-52`](setup.md#L39-L52), [`start-macos.sh:33-36`](../start-macos.sh#L33-L36))

### Local prerequisite check (read-only)

- Homebrew 6.0.2, `tmux` 3.6b, `llama.cpp`/`llama-server`, and `apfel` 1.5.5 are
  present under `/opt/homebrew`.
- The default `python3` is macOS Python 3.9.6, which is below the documented
  requirement. An arm64 Homebrew Python 3.11.15 is present at
  `/opt/homebrew/bin/python3.11`, so this launcher should use it rather than
  install another interpreter.
- The Docker CLI is not installed; the native path is therefore the available
  Apple-Silicon procedure.
- The Tailscale CLI exists, but `tailscale status` reports “Failed to load
  preferences”; no Tailscale URL should be assumed until that is repaired.

## Address, ports, and existing processes

The native app defaults to `127.0.0.1:7860`. `ODYSSEUS_PORT` overrides the port,
then `.env`/`APP_PORT`; `ODYSSEUS_HOST` overrides the host, then
`.env`/`APP_BIND`. The launcher probes the selected app port and exits before
setup if it is occupied. ([`start-macos.sh:19-50`](../start-macos.sh#L19-L50))

At this report's read-only check, TCP listeners on 7860, 8100, and 11435 were
free. Those ports were occupied earlier by the existing stack, so restarting that
old checkout would recreate the conflicts. Do not stop anything automatically;
the safest first run is to stop/verify the old stack yourself, then launch the
new checkout.

Changing only the app port is not sufficient to avoid helper-service collisions:

- **7860 (Odysseus):** if occupied, the launcher fails fast. Choose a free port,
  e.g. `ODYSSEUS_PORT=7900 ./start-macos.sh`. ([`start-macos.sh:47-52`](../start-macos.sh#L47-L52))
- **8100 (ChromaDB):** the launcher probes `127.0.0.1:$CHROMADB_PORT` (default
  8100). If reachable, it reuses that service; selecting `ODYSSEUS_PORT=7900`
  still reuses/touches 8100. If `CHROMADB_HOST` is remote, it does not start a
  local ChromaDB. Verify that an existing listener is actually ChromaDB before
  relying on it. ([`start-macos.sh:187-209`](../start-macos.sh#L187-L209), [`.env.example:98-102`](../.env.example#L98-L102))
- **11435 (Apfel):** on arm64, when `apfel` is installed, the launcher starts
  `apfel --serve --port 11435` without a port-availability probe. An existing
  service there can make Apfel fail to bind; inspect its log and configure the
  intended model endpoint, or stop the old service before launch. ([`start-macos.sh:167-177`](../start-macos.sh#L167-L177))

## Environment, authentication, and data

No `.env` is required for a basic native launch; the setup guide says defaults
work out of the box and feature providers can be configured in Settings. Use
`.env` for deployment-level overrides such as bind/port, authentication,
database, or a pre-seeded admin password. Authentication is enabled by default;
first setup creates `admin` (unless `ODYSSEUS_ADMIN_USER` is set) and prints a
temporary password in the terminal. ([`docs/setup.md:8-16`](setup.md#L8-L16), [`.env.example:53-89`](../.env.example#L53-L89))

Persistent state defaults under `data/`: the SQLite database, sessions/messages,
memory, settings/auth, uploads, personal documents, Chroma data, and other
feature state. `ODYSSEUS_DATA_DIR` relocates this tree; the documented database
default is `sqlite:///./data/app.db`. ([`docs/setup.md:543-545`](setup.md#L543-L545), [`src/constants.py:9-55`](../src/constants.py#L9-L55), [`.env.example:56-64`](../.env.example#L56-L64))

## Tailscale

Tailscale is optional, not a prerequisite for local use: loopback binding works
without it. For another trusted device, explicitly bind all interfaces and use a
Tailscale/LAN address, for example:

```bash
ODYSSEUS_HOST=0.0.0.0 ./start-macos.sh
```

The launcher prints a Tailscale URL only when the `tailscale` command is installed
and returns an IPv4 address; binding itself does not require Tailscale. Keep
`AUTH_ENABLED=true`, do not expose the port directly to the public internet, and
use HTTPS for browser clipboard features over a non-localhost LAN/Tailscale URL.
([`docs/setup.md:64-75`](setup.md#L64-L75), [`docs/setup.md:390-407`](setup.md#L390-L407), [`start-macos.sh:215-228`](../start-macos.sh#L215-L228))

