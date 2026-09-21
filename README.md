# AutoRed

Autonomous red-team copilot. Phase 1: Recon Agent.

## Install

```bash
uv sync
cp .env.example .env  # edit with your API keys
```

## Usage

```bash
# Run recon against a target (headless)
autored run --target 10.10.10.5 --roe roe-sandbox.yaml --no-tui

# Resume an interrupted engagement
autored resume <engagement_id>

# List engagements
autored engagements
```

## Development

```bash
uv run pytest                    # run tests
uv run pytest --cov=autored      # run with coverage
uv run ruff check autored tests  # lint
uv run ruff format autored tests # format
```

## E2E Tests

E2E tests run against live targets (HackTheBox). They're skipped by
default — set `AUTORED_E2E=1` to opt in.

To run the Phase 1 E2E test against HTB Lame (`10.10.10.5`):

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify target is reachable
ping 10.10.10.5

# 3. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export AUTORED_E2E=1

# 4. Run E2E test (use -s to see live findings)
uv run pytest tests/e2e/test_phase1_lame.py -v -s
```

Expected runtime: 5–10 minutes. The test passes if:

- nmap discovers ports 21 (FTP), 22 (SSH), and 445 (SMB)
- All tools (`naabu`, `httpx`, `nuclei`, `feroxbuster`, etc.) execute
  without error
- The Phase 1 graph reaches the `done` phase
- Final state has at least 1 host and 3 services

## Phase 2 E2E Test (Shocker)

Phase 2 adds the Vuln Agent (CVE correlation, exploit search, self-critique
loop, ranked attack hypotheses). The Phase 2 E2E test runs recon + vuln
against HTB Shocker (`10.10.10.56`) and asserts the Vuln Agent identifies
Shellshock (CVE-2014-6271).

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify Shocker is reachable
ping 10.10.10.56

# 3. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1

# 4. Run Phase 2 E2E test (use -s to see live findings + hypotheses)
uv run pytest tests/e2e/test_phase2_shocker.py -v -s
```

Expected runtime: 10–15 minutes. The test passes if:

- Recon discovers port 80 (Apache httpd 2.2.22) on Shocker
- All tools (`nmap`, `naabu`, `httpx`, `nuclei`, `feroxbuster`,
  `searchsploit`, etc.) execute without error
- The Vuln Agent produces at least 1 attack hypothesis
- At least one hypothesis references Shellshock (CVE-2014-6271)
- The Phase 2 graph reaches the `done` phase

## Phase 3 E2E Test (Blue)

Phase 3 adds the Exploit Agent (HitL gates, sub-agent dispatch, foothold
verification, evidence capture). The Phase 3 E2E test runs recon + vuln +
exploit against HTB Blue (`10.10.10.40`) and asserts the Exploit Agent
achieves an EternalBlue (MS17-010) foothold via Metasploit RPC.

### Prerequisites

In addition to the Phase 2 prerequisites, you need:

1. **Metasploit Framework** with `msfrpcd` installed (Kali ships both).
2. **Your HTB VPN IP** (the `tun0` interface address) — Metasploit's
   reverse shell will connect back to this. Find it with:
   ```bash
   ip addr show tun0 | grep "inet "
   ```

### Start `msfrpcd`

The Exploit Agent talks to Metasploit via RPC, so `msfrpcd` must be
running before the test starts. In a separate terminal:

```bash
# Start msfrpcd on 127.0.0.1:55553 with password "msf"
msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L
```

- `-P msf` — RPC password (must match the default in
  `autored/tools/metasploit.py`)
- `-p 55553` — RPC port (must match the default)
- `-a 127.0.0.1` — bind to localhost only
- `-U msf` — RPC username (unused by the msgpack RPC client but
  required by `msfrpcd`)
- `-L` — log to stdout so you can watch RPC calls

Verify `msfrpcd` is listening:

```bash
ss -tlnp | grep 55553
# expect: LISTEN ... 127.0.0.1:55553 ...
```

### Run the Phase 3 E2E test

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify Blue is reachable
ping 10.10.10.40

# 3. Start msfrpcd (see above — keep this running in a separate terminal)
msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

# 4. Find your HTB VPN IP
export AUTORED_LHOST=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo "LHOST=$AUTORED_LHOST"

# 5. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1

# 6. Run Phase 3 E2E test (use -s to see live findings + hypotheses + exploit)
uv run pytest tests/e2e/test_phase3_blue.py -v -s
```

Expected runtime: 15–30 minutes (recon + vuln + Metasploit exploit). The
test passes if:

- Recon discovers port 445 (SMB) on Blue
- All recon tools execute without error
- The Vuln Agent produces at least 1 EternalBlue hypothesis (MS17-010 /
  CVE-2017-0144)
- The Exploit Agent dispatches `msfagent` →
  `exploit/windows/smb/ms17_010_eternalblue` via Metasploit RPC
- A Meterpreter session is obtained (foothold recorded in final state)
- The foothold's `method` field is `ms17_010`
- The Phase 3 graph reaches the `done` or `postex` phase

### Troubleshooting

- **`MSF RPC login failed`** — `msfrpcd` isn't running, or the
  password/port doesn't match the defaults in
  `autored/tools/metasploit.py`. Restart `msfrpcd` with the exact
  flags above.
- **`exploit_failed` / no session** — `AUTORED_LHOST` is wrong (target
  can't reach your VPN IP), or a firewall is blocking the reverse
  shell on `LPORT=4444`. Verify with `tcpdump -i tun0 port 4444`.
- **`No EternalBlue hypothesis`** — the Vuln Agent's Sonnet model didn't
  identify MS17-010. Re-run; if it persists, check that nmap discovered
  port 445 with the `ms17-010` script output.
