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

## Phase 4 E2E Test (GoAD)

Phase 4 adds the Post-Ex Agent (six sub-activities: enumeration, privesc,
persistence, evasion, exfiltration, BloodHound). The Phase 4 E2E test
runs recon + vuln + exploit + post-ex against a local **GoAD** lab
([Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD))
and asserts the Post-Ex Agent populates `local_users`,
`harvested_secrets`, and `persistence_artifacts` on at least one
foothold.

### Prerequisites

In addition to the Phase 3 prerequisites, you need:

1. **GoAD lab running locally** — follow the
   [GOAD install instructions](https://github.com/Orange-Cyberdefense/GOAD)
   for vagrant-libvirt / virtualbox. The standard layout puts VMs on
   `192.168.56.0/24`; the default target for this E2E test is
   `192.168.56.22` (SRV02), override with `AUTORED_GOAD_TARGET`.
2. **Phase 4 tool dependencies** — in addition to the Phase 3 toolset:
   - `impacket`'s `secretsdump.py` (CredHarvester)
   - `mimikatz` (CredHarvester on Windows footholds — runs via the
     Meterpreter session, no local install needed on your box)
   - `bloodhound-python` (BloodHound collection — install with
     `pip install bloodhound-ce`)
   - `linpeas.sh` / `winpeas.exe` (Enumeration sub-agents — the agent
     uploads these to the foothold, so they must be on your local
     `$PATH`)

### Run the Phase 4 E2E test

```bash
# 1. Bring up GoAD (see GOAD repo for vagrant / ansible setup)
cd GOAD && vagrant up

# 2. Verify the GoAD target VM is reachable
ping 192.168.56.22  # or whichever VM you're targeting first

# 3. Start msfrpcd (see Phase 3 section above — keep it running)
msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

# 4. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1
export AUTORED_LHOST=192.168.56.1   # your VirtualBox host-only IP
export AUTORED_GOAD_TARGET=192.168.56.22  # override as needed

# 5. Run Phase 4 E2E test (use -s to see live findings + sub-activities)
uv run pytest tests/e2e/test_phase4_goad.py -v -s
```

Expected runtime: 30–60 minutes (recon + vuln + exploit + 6 sub-activities
per foothold). The test passes if:

- Recon discovers at least 1 host (the GoAD target)
- The Exploit Agent records at least 1 foothold (initial access)
- The Post-Ex Agent's WindowsEnum sub-agent records at least 1 local user
- The CredHarvester sub-agent harvests at least 1 secret (NTLM hash or
  cleartext password)
- The PersistenceAgent sub-agent installs at least 1 persistence
  artifact on the foothold
- The Phase 4 graph reaches the `done` phase

### Post-run cleanup (IMPORTANT)

The Phase 4 E2E test installs persistence artifacts on the GoAD lab
(scheduled tasks, registry Run keys, etc.). Each artifact records its
exact `removal_command` in the engagement's `state.json` — run those
commands manually against the affected VMs before the next E2E run to
avoid duplicate artifacts piling up:

```bash
# Find the engagement ID from the test output, then:
python -c "
import json
state = json.load(open('engagements/<id>/state.json'))
for a in state['persistence_artifacts']:
    print(a['host_ip'], a['method'], '->', a['removal_command'])
"
```

Then SSH / WinRM into each affected VM and run the printed commands.

